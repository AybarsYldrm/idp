'use strict';

const { EventEmitter } = require('node:events');

const { StagingStore } = require('./staging-store');
const pairing = require('./pairing');
const spiffe = require('./spiffe');

// IdP ile veritabanı arasındaki ilişkinin TAMAMI.
//
// Daha önce bu iş oauth-server.js'in açılış fonksiyonuna dağılmıştı ve şu sonucu veriyordu:
// veritabanı ayakta değilse IdP hiç açılmıyordu. Yani sıralama şuydu -- önce veritabanını
// çalıştır, sonra IdP'yi. Oysa veritabanı, IdP ona bir sunucu sertifikası verene kadar mühürlü
// bekliyor. İki taraf da diğerini bekliyordu.
//
// Buradaki çözüm, bağlantıyı AÇILIŞ KOŞULU olmaktan çıkarmak:
//
//   1. IdP her hâlükârda açılır. Yönetici giriş yapabilir, panel çalışır.
//   2. Yazmalar açılış tamponuna gider (core/staging-store.js).
//   3. Bu modül arka planda veritabanını arar, bulunca sağlar, mTLS'e geçer.
//   4. Bağlantı kurulduğu anda tampon gerçek veritabanına boşaltılır ve her şey doğrudan geçer.
//   5. Bağlantı koparsa geri tampona düşülür ve yeniden denenir.
//
// Artık "önce hangisi" diye bir soru yok: ikisi de herhangi bir sırada açılabilir ve sistem
// kendini bulur.
//
//
// YAPILANDIRMA
//
// Değerler üç yerden gelebilir, bu öncelikle:
//
//   1. ortam değişkenleri     -- açıkça verilmiş, her zaman kazanır
//   2. eşleştirme dizini      -- veritabanının açılışta yazdığı dosya (core/pairing.js)
//   3. varsayılanlar
//
// İkincisi bu modülün var olma sebebinin yarısı: denetim düzlemi sırrını bir terminalden
// kopyalayıp bir ortam değişkenine yapıştırmak, bu iki projeyi birbirine bağlamayı fiilen
// imkânsız kılan şeydi.

const DEFAULT_RETRY_MS = 5000;
const MAX_RETRY_MS = 60_000;

const STATES = Object.freeze({
  STAGING: 'staging',         // veritabanı yok; yazmalar tamponda
  PROVISIONING: 'provisioning', // sunucu kimliği kuruluyor
  CONNECTED: 'connected',     // mTLS kuruldu, tampon boşaltıldı
  DISABLED: 'disabled',       // gömülü motor ya da mock -- bağlanacak bir şey yok
});

class DatabaseLink extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.config     core/config.js çıktısı
   * @param {object} opts.pkiIssuer  sunucu sertifikasını üretecek olan
   * @param {object} opts.logger
   */
  constructor({ config, pkiIssuer, logger }) {
    super();
    this.config = config;
    this.pkiIssuer = pkiIssuer;
    this.log = logger.child('db-link');

    this.state = STATES.STAGING;
    this.staging = new StagingStore({ logger: this.log });
    this.real = null;
    this.handle = null;
    this.identity = null;
    this.lastError = null;
    this.connectedAt = null;
    this.attempts = 0;

    this._retryTimer = null;
    this._renewalTimer = null;
    this._stopped = false;
    // Bu süreçte kurduğumuz sunucu sertifikasının parmak izi; yeniden denemelerde sabitleme
    // listesine ekleniyor (gerekçe _resolveSettings içinde).
    this._installedServerFingerprint = null;

    // Çağıranın tuttuğu TEK nesne. İçerideki hedef tampondan gerçek veritabanına geçtiğinde
    // çağıranın hiçbir şey yapması gerekmiyor -- `db` referansı aynı kalıyor.
    this.db = this._createFacade();
  }

  /**
   * Servislerin tuttuğu cephe.
   *
   * Neden bir Proxy değil de açık bir cephe: Proxy her özellik erişimini yakalar ve hata
   * ayıklarken ne olduğunu anlaşılmaz kılar. Buradaki yüzey küçük ve sabittir; açıkça yazmak,
   * bir metodun eksik olduğunun çalışma zamanında değil okurken görülmesini sağlar.
   */
  _createFacade() {
    const link = this;
    return {
      collection(name) { return link._target().collection(name); },
      async defineCollectionAsync(name, definition) {
        return link._target().defineCollectionAsync(name, definition);
      },
      async defineCollection(name, definition) {
        const target = link._target();
        if (typeof target.defineCollection === 'function') return target.defineCollection(name, definition);
        return target.defineCollectionAsync(name, definition);
      },
      async applySchemaRegistry(registry) { return link._target().applySchemaRegistry(registry); },
      // Bağlantı durumunu okumak isteyen (yönetim paneli) için.
      get linkState() { return link.state; },
    };
  }

  _target() {
    return this.state === STATES.CONNECTED && this.real ? this.real : this.staging;
  }

  // ---- yaşam döngüsü --------------------------------------------------------------------------

  /**
   * Bağlanmayı başlatır ve HEMEN döner.
   *
   * Beklememesi kasıtlı: IdP'nin açılışı veritabanına bağlı olmamalı, çünkü veritabanı IdP'yi
   * bekliyor. `await link.start()` yazmak o kilidi geri getirirdi.
   */
  start() {
    if (this.config.devMockDb) {
      this.state = STATES.DISABLED;
      this.log.warn({ msg: 'mock veritabanı modu — bağlantı denenmeyecek' });
      return this;
    }
    if (!this.config.db.remoteTarget && !this.config.db.pairingDiscovery) {
      this.state = STATES.DISABLED;
      return this;
    }
    this._attempt();
    return this;
  }

  async stop() {
    this._stopped = true;
    if (this._retryTimer) clearTimeout(this._retryTimer);
    if (this._renewalTimer) clearInterval(this._renewalTimer);
    try { this.handle?.close?.(); } catch (_) { /* kapanırken hata önemli değil */ }
    try { this.identity?.close?.(); } catch (_) { /* aynı */ }
  }

  status() {
    return {
      state: this.state,
      connectedAt: this.connectedAt,
      attempts: this.attempts,
      lastError: this.lastError,
      staging: this.staging.status(),
      target: this._resolvedTarget || null,
      principal: this.identity?.principal || null,
      spiffeId: spiffe.identities.service('idp').uri,
    };
  }

  // ---- bağlanma ---------------------------------------------------------------------------

  async _attempt() {
    if (this._stopped) return;
    this.attempts += 1;

    const done = this.log.timer('veritabanı bağlantı denemesi', { warnAboveMs: 15_000 });
    try {
      await this._connect();
      done({ attempt: this.attempts, state: this.state });
    } catch (err) {
      this.lastError = err.message;
      done({ attempt: this.attempts, failed: true });

      // Geri çekilme üstel ama tavanlı. Tavan olmadan, bir gecelik kesintiden sonra ilk deneme
      // saatler sonrasına düşerdi; tavan olduğunda en kötü ihtimalle bir dakika beklenir.
      const delay = Math.min(DEFAULT_RETRY_MS * Math.min(this.attempts, 8), MAX_RETRY_MS);
      this.log.warn({
        attempt: this.attempts,
        error: err.message,
        retryInMs: delay,
        bufferedOperations: this.staging.size,
        msg: 'veritabanına bağlanılamadı — açılış tamponuyla devam ediliyor',
      });
      // Olay adı 'error' DEĞİL, ve bu fark bir süslemeden ibaret değil.
      //
      // Node'da bir EventEmitter üzerinde dinleyicisi olmayan 'error' olayı YAKALANMAZ: fırlatılır
      // ve süreci öldürür. Yani bu satır 'error' yayınlarken, veritabanına ulaşılamadığı her
      // durumda IdP çöküyordu -- tam olarak bu modülün önlemek için var olduğu şey. Açılış
      // tamponu, yeniden deneme, geri çekilme, hepsi ilk denemede öldürülen bir süreçte anlamsız.
      //
      // Bağlanamamak bu mimaride BEKLENEN bir durum: veritabanı IdP'den sonra açılabilir. Bunu
      // Node'un ölümcül olay adıyla bildirmek, normal bir sıralamayı çökme sebebine çeviriyordu.
      this.emit('attemptFailed', err);

      if (this._stopped) return;
      this._retryTimer = setTimeout(() => this._attempt(), delay);
      if (typeof this._retryTimer.unref === 'function') this._retryTimer.unref();
    }
  }

  /** Ayarları ortam ve eşleştirme dizininden birleştirir. Ortam her zaman kazanır. */
  async _resolveSettings() {
    const dbCfg = this.config.db;
    const discovered = await pairing.readDatabase({ dir: this.config.pairingDir, logger: this.log });

    if (!discovered && !dbCfg.remoteTarget) {
      throw new Error(
        `veritabanı bulunamadı. Ne FITFAK_IDP_DB_TARGET verildi ne de eşleştirme dizininde bir `
        + `kayıt var (${pairing.pairingDir(this.config.pairingDir)}). Veritabanı sunucusunu `
        + 'başlatın; açılışta oraya kendini yazacak.',
      );
    }
    if (discovered && !dbCfg.remoteTarget) {
      this.log.info({
        target: discovered.target,
        msg: 'veritabanı eşleştirme dizininden bulundu — elle yapılandırma gerekmedi',
      });
    }

    const target = dbCfg.remoteTarget || discovered?.target;
    const controlSecret = dbCfg.controlSecret || discovered?.controlSecret;
    if (!controlSecret) {
      throw new Error(
        'denetim düzlemi sırrı yok. Veritabanı onu eşleştirme dizinine yazar; oraya erişemiyorsanız '
        + 'FITFAK_IDP_DB_CONTROL_SECRET ile verin.',
      );
    }

    // Sabitlenen parmak izleri: önyükleme sertifikası VE bizim kurduğumuz sunucu sertifikası.
    //
    // İkincisi bir düzeltme. Liste yalnızca önyükleme sertifikasını içerdiğinde, sağlama
    // BAŞARILI olduktan sonraki her yeniden deneme başarısız oluyordu: veritabanı artık bizim
    // kurduğumuz sertifikayı sunuyor ve o listede yok. Yani sağlamadan sonraki herhangi bir
    // geçici hata bağlantıyı KALICI olarak imkânsız kılıyordu, ve mesaj "sabitlenmiş parmak
    // izleri arasında değil" diyerek bunu bir saldırı gibi gösteriyordu.
    //
    // Kendi kurduğumuz sertifikayı kabul etmek sabitlemeyi zayıflatmaz: onu biz ürettik ve özel
    // anahtarını biz verdik. Liste hâlâ "ya hiç sağlanmamış bir veritabanı, ya da bizim
    // sağladığımız veritabanı" diyor.
    const fingerprints = dbCfg.bootstrapFingerprints.length
      ? dbCfg.bootstrapFingerprints.slice()
      : (discovered?.bootstrapFingerprint ? [discovered.bootstrapFingerprint] : []);
    if (this._installedServerFingerprint && !fingerprints.includes(this._installedServerFingerprint)) {
      fingerprints.push(this._installedServerFingerprint);
    }

    this._resolvedTarget = target;
    return { target, controlSecret, fingerprints };
  }

  async _connect() {
    const { resume, connectDatabase, createFitfakSslCsrProvider } = require('@fitfak/database');
    const { provisionDatabase } = require('./db-bootstrap');

    const settings = await this._resolveSettings();

    this.state = STATES.PROVISIONING;
    this.emit('stateChanged', this.state);

    // Sunucu kimliğini kur. Bu, veritabanını MÜHÜRLÜ durumdan çıkarır ama HENÜZ açmaz --
    // açılması, aşağıdaki mTLS bağlantısının başarılı olmasına bağlı.
    const provisioned = await provisionDatabase({
      config: this.config,
      pkiIssuer: this.pkiIssuer,
      settings,
      logger: this.log,
      onServerIdentityInstalled: (fingerprint) => { this._installedServerFingerprint = fingerprint; },
    });

    const csrProvider = createFitfakSslCsrProvider();
    this.identity = await resume({
      target: settings.target,
      certPem: provisioned.clientCertPem,
      privateKeyPem: provisioned.clientKeyPem,
      chainPem: provisioned.chainPem,
      principal: this.config.db.serviceName,
      roles: ['admin'],
      notAfter: provisioned.notAfter,
      csrProvider,
      logger: this.log,
    });

    this.handle = await connectDatabase({ target: settings.target, identity: this.identity });
    this.real = await this._openDatabase();

    // Şema HER açılışta uygulanır. Bu bir no-op değildir: alan eklemek bir migrasyondur ve
    // motor bunu tespit edip indeksleri yeniden kurar.
    const schema = require('../db/schema');
    await this.real.applySchemaRegistry(schema);

    this.state = STATES.CONNECTED;
    this.connectedAt = Date.now();
    this.lastError = null;
    this.emit('stateChanged', this.state);

    // Boşaltma bağlantı kurulduktan SONRA: yarıda kalan bir bağlantıya yazmaya başlamak,
    // tamponu tüketip sonra kopmak demek olurdu.
    if (this.staging.size > 0) {
      const summary = await this.staging.flushTo(this.real);
      this.log.info({
        ...summary,
        msg: 'açılış tamponu veritabanına yazıldı',
      });
      this.emit('flushed', summary);
    }

    this.log.info({
      target: settings.target,
      principal: this.identity.principal,
      spiffeId: provisioned.spiffeId,
      attempts: this.attempts,
      msg: 'veritabanı bağlantısı kuruldu — yazmalar artık doğrudan gidiyor',
    });
    this.emit('connected', { target: settings.target, principal: this.identity.principal });

    this._startRenewal();
  }

  /**
   * Veritabanı tutamağını açar ya da oluşturur.
   *
   * `createDatabase` istemci sırrını SUNUCUDA SAKLAMAZ; bir kez döner ve o kadar. Onu kaybeden
   * taraf veriyi de kaybeder, o yüzden kimlik dosyasıyla aynı muameleyi görüyor.
   */
  async _openDatabase() {
    const { storeDbHandle, loadStoredDbHandle } = require('./db-bootstrap');
    const dbCfg = this.config.db;

    const stored = await loadStoredDbHandle(dbCfg.identityDir);
    if (stored) {
      this.log.debug({ dbId: stored.dbId, msg: 'kayıtlı veritabanı tutamağı kullanılıyor' });
      return this.handle.openDatabase({ dbId: stored.dbId, clientSecret: stored.clientSecret });
    }

    if (dbCfg.dbId) {
      const clientSecret = dbCfg.rootSecret.toString('base64');
      await storeDbHandle(dbCfg.identityDir, { dbId: dbCfg.dbId, clientSecret });
      return this.handle.openDatabase({ dbId: dbCfg.dbId, clientSecret });
    }

    const created = await this.handle.createDatabase('kimlik');
    // Sır ÖNCE saklanıyor, sonra kullanılıyor: aradaki bir çökme, bir daha açılamayan bir
    // veritabanı bırakırdı.
    await storeDbHandle(dbCfg.identityDir, { dbId: created.dbId, clientSecret: created.clientSecret });
    this.log.warn({
      dbId: created.dbId,
      msg: 'yeni veritabanı oluşturuldu — erişim sırrı kimlik dizinine yazıldı, YEDEKLEYİN; '
        + 'o dosya kaybolursa veritabanı bir daha açılamaz',
    });
    return this.handle.openDatabase({ dbId: created.dbId, clientSecret: created.clientSecret });
  }

  /**
   * Kimlik yenilemesi.
   *
   * Sertifikayı YENİDEN ÜRETEREK yapılıyor, enrolment ile değil: yenileme de bir sertifika
   * talebidir ve talebin muhatabı IdP'nin kendisidir. Veritabanının sunucu sertifikası da aynı
   * anda yenileniyor -- yoksa saatler sonra IdP'ninki tazeyken veritabanınınki ölür ve bağlantı
   * anlaşılması zor bir TLS hatasıyla düşer.
   */
  _startRenewal() {
    if (this._renewalTimer) clearInterval(this._renewalTimer);
    const everyMs = Math.floor((this.config.db.identityValiditySeconds * 1000) / 2);

    this._renewalTimer = setInterval(async () => {
      if (this._stopped || this.state !== STATES.CONNECTED) return;
      const done = this.log.timer('kimlik yenileme');
      try {
        const settings = await this._resolveSettings();
        const { provisionDatabase } = require('./db-bootstrap');
        const renewed = await provisionDatabase({
          config: this.config, pkiIssuer: this.pkiIssuer, settings, logger: this.log,
        });
        await this.identity.client.upgrade({
          key: renewed.clientKeyPem,
          cert: [renewed.clientCertPem, ...renewed.chainPem.slice(0, -1)].join(''),
          ca: renewed.chainPem.join(''),
          rejectUnauthorized: true,
        });
        done({ notAfter: new Date(renewed.notAfter).toISOString() });
      } catch (err) {
        // Yenileme başarısızlığı MEVCUT sertifikayı bozmaz: eldeki hâlâ geçerli ve bir sonraki
        // turda tekrar denenecek. Bu yüzden bir uyarı, bir çökme değil.
        done({ failed: true });
        this.log.warn({ error: err.message, msg: 'kimlik yenilenemedi — mevcut sertifika ile devam ediliyor' });
      }
    }, everyMs);
    if (typeof this._renewalTimer.unref === 'function') this._renewalTimer.unref();
  }
}

function createDatabaseLink(options) { return new DatabaseLink(options); }

module.exports = { DatabaseLink, createDatabaseLink, LINK_STATES: STATES };
