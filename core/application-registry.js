'use strict';

// Bir uygulamayı sisteme TEK bir işlemle almak.
//
// Bir tünel, bir SMTP aktarıcısı ya da bir DNS çözücüsü eklemek üç ayrı yerde iş yapmayı
// gerektiriyordu:
//
//   1. IdP'de bir OAuth istemcisi oluştur, sırrı bir yere not et
//   2. Veritabanında bir servis kaydet, kayıt sırrını başka bir yere not et
//   3. İkisinin adlarının ve SPIFFE kimliğinin tutmasını ELLE sağla
//
// Üçüncüsü sessizce yanlış yapılabilen kısımdı. İki sistemde iki ayrı ad varsa, uygulama OAuth
// belirteci alır ve veritabanına bağlanamaz -- ya da bağlanır ama başka bir kimlikle. Hata,
// uygulamanın ilk çalıştırıldığı anda değil, ilk kez veritabanına yazmaya çalıştığında ortaya
// çıkar ve iki sistemin günlüklerinde ayrı ayrı görünür.
//
// Burada tek bir ad var ve her şey ondan türüyor: OAuth istemci kimliği, veritabanı servis adı
// ve SPIFFE kimliği. Elle eşleştirilecek bir şey kalmıyor.
//
//
// İKİ SİSTEM, TEK İŞLEM: ATOMİKLİK DİYE BİR ŞEY YOK
//
// IdP ile veritabanı ayrı süreçler. Aralarında dağıtık bir işlem yok ve olmasını istemek de
// doğru değil -- bunun için iki fazlı bir taahhüt gerekirdi ve o, bir yönetim işlemi için
// taşınacak bir maliyet değil.
//
// Yapılan şey sıralamayı DÜŞÜRMEYE göre seçmek: önce başarısız olma ihtimali yüksek olan
// (veritabanı; kapalı olabilir, ulaşılamaz olabilir), sonra yerel olan (OAuth istemcisi).
// İkincisi düşerse birincisi GERİ ALINIYOR. Tersi sırada, veritabanı düştüğünde geriye sahibi
// olmayan bir OAuth istemcisi kalırdı ve onu kimse fark etmezdi.
//
// Geri alma da düşerse ne olduğu AÇIKÇA dönüyor. Sessizce başarılı görünmek, iki sistemin
// birbirinden habersiz olduğu bir durumu bir de gizlemek olurdu.

const spiffe = require('./spiffe');

/** Uygulama adının biçimi: veritabanının servis adı kuralıyla aynı, çünkü aynı ad. */
const NAME_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;

const DEFAULT_SCOPES = Object.freeze(['openid', 'profile']);

class ApplicationRegistry {
  /**
   * @param {object}   opts
   * @param {object}   opts.clientStore   IdP'nin OAuth istemci deposu
   * @param {object}   opts.databaseProxy core/database-admin-proxy.js
   * @param {string}   opts.trustDomain
   * @param {function} [opts.onChanged]   istemci listesi değiştiğinde (CORS tazeleme)
   * @param {object}   [opts.logger]
   */
  constructor({ clientStore, databaseProxy, trustDomain, onChanged = null, logger = null }) {
    this.clientStore = clientStore;
    this.databaseProxy = databaseProxy;
    this.trustDomain = trustDomain;
    this.onChanged = onChanged;
    this._log = logger;
  }

  /**
   * Bir uygulamayı kaydeder.
   *
   * @param {object}   app
   * @param {string}   app.name             tek ad: OAuth istemcisi, veritabanı servisi, SPIFFE
   * @param {string}  [app.description]
   * @param {string[]}[app.redirectUris]    OAuth gerekiyorsa zorunlu
   * @param {string[]}[app.scopes]
   * @param {string[]}[app.roles]           veritabanı rolleri
   * @param {boolean} [app.needsOauth=true]
   * @param {boolean} [app.needsDatabase=true]
   * @param {string[]}[app.altNames]
   * @returns {object} kimlik bilgileri BİR KEZ
   */
  async register({
    name, description = '', redirectUris = [], scopes = DEFAULT_SCOPES,
    roles = ['reader'], needsOauth = true, needsDatabase = true, altNames = [],
    generateSecret,
  }) {
    if (!NAME_RE.test(String(name || ''))) {
      throw new Error(
        "Uygulama adı küçük harf, rakam ve tire olmalı, 2-63 karakter. Bu ad üç yerde birden "
        + 'kullanılıyor (OAuth istemcisi, veritabanı servisi, SPIFFE kimliği), o yüzden üçünün '
        + 'de kabul ettiği biçimde olmak zorunda.',
      );
    }
    if (!needsOauth && !needsDatabase) {
      throw new Error('Uygulama ya OAuth ya veritabanı erişimi istemeli; ikisi de değilse kaydedilecek bir şey yok.');
    }
    if (needsOauth && redirectUris.length === 0) {
      // Yönlendirme adresi olmayan bir istemci yetkilendirme kodu alamaz. Kaydı yine de
      // oluşturmak, çalışmayacağı ilk kullanıldığında anlaşılan bir uygulama bırakırdı.
      throw new Error('OAuth isteyen bir uygulama için en az bir yönlendirme adresi gerekli.');
    }

    // SPIFFE kimliği ADDAN türüyor ve iki tarafta da aynı olduğu buradan geliyor. Veritabanı
    // da aynı kuralla türetiyor; ikisinin ayrı hesaplaması, ayrışabilecekleri bir yer olurdu --
    // o yüzden burada üretilip AÇIKÇA gönderiliyor.
    const spiffeId = spiffe.build(this.trustDomain, 'service', name).uri;

    let databaseResult = null;
    if (needsDatabase) {
      // ÖNCE veritabanı: düşme ihtimali yüksek olan taraf o (kapalı olabilir, ulaşılamaz
      // olabilir). Sonraya bıraksaydık, düştüğünde geriye sahibi olmayan bir OAuth istemcisi
      // kalır ve onu kimse fark etmezdi.
      const { status, payload } = await this.databaseProxy.forward('POST', '/services', {
        name, roles, description, altNames, kind: 'service', maxUses: 1,
      });
      if (status >= 400) {
        throw new Error(
          `Veritabanında servis oluşturulamadı (${payload.error || status}): `
          + `${payload.error_description || 'sebep bildirilmedi'}`,
        );
      }
      databaseResult = payload;
    }

    let oauthResult = null;
    if (needsOauth) {
      const clientSecret = generateSecret();
      try {
        oauthResult = await this.clientStore.createClient({
          clientId: name,
          clientSecret,
          name: description || name,
          redirectUris,
          allowedScopes: scopes,
          firstParty: false,
        });
        oauthResult = { ...oauthResult, clientSecret };
      } catch (err) {
        // OAuth kaydı düştü ve veritabanında bir servis bıraktık. Geri alınıyor -- yoksa aynı
        // adla ikinci bir deneme "bu servis zaten var" ile reddedilir ve operatör, neyin
        // yarım kaldığını anlamadan sıkışır.
        if (databaseResult) {
          const rollback = await this.databaseProxy.forward('POST', '/services/remove', { name });
          if (rollback.status >= 400) {
            // Geri alma da düştü. SESSİZ KALMAK en kötüsü olurdu: iki sistem birbirinden
            // habersiz kalır ve durumu yalnızca elle temizlemek mümkün olur.
            this._log?.error?.({
              name, error: err.message, rollback: rollback.payload,
              msg: 'OAuth kaydı düştü ve veritabanı servisi geri alınamadı — elle temizlik gerekli',
            });
            throw new Error(
              `OAuth istemcisi oluşturulamadı (${err.message}), ve veritabanındaki '${name}' `
              + 'servisi geri alınamadı. Veritabanı panelinden elle silin, sonra tekrar deneyin.',
            );
          }
        }
        throw err;
      }
    }

    if (this.onChanged) await this.onChanged();
    this._log?.warn?.({
      name, spiffeId, oauth: !!oauthResult, database: !!databaseResult,
      msg: 'uygulama kaydedildi',
    });

    return {
      name,
      spiffeId,
      description,
      // Sırlar BİR KEZ dönüyor ve hiçbir listeleme ucundan tekrar okunamıyor. İkisi de burada
      // birlikte dönüyor, çünkü ayrı ayrı dönselerdi operatör birini kaydedip diğerini kaçırır.
      oauth: oauthResult && {
        clientId: oauthResult.clientId,
        clientSecret: oauthResult.clientSecret,
        redirectUris: oauthResult.redirects || oauthResult.redirectUris || [],
        scopes,
      },
      database: databaseResult && {
        serviceName: name,
        enrolmentSecret: databaseResult.secret,
        roles,
      },
      // Kopyalanıp uygulamanın ortamına yapıştırılacak hâli. Operatörün değerleri tek tek
      // toplaması, bu işi zorlaştıran şeyin kendisiydi.
      environment: buildEnvironment({ name, spiffeId, oauthResult, databaseResult, trustDomain: this.trustDomain }),
    };
  }

  /**
   * Kayıtlı uygulamalar, iki sistemin görüşü BİRLEŞTİRİLMİŞ olarak.
   *
   * Birleştirmenin asıl değeri EKSİKLERİ göstermesi: yalnızca bir tarafta duran bir kayıt,
   * çalışmayacak bir uygulamadır ve iki ayrı panele bakan biri bunu göremez.
   */
  async list() {
    const clients = await this.clientStore.listClients();
    const byName = new Map();

    for (const client of clients) {
      byName.set(client.clientId, {
        name: client.clientId,
        description: client.name,
        oauth: {
          scopes: client.allowedScopes || [],
          redirects: (client.redirects || []).map((r) => r.redirectUri),
        },
        database: null,
      });
    }

    const { status, payload } = await this.databaseProxy.forward('GET', '/services');
    const databaseReachable = status < 400;
    if (databaseReachable) {
      for (const service of payload.services || []) {
        // Sistem servisleri uygulama değil: kimlik sağlayıcısı buraya ait değil ve onu
        // uygulamaların arasında göstermek, üzerinde işlem yapılabilirmiş izlenimi verirdi.
        if (service.system) continue;
        const entry = byName.get(service.name) || {
          name: service.name, description: service.description || '', oauth: null, database: null,
        };
        entry.database = {
          roles: service.roles || [],
          spiffeId: service.spiffeId,
          enrolled: !!service.enrolledAt,
          credentialSpent: !!service.credentialSpent,
          megabytes: service.usage ? service.usage.megabytes : 0,
        };
        byName.set(service.name, entry);
      }
    }

    return {
      databaseReachable,
      applications: [...byName.values()]
        .map((entry) => ({
          ...entry,
          // Tek taraflı bir kayıt çalışmaz ve panelde öyle görünmeli.
          complete: !!entry.oauth === !!entry.database ? true : false,
          missing: entry.oauth && !entry.database ? 'database'
            : (!entry.oauth && entry.database ? 'oauth' : null),
        }))
        .sort((a, b) => a.name.localeCompare(b.name)),
    };
  }

  /** Bir uygulamayı iki sistemden de kaldırır. */
  async remove(name) {
    const removed = { oauth: false, database: false, errors: [] };

    try {
      await this.clientStore.deleteClient(name);
      removed.oauth = true;
    } catch (err) {
      removed.errors.push(`OAuth: ${err.message}`);
    }

    const { status, payload } = await this.databaseProxy.forward('POST', '/services/remove', { name });
    if (status < 400) removed.database = true;
    else removed.errors.push(`Veritabanı: ${payload.error_description || payload.error || status}`);

    if (this.onChanged) await this.onChanged();
    // Kısmi kaldırma AÇIKÇA bildiriliyor. "Silindi" deyip yarısını bırakmak, aynı adla ikinci
    // bir kaydın anlaşılmaz bir çakışmayla reddedilmesi demek.
    this._log?.warn?.({ name, ...removed, msg: 'uygulama kaldırıldı' });
    return removed;
  }
}

/**
 * Uygulamanın ortam değişkenleri.
 *
 * Operatörün değerleri iki panelden tek tek toplaması, bu işi zorlaştıran şeyin ta kendisiydi.
 * Adres ve güven çıpası BURADA YOK: onları uygulama eşleştirme dizininden kendisi buluyor
 * (examples/app-client.js), ve buraya yazmak onları elle girilen değerler hâline geri getirirdi.
 */
function buildEnvironment({ name, spiffeId, oauthResult, databaseResult, trustDomain }) {
  const lines = [
    `FITFAK_SERVICE_NAME='${name}'`,
    `FITFAK_TRUST_DOMAIN='${trustDomain}'`,
    `# SPIFFE kimliği: ${spiffeId}`,
  ];
  if (oauthResult) {
    lines.push(
      `FITFAK_OAUTH_CLIENT_ID='${oauthResult.clientId}'`,
      `FITFAK_OAUTH_CLIENT_SECRET='${oauthResult.clientSecret}'`,
    );
  }
  if (databaseResult) {
    lines.push(
      '# Tek kullanımlık: ilk kayıttan sonra harcanır, ortamdan kaldırın.',
      `FITFAK_ENROLMENT_SECRET='${databaseResult.secret}'`,
    );
  }
  return lines.join('\n');
}

function createApplicationRegistry(options) { return new ApplicationRegistry(options); }

module.exports = { ApplicationRegistry, createApplicationRegistry, APPLICATION_NAME_RE: NAME_RE };
