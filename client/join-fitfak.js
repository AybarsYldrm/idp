'use strict';

const path = require('node:path');

const { IdentityClient } = require('./identity-client');

// BİR UYGULAMANIN BU YIĞINA KATILMASI -- TEK ÇAĞRIYLA.
//
//     const app = await joinFitfak({ name: 'dns-resolver' });
//
//     app.spiffeId                      // spiffe://fitfak.net/service/dns-resolver
//     app.db.collection('records')      // mTLS üzerinden veritabanı, kendini yenileyen kimlikle
//     await app.identity.introspectToken(token)   // IdP'ye "bu belirteç geçerli mi"
//     await app.close();
//
// BU DOSYA NEDEN VAR
//
// İki yarısı da zaten vardı ve ikisi de ayrı ayrı doğruydu:
//
//   * veritabanı tarafı: @fitfak/database'in `joinAsService()` -- keşif, kayıt-ya-da-devam,
//     sertifikanın saklanması, yenileme, bağlantı
//   * IdP tarafı: client/identity-client.js -- belirteç doğrulama, oturum sorgulama
//
// Eksik olan, ikisinin AYNI KİMLİK altında birleştiği yerdi. Bir uygulama iki ayrı şeyi elle
// tutturmak zorundaydı: veritabanına hangi adla kaydolduğu ve IdP'de hangi istemci kimliğiyle
// konuştuğu. core/application-registry.js bunları TEK bir addan türetiyor -- OAuth istemci
// kimliği, veritabanı servis adı ve SPIFFE kimliği hep o ad. Ama uygulama tarafında o tekliği
// koruyan bir şey yoktu, yani kayıt tek adla yapılıyor, kullanım iki ayrı yerden okunuyordu.
//
// Buradaki mekanizma o teklikten faydalanıyor: ad bir kez veriliyor, üç kimlik de ondan
// türüyor ve ayrışabilecekleri bir yer kalmıyor.
//
//
// KEŞİF EVET, SIRLAR HAYIR
//
// Adresler, kök sertifika ve güven alanı EŞLEŞTİRME DİZİNİNDEN okunuyor (core/pairing.js): bir
// operatörün beş değeri terminalden kopyalayıp iki yere girmesi, bu iki projeyi bağlamayı
// fiilen imkânsız kılan şeydi.
//
// SIRLAR ORADAN OKUNMUYOR ve okunmamalı. Kayıt sırrı ile OAuth istemci sırrı BU uygulamanın
// kendi kimlik bilgileri; yönetim panelinde bir kez gösteriliyorlar. Paylaşılan bir dizinden
// okunabilen bir sır, o makinedeki her sürecin kullanabileceği bir sır demektir ve kimlik
// modelinin tamamı "bu dizini okuyabiliyor musun" sorusuna indirgenir. Aynı gerekçe
// @fitfak/database'in service-identity.js dosyasında da yazılı; ikisi aynı kural.

const DEFAULT_STATE_DIR = () => process.env.FITFAK_SERVICE_STATE_DIR
  || path.join(process.cwd(), '.service-state');

/** Ad, üç sistemin de kabul ettiği biçimde olmak zorunda -- çünkü üçünde de aynı ad. */
const NAME_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;

class JoinError extends Error {
  constructor(message, { half = null, cause = null } = {}) {
    super(message);
    this.name = 'JoinError';
    // Hangi yarının düştüğü: bir uygulamanın veritabanına bağlanamaması ile IdP'ye
    // bağlanamaması çok farklı iki operasyonel durum ve tek bir "bağlanamadı" ikisini de gizler.
    this.half = half;
    this.cause = cause;
  }
}

/**
 * Uygulamayı yığına bağlar.
 *
 * @param {object}   opts
 * @param {string}   opts.name              yönetim panelinde kayıtlı TEK ad
 * @param {string}  [opts.enrolmentSecret]  ilk çalıştırma; base64. Öntanımlı FITFAK_ENROLMENT_SECRET
 * @param {string}  [opts.accessToken]      kayıt sırrı yerine, IdP ayaktayken
 * @param {string}  [opts.oauthClientSecret] IdP'ye konuşmak için. Öntanımlı FITFAK_OAUTH_CLIENT_SECRET
 * @param {boolean} [opts.needsDatabase=true]
 * @param {boolean} [opts.needsIdp=true]
 * @param {string}  [opts.stateDir]         sertifikanın yeniden başlatmalar arasında durduğu yer
 * @param {string}  [opts.pairingDir]
 * @param {string}  [opts.issuer]           keşfi ezmek için
 * @param {string}  [opts.trustDomain]
 * @param {string[]}[opts.roles]            veritabanı rolleri
 * @param {boolean} [opts.waitForStack=false] yığın henüz açılmadıysa bekle
 * @param {object}  [opts.logger]
 * @returns {{ name, spiffeId, db, handle, serviceIdentity, identity, issuer, trustAnchorsPem, close }}
 */
async function joinFitfak({
  name,
  enrolmentSecret = process.env.FITFAK_ENROLMENT_SECRET || '',
  accessToken = process.env.FITFAK_ACCESS_TOKEN || '',
  oauthClientSecret = process.env.FITFAK_OAUTH_CLIENT_SECRET || '',
  needsDatabase = true,
  needsIdp = true,
  stateDir = DEFAULT_STATE_DIR(),
  pairingDir = process.env.FITFAK_PAIRING_DIR || null,
  issuer = process.env.FITFAK_IDP_ISSUER || null,
  trustDomain = process.env.FITFAK_TRUST_DOMAIN || null,
  roles = [],
  databaseName = 'main',
  waitForStack = false,
  logger = null,
} = {}) {
  if (!NAME_RE.test(String(name || ''))) {
    throw new JoinError(
      `'${name}' geçerli bir uygulama adı değil. Küçük harf, rakam ve tire, 2-63 karakter. `
      + 'Bu ad ÜÇ yerde birden kullanılıyor -- OAuth istemci kimliği, veritabanı servis adı ve '
      + 'SPIFFE kimliği -- o yüzden üçünün de kabul ettiği biçimde olmak zorunda.',
    );
  }
  if (!needsDatabase && !needsIdp) {
    throw new JoinError('Uygulama ya veritabanına ya IdP\'ye bağlanmalı; ikisi de değilse katılacak bir şey yok.');
  }

  const database = require('@fitfak/database');
  const pairing = require('../core/pairing');

  // ---- keşif ---------------------------------------------------------------------------------
  //
  // Eşleştirme dizini YOKSA bu bir hata değil: uygulamaya adresler açıkça verilmiş olabilir.
  // Hata, ne dizinden ne de ortamdan bir cevap çıkmadığında -- ve o zaman hangi değerin eksik
  // olduğu söyleniyor.
  let published = null;
  try {
    published = await pairing.readIdp({ dir: pairingDir, logger });
  } catch (err) {
    logger?.debug?.({ error: err.message, msg: 'eşleştirme dizini okunamadı — açık ayarlara düşülüyor' });
  }

  const resolvedIssuer = issuer || published?.issuer || null;
  const resolvedTrustDomain = trustDomain || published?.trustDomain || 'fitfak.net';
  const spiffeId = database.spiffe.build(resolvedTrustDomain, 'service', name).uri;

  if (needsIdp && !resolvedIssuer) {
    throw new JoinError(
      `'${name}' IdP'ye bağlanacak ama IdP'nin adresi bilinmiyor. IdP ayağa kalktığında adresini `
      + `eşleştirme dizinine yazar (${pairing.pairingDir(pairingDir)}); o dizini paylaşmıyorsanız `
      + 'FITFAK_IDP_ISSUER verin.',
      { half: 'idp' },
    );
  }
  if (needsIdp && !oauthClientSecret) {
    throw new JoinError(
      `'${name}' için OAuth istemci sırrı yok. Bu sır uygulamanın KENDİ kimlik bilgisidir ve `
      + 'yönetim panelinde kaydedilirken bir kez gösterilir -- paylaşılan bir dizinden '
      + 'okunabilseydi, o makinedeki her süreç bu uygulama gibi konuşabilirdi. '
      + 'FITFAK_OAUTH_CLIENT_SECRET olarak verin.',
      { half: 'idp' },
    );
  }

  // ---- veritabanı yarısı ----------------------------------------------------------------------
  //
  // Sıra kasıtlı: düşme ihtimali yüksek olan taraf bu (mühürlü olabilir, IdP henüz onu
  // açmamış olabilir, ağda olmayabilir). IdP istemcisi ise yerel bir nesne ve kurulması
  // bir tur atmıyor. Tersi sırada, veritabanı düştüğünde kurulmuş ama kullanılmayan bir
  // istemci kalırdı.
  let service = null;
  if (needsDatabase) {
    const join = waitForStack ? database.joinAsServiceWhenReady : database.joinAsService;
    const options = {
      serviceName: name,
      stateDir,
      enrolmentSecret,
      accessToken,
      pairingDir,
      trustDomain: resolvedTrustDomain,
      roles,
      databaseName,
      logger,
    };
    try {
      service = waitForStack ? await join(options, { logger }) : await join(options);
    } catch (err) {
      throw new JoinError(
        `'${name}' veritabanına bağlanamadı: ${err.message}`,
        { half: 'database', cause: err },
      );
    }

    // Kayıt tek addan türüyor; iki tarafın AYNI kimliğe vardığı burada doğrulanıyor.
    // Ayrıştıkları hâl gerçekten yaşandı: uygulama tarafı adın `-service` ekini kırpıyordu,
    // yani IdP `spiffe://…/service/smtp-service` veriyor, uygulama `…/service/smtp` istiyordu
    // ve kayıt reddediliyordu. Kontrol ucuz ve hatayı doğru yerde gösteriyor.
    if (service.spiffeId !== spiffeId) {
      await service.close().catch(() => {});
      const installed = (() => {
        try { return require('@fitfak/database/package.json').version; } catch (_) { return 'bilinmiyor'; }
      })();
      throw new JoinError(
        `Kimlik ayrışması: IdP '${spiffeId}' veriyor, veritabanı istemcisi '${service.spiffeId}' `
        + `istiyor. İkisi de AYNI addan ('${name}') çıkmak zorunda -- tek adla kaydın bütün `
        + 'amacı elle tutturulacak bir şey bırakmamak.\n\n'
        + `  Kurulu @fitfak/database: ${installed}\n\n`
        + '  Bilinen sebep: @fitfak/database'
        + " 2.3.0 ve öncesi, `joinAsService` içinde adın `-service` ekini kırpıyor"
        + " (`serviceName.replace(/-service$/, '')`). IdP ise adı OLDUĞU GİBİ kullanıyor, yani"
        + " `-service` ile biten HER uygulama için kayıt reddedilir. Düzeltmeyi içeren sürüme"
        + ' yükseltin, ya da uygulamayı `-service` ile bitmeyen bir adla kaydedin.',
        { half: 'database' },
      );
    }
  }

  // ---- IdP yarısı -------------------------------------------------------------------------
  let identity = null;
  if (needsIdp) {
    identity = new IdentityClient({
      baseUrl: resolvedIssuer,
      clientId: name,
      clientSecret: oauthClientSecret,
      // Kök sertifika eşleştirme dizininden geliyor. Verilmezse Node'un kamusal kök listesi
      // kullanılır -- ki `session.fitfak.net` genel bir sertifika taşıyorsa doğru olabilir.
      // Açıkça yazılmasının sebebi, hangisinin geçerli olduğunun okunabilir olması.
      ...(published?.rootCertPem ? { ca: published.rootCertPem } : {}),
    });
  }

  logger?.info?.({
    application: name,
    spiffeId,
    database: needsDatabase ? 'bağlı' : 'istenmedi',
    idp: needsIdp ? resolvedIssuer : 'istenmedi',
    msg: 'uygulama yığına katıldı',
  });

  return {
    name,
    spiffeId,
    trustDomain: resolvedTrustDomain,
    issuer: resolvedIssuer,
    // Kök sertifika(lar): bu uygulama başka bir eşi doğrulayacaksa güven çıpası budur.
    // ARA sertifika DEĞİL: bir ara CA'yı çıpa olarak kurmak, kökün onun hakkındaki iptalini
    // hiç sormamak demektir (bkz. @fitfak/database src/provisioning/chain.js).
    trustAnchorsPem: published?.rootCertPem || null,
    rootFingerprint: published?.rootFingerprint || null,

    /** Veri düzlemi: mTLS üzerinden, kendini yenileyen bir kimlikle. */
    db: service ? service.db : null,
    handle: service ? service.handle : null,
    /** @fitfak/database'in ManagedIdentity'si -- sertifika, yenileme, olaylar. */
    serviceIdentity: service ? service.identity : null,

    /** IdP: belirteç doğrulama, oturum sorgulama ve iptali. */
    identity,

    async close() {
      if (service) await service.close().catch(() => {});
    },
  };
}

/**
 * Yığın henüz açık değilse bekleyen biçim.
 *
 * Ayrı bir seçenek, çünkü ikisi farklı şeyler istiyor: yanlış yapılandırıldığında ÇIKMASI
 * gereken bir araç düz çağrıyı, ilk başlatılabilmesi gereken uzun ömürlü bir servis bunu
 * ister. Veritabanı IdP onu açana kadar herkesi reddeder ve bu bir arıza değil, bu mimaride
 * normal bir açılış sıralamasıdır.
 */
function joinFitfakWhenReady(options = {}) {
  return joinFitfak({ ...options, waitForStack: true });
}

module.exports = { joinFitfak, joinFitfakWhenReady, JoinError };
