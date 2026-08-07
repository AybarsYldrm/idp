'use strict';

// SPIFFE kimlik modeli.
//
// Bu dosya kasıtlı olarak İNCE: gerçek ayrıştırıcı @fitfak/database içinde
// (src/provisioning/spiffe.js) ve buradan yalnızca yeniden dışa aktarılıyor.
//
// Neden kopyalanmıyor: bir SPIFFE kimliği iki taraf arasında KARŞILAŞTIRILAN
// bir değerdir. IdP sertifikayı üretir, veritabanı onu doğrular. İki ayrı
// ayrıştırıcı, aynı sertifikayı iki farklı kimlik olarak okuyabileceği ilk gün
// birbirinden ayrışmaya başlar -- ve bu ayrışma, tam olarak yetkilendirme
// kararının verildiği yerde olur. Tek uygulama, tek kural.
//
// Buradaki ek şey yalnızca bu dağıtımın güven alanı (trust domain) ve kimlik
// biçimleri: hangi yolun neyi ifade ettiği bir dağıtım kararıdır ve tek bir
// yerde yazılı olması, bir sonraki dosyada 'service/' yerine 'services/'
// yazılmasını engelleyen şeydir.

const path = require('node:path');

/**
 * Paketi çözer; kurulu değilse yan yana duran bir checkout'u dener.
 *
 * Yan yana checkout yolu bir GELİŞTİRME kolaylığıdır ve paketin kurulu olduğu
 * her yerde hiç denenmez. Var olma sebebi: bu iki depo birlikte geliştiriliyor
 * ve SPIFFE ayrıştırıcısı ikisinin de kullandığı tek uygulama, dolayısıyla
 * `npm install` yapılmamış bir checkout'ta onu test edememek, ortak kodun
 * testsiz kalması demek olurdu. @fitfak/database'in kendi test paketi
 * scripts/link-grpc.js ile aynı deseni kullanıyor.
 */
function requireDatabasePackage() {
  const attempts = [
    '@fitfak/database',
    path.join(__dirname, '..', '..', 'database'),
  ];
  const failures = [];
  for (const candidate of attempts) {
    try {
      // eslint-disable-next-line global-require, import/no-dynamic-require
      return require(candidate);
    } catch (err) {
      failures.push(`${candidate}: ${err.message}`);
    }
  }
  throw new Error(
    '[fitfak-idp] SPIFFE kimlik modeli @fitfak/database içinden geliyor ve yüklenemedi.\n'
    + `  ${failures.join('\n  ')}\n`
    + '  İkinci bir kopyasını buraya yazmak çözüm DEĞİL: kimlik, IdP ile veritabanının\n'
    + '  KARŞILAŞTIRDIĞI bir değerdir ve iki ayrı ayrıştırıcı er ya da geç aynı\n'
    + '  sertifikayı iki farklı kimlik olarak okur.',
  );
}

const { spiffe } = requireDatabasePackage();
if (!spiffe) throw new Error('[fitfak-idp] @fitfak/database bu sürümde `spiffe` dışa aktarmıyor');

const TRUST_DOMAIN = process.env.FITFAK_TRUST_DOMAIN || 'fitfak.net';

/**
 * Bu dağıtımın kimlik biçimleri. Hepsi güven alanını kendisi koyar, çünkü
 * çağıranın her seferinde yazması, bir yerde yanlış yazılmasıyla aynı şeydir.
 *
 * Değerler (userId, deviceId, sessionId) DIŞARIDAN gelir; build() bunları
 * doğrular ve bir eğik çizgi içeren değerin yolu derinleştirmesini engeller --
 * `spiffe://fitfak.net/user/abc/../service/idp` yazmaya çalışan bir kayıt
 * burada reddedilir, sertifikada değil.
 */
const identities = {
  trustDomain: TRUST_DOMAIN,

  /** Uzun ömürlü sunucu tarafı iş yükü: IdP'nin kendisi, SMTP aktarıcısı. */
  service: (name) => spiffe.forService(TRUST_DOMAIN, name),
  /** Zamanlanmış/geçici iş yükü örneği. */
  workload: (name, instance) => spiffe.forWorkload(TRUST_DOMAIN, name, instance),
  /** Donanım destekli kimlik bilgisi taşıyan kayıtlı cihaz. */
  device: (deviceId) => spiffe.forDevice(TRUST_DOMAIN, deviceId),
  /** İnsan -- istemci sertifikası bağlamında. */
  user: (userId) => spiffe.forUser(TRUST_DOMAIN, userId),
  /**
   * TEK bir doğrulanmış oturum. BeyondCorp'un kısa ömürlü sertifikası tam
   * olarak budur: sertifika kalıcı bir kimlik değil, o oturumun süresi kadar
   * yaşayan bir yetkidir.
   */
  session: (sessionId) => spiffe.forSession(TRUST_DOMAIN, sessionId),
  /** Otomasyon/CI asıl kimliği. */
  agent: (agentId) => spiffe.forAgent(TRUST_DOMAIN, agentId),
};

module.exports = { ...spiffe, TRUST_DOMAIN, identities };
