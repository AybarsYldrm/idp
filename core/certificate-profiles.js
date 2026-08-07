'use strict';

const { PKI_PURPOSES } = require('./ca-vault-purposes');

// Hangi profil ne kadar yaşar, hangi ara CA imzalar, kimliği nereye yazar.
//
// Bu tablo SAF POLİTİKADIR: içinde kripto yok, dosya yok, ağ yok. Kendi
// dosyasında durmasının sebebi de bu -- core/pki-issuer.js @fitfak/ssl'i açılışta
// require ediyor, ve profil tablosu orada kaldığı sürece "bu profil kısa ömürlü
// mü" gibi bir soruyu sormak için tüm PKI kütüphanesini yüklemek gerekiyordu.
// services/workload-identity-service.js tam olarak o soruyu soruyor ve başka
// hiçbir şeye ihtiyacı yok.
//
// Ömürler amaca göre ayrışır ve ayrım bilinçlidir:
//
//   - iş yükü/oturum sertifikaları DAKİKALARLA ölçülür: kimlik kalıcı değil,
//     doğrulanmış bir oturumun süresi kadar yaşayan bir yetkidir
//   - TLS sunucu sertifikaları kısa yaşar (iptal yayılmadan da geçersizleşsin)
//   - belge/kod imzalama sertifikaları uzun yaşar: imza, sertifikanın süresi
//     dolduktan SONRA da doğrulanabilir olmalıdır

const PROFILE_MAP = {
  // ---- BeyondCorp: kısa ömürlü, SPIFFE kimlikli --------------------------------------------
  //
  // `requiresSpiffeId` bu profillerin ayırt edici özelliği: kimlik SAN'daki
  // URI'de taşınır, CN'de değil. RFC 6125 §6.4.4 CN'i kimlik olarak on yıl önce
  // terk etti ve birlikte çalışılmaya değer her iş yükü kimliği uygulaması
  // (SPIRE, Istio) SAN'a bakar.
  workload: {
    sslProfile: 'tls-client', purpose: PKI_PURPOSES.WORKLOAD,
    seconds: 300, requiresSpiffeId: true, shortLived: true,
  },
  session: {
    sslProfile: 'tls-client', purpose: PKI_PURPOSES.TLS_CLIENT,
    seconds: 300, requiresSpiffeId: true, shortLived: true,
  },
  device: {
    sslProfile: 'tls-client', purpose: PKI_PURPOSES.TLS_CLIENT,
    seconds: 600, requiresSpiffeId: true, shortLived: true,
  },
  // Servisler arası mTLS. Dakikalar yerine saatler: bir arka uç servisi kendi
  // kendini yeniler ve yenileme başarısız olduğunda geri dönmek için zamana
  // ihtiyaç duyar; beş dakika, tek bir yavaş CA turunu kesintiye dönüştürür.
  'service-identity': {
    sslProfile: 'tls-client', purpose: PKI_PURPOSES.TLS_CLIENT,
    seconds: 3600, requiresSpiffeId: true, shortLived: true,
  },

  // ---- klasik profiller ---------------------------------------------------------------------
  'client-auth': { sslProfile: 'tls-client', purpose: PKI_PURPOSES.TLS_CLIENT, days: 365 },
  'server-auth': { sslProfile: 'tls-server', purpose: PKI_PURPOSES.TLS_SERVER, days: 90 },
  smime: { sslProfile: 'email', purpose: PKI_PURPOSES.EMAIL, days: 730 },
  timestamping: { sslProfile: 'tsa', purpose: PKI_PURPOSES.TIMESTAMPING, days: 1095 },
  'code-signing': { sslProfile: 'code-signing', purpose: PKI_PURPOSES.CODE_SIGNING, days: 1095 },
  'document-signing': { sslProfile: 'code-signing', purpose: PKI_PURPOSES.CODE_SIGNING, days: 1095 },
  'ocsp-responder': { sslProfile: 'ocsp-responder', purpose: PKI_PURPOSES.OCSP, days: 365 },
};

// Kısa ömür sınırları.
//
// Alt sınır bir dakika: bundan kısası, saat kaymasına ayrılan geri-tarihlemeyle
// neredeyse tamamen örtüşür ve sertifika üretildiği anda yarılanmış olur. Üst
// sınır bir saat: bundan uzun bir "kısa ömürlü" sertifika, iptalin yayılma
// süresiyle yarışmayı bırakır ve o noktada kısa ömürlü olmanın tek faydası --
// iptale ihtiyaç duymamak -- ortadan kalkar.
const MIN_SHORT_LIVED_SECONDS = 60;
const MAX_SHORT_LIVED_SECONDS = 3600;

// notBefore ne kadar geri tarihlenir.
//
// Üretildiği anda geçerli olmaya başlayan bir sertifika, saati bir saniye geride
// olan her doğrulayıcı tarafından reddedilir -- ve bir filodaki saatler her zaman
// bir şeyin bir saniye gerisindedir. 397 günlük bir sertifikada kimse fark etmez;
// beş dakikalıkta bu, "çalışıyor" ile "filonun üçte birinde, aralıklı olarak
// başarısız" arasındaki farktır. Let's Encrypt ve SPIRE de 60 saniye kullanır.
const BACKDATE_SECONDS = 60;

const shortLivedProfiles = () => Object.keys(PROFILE_MAP).filter((name) => PROFILE_MAP[name].shortLived);

module.exports = {
  PROFILE_MAP,
  PKI_PURPOSES,
  MIN_SHORT_LIVED_SECONDS,
  MAX_SHORT_LIVED_SECONDS,
  BACKDATE_SECONDS,
  shortLivedProfiles,
};
