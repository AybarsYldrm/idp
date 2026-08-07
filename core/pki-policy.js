'use strict';

// FITFAK sertifika politikaları — IANA Private Enterprise Number 65133.
//
// Bir sertifika politikası OID'i, "bu sertifika hangi kurallara göre verildi"
// sorusunun makine tarafından okunabilir cevabıdır. Doğrulayan taraf bunu
// görüp "yalnızca şu politikayla verilmiş sertifikaları kabul et" diyebilir --
// EKU'dan farklı olarak bu, anahtarın NE İÇİN kullanılabileceğini değil,
// kimliğin NASIL doğrulandığını anlatır. İkisi ayrı sorulardır: iki sertifika
// aynı EKU'ya (clientAuth) sahip olup biri e-posta doğrulamasıyla, diğeri
// yalnızca bir paylaşılan sırla verilmiş olabilir.
//
// Arc:  1.3.6.1.4.1.65133
//         .1            sertifika politikaları
//           .1  device / client authentication
//           .2  TLS server
//           .3  S/MIME
//           .4  timestamping        (RFC 3161 TSA politikası)
//           .5  code signing
//           .6  document signing
//           .7  OCSP responder
//           .8  kısa ömürlü iş yükü kimliği   (SPIFFE, BeyondCorp)
//           .9  kısa ömürlü oturum kimliği
//           .10 kısa ömürlü cihaz kimliği
//           .11 servisler arası mTLS kimliği
//         .2            protokol/uzantı arc'ı (ileride)

const PEN = '1.3.6.1.4.1.65133';
const POLICY_ARC = `${PEN}.1`;

// Politika belgelerinin yayınlandığı yer. Sertifikanın içine gömülen CPS
// bağlantısı buraya işaret eder; doğrulayan taraf sertifikadan çıkardığı OID
// ile bu adresi ziyaret edip metni okuyabilir.
const POLICY_BASE_URL = process.env.FITFAK_TRUST_POLICY_URL || 'https://trust.fitfak.net/policy';

/**
 * Her politika için: OID, insan tarafından okunabilir ad, CPS adresi ve
 * sertifikaya gömülecek kullanıcı bildirimi (user notice).
 *
 * `identityProofing` alanı belgeleyicidir ama gelişigüzel değildir: /policy
 * altında yayınlanan metin bu tablodan üretilir, böylece "politika ne diyor"
 * ile "kod ne yapıyor" tek kaynaktan gelir ve zamanla ayrışamaz.
 */
const POLICIES = {
  'client-auth': {
    oid: `${POLICY_ARC}.1`,
    name: 'FITFAK Device & Client Authentication',
    identityProofing: 'Doğrulanmış e-posta adresine sahip, MFA kurulumu tamamlanmış hesap',
    notice: 'Bu sertifika yalnızca FITFAK sistemlerine istemci kimlik doğrulaması için verilmiştir.',
  },
  'server-auth': {
    oid: `${POLICY_ARC}.2`,
    name: 'FITFAK TLS Server',
    identityProofing: 'ACME http-01 alan adı sahipliği doğrulaması',
    notice: 'Bu sertifika, alan adı sahipliği doğrulanarak verilmiş bir TLS sunucu sertifikasıdır.',
  },
  smime: {
    oid: `${POLICY_ARC}.3`,
    name: 'FITFAK Secure Email (S/MIME)',
    identityProofing: 'Doğrulanmış e-posta adresi; sertifikadaki rfc822Name hesabın adresidir',
    notice: 'Bu sertifikadaki e-posta adresi FITFAK tarafından doğrulanmıştır.',
  },
  timestamping: {
    oid: `${POLICY_ARC}.4`,
    name: 'FITFAK Time Stamping Authority',
    identityProofing: 'Yalnızca FITFAK altyapı bileşenlerine verilir',
    notice: 'RFC 3161 zaman damgası politikası. Zaman kaynağı UTC ile senkronizedir.',
  },
  'code-signing': {
    oid: `${POLICY_ARC}.5`,
    name: 'FITFAK Code Signing',
    identityProofing: 'Yönetici onayı + doğrulanmış hesap',
    notice: 'Bu sertifika yazılım imzalama için verilmiştir.',
  },
  'document-signing': {
    oid: `${POLICY_ARC}.6`,
    name: 'FITFAK Document Signing',
    identityProofing: 'Yönetici onayı + doğrulanmış hesap',
    notice: 'Bu sertifika belge imzalama için verilmiştir.',
  },
  'ocsp-responder': {
    oid: `${POLICY_ARC}.7`,
    name: 'FITFAK OCSP Responder',
    identityProofing: 'Yalnızca FITFAK altyapı bileşenlerine verilir',
    notice: 'Bu sertifika OCSP yanıtlarını imzalamak için verilmiştir.',
  },

  // ---- kısa ömürlü (BeyondCorp) politikalar --------------------------------------------------
  //
  // Bunların ayrı OID'leri olması önemli: bir doğrulayıcı "yalnızca kısa ömürlü,
  // JIT üretilmiş kimlikleri kabul et" diyebilmelidir. EKU bunu söyleyemez --
  // kısa ömürlü bir iş yükü sertifikası ile bir yıllık bir istemci sertifikası
  // aynı clientAuth EKU'sunu taşır. Fark, kimliğin NASIL doğrulandığındadır ve
  // sertifika politikası tam olarak o sorunun cevabıdır.
  //
  // `identityProofing` alanları, iptalin neden nadiren gerektiğini de açıklar:
  // her biri, üretim anında canlı olarak doğrulanmış bir yetkiye dayanır ve o
  // yetki geri alındığında sertifika YENİLENMEZ -- iptal edilmesi gerekmez,
  // dakikalar içinde kendiliğinden yok olur.
  workload: {
    oid: `${POLICY_ARC}.8`,
    name: 'FITFAK Short-Lived Workload Identity',
    identityProofing: 'Üretim anında doğrulanmış OAuth 2.0 yetkisi ya da mevcut mTLS kimliği; '
      + 'kimlik SAN\'daki SPIFFE URI\'sinde taşınır',
    notice: 'Kısa ömürlü iş yükü sertifikası. Kalıcı bir kimlik değil, dakikalarla ölçülen bir yetkidir.',
  },
  session: {
    oid: `${POLICY_ARC}.9`,
    name: 'FITFAK Short-Lived Session Identity',
    identityProofing: 'Üretim anında canlı olduğu doğrulanmış, MFA tamamlanmış kullanıcı oturumu',
    notice: 'Bu sertifika tek bir doğrulanmış oturumu temsil eder ve o oturumdan uzun yaşamaz.',
  },
  device: {
    oid: `${POLICY_ARC}.10`,
    name: 'FITFAK Short-Lived Device Identity',
    identityProofing: 'Kayıtlı cihaz bağlaması (WebAuthn ya da donanım destekli kimlik bilgisi)',
    notice: 'Kısa ömürlü cihaz sertifikası. Cihaz kaydı geri alındığında yenilenmez.',
  },
  'service-identity': {
    oid: `${POLICY_ARC}.11`,
    name: 'FITFAK Service Identity (mTLS)',
    identityProofing: 'Kayıt otoritesi (fitdb) tarafından doğrulanmış servis kimliği',
    notice: 'Servisler arası mTLS kimliği. Saatlerle ölçülür ve mTLS üzerinden yenilenir.',
  },
};

/**
 * Bir profil için @fitfak/ssl'in `policies` seçeneğinin beklediği yapıyı üretir
 * (OID + CPS bağlantısı + user notice).
 */
function policyForProfile(profile) {
  const policy = POLICIES[profile];
  if (!policy) return null;
  return [{
    oid: policy.oid,
    cps: `${POLICY_BASE_URL}/${profile}`,
    notice: {
      organization: 'FITFAK',
      noticeNumbers: [1],
      text: policy.notice,
    },
  }];
}

/** trust.fitfak.net/policy altında yayınlanacak makine-okunur politika dizini. */
function policyDirectory() {
  return {
    pen: PEN,
    policyArc: POLICY_ARC,
    baseUrl: POLICY_BASE_URL,
    policies: Object.entries(POLICIES).map(([profile, p]) => ({
      profile,
      oid: p.oid,
      name: p.name,
      identityProofing: p.identityProofing,
      notice: p.notice,
      cps: `${POLICY_BASE_URL}/${profile}`,
    })),
  };
}

module.exports = { PEN, POLICY_ARC, POLICY_BASE_URL, POLICIES, policyForProfile, policyDirectory };
