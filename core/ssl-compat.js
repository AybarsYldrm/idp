'use strict';

// @fitfak/ssl'in beklenen sürümde olduğunu AÇILIŞTA doğrular.
//
// Bu dosya bir olaydan sonra yazıldı. package.json `^1.0.2` diyordu; kütüphanenin 2.x'i
// yayınlandığında o aralık onu hiçbir zaman kurmadı ve kurulum eski sürümde kaldı. Sonuç,
// CSR'den üretilen sertifikaların istekteki özel anahtarla eşleşmemesiydi.
//
// EŞLEŞMEME NEDEN SESSİZDİR
//
// Sertifika üretilir, PEM olarak döner, ayrıştırılır, tarihleri doğrudur, zinciri doğrulanır.
// Yanlış olan tek şey İÇİNDEKİ AÇIK ANAHTARDIR ve onu kimse okumaz. Hata ancak o sertifika bir
// TLS el sıkışmasında kullanıldığında ortaya çıkar -- sunucu tarafında "key values mismatch"
// ya da istemci tarafında anlamı olmayan bir handshake failure olarak, yani sertifikayı ÜRETEN
// koddan bir ağ hattı ötede.
//
// İki ayrı kontrol var ve ikisi de gerekli:
//
//   1. SÜRÜM. Yanlış sürümü isim olarak yakalar ve neyin yükleneceğini söyler.
//   2. DAVRANIŞ. Asıl kanıt budur: bir anahtar çifti üretilir, ondan bir CSR kurulur, imzalanır
//      ve çıkan sertifikanın açık anahtarının BAŞLANGIÇTAKİ özel anahtara ait olduğu doğrulanır.
//      Sürüm numarası bir vaattir; bu bir ölçümdür.
//
// Kontrol ucuz değil (bir anahtar üretimi ve bir imza, birkaç milisaniye) ama açılışta bir kez
// çalışıyor ve karşılığında, aylarca sürebilecek bir teşhisi ortadan kaldırıyor.

const crypto = require('node:crypto');

const MIN_MAJOR = 2;

// 2.x'te profil adları değişti. Eski adlarla çağırmak "Bilinmeyen profil" hatası verir -- bu
// gürültülü bir hatadır ve kendini gösterir, ama mesajı hangi eşlemenin eksik olduğunu
// söylemediği için burada adları da doğruluyoruz.
const REQUIRED_PROFILES = ['tls-server', 'tls-client', 'email', 'code-signing', 'tsa', 'ocsp-responder'];

class SslCompatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SslCompatError';
  }
}

function installedVersion() {
  try {
    // eslint-disable-next-line global-require, import/no-unresolved
    return require('@fitfak/ssl/package.json').version || null;
  } catch (_) {
    return null;
  }
}

/**
 * Kurulu @fitfak/ssl'in bu kod tabanının beklediği şey olup olmadığı.
 *
 * @param {object} [ssl]  enjekte edilebilir (testler için)
 * @returns {{ version, profiles, keyMatch }}
 */
function assertSslCompatible(ssl = null) {
  // eslint-disable-next-line global-require, import/no-unresolved
  const lib = ssl || require('@fitfak/ssl');
  const version = installedVersion();

  // ---- 1. sürüm --------------------------------------------------------------------------
  if (version) {
    const major = Number(String(version).split('.')[0]);
    if (Number.isFinite(major) && major < MIN_MAJOR) {
      throw new SslCompatError(
        `@fitfak/ssl ${version} kurulu, ama bu kod ${MIN_MAJOR}.x bekliyor.\n\n`
        + '  Eski sürüm sessizce yanlış çalışır: CSR\'den üretilen sertifikanın içindeki açık\n'
        + '  anahtar istekteki özel anahtara ait olmaz. Sertifika geçerli görünür, zinciri\n'
        + '  doğrulanır, ve yalnızca bir TLS el sıkışmasında "key values mismatch" olarak\n'
        + '  patlar -- yani onu üreten koddan bir ağ hattı ötede.\n\n'
        + '  Çözüm:  npm install @fitfak/ssl@^2.1.0\n'
        + '          (kaynak: https://github.com/aybarsyldrm/ssl)',
      );
    }
  }

  // ---- 2. profil adları ---------------------------------------------------------------------
  const profiles = typeof lib.listProfiles === 'function' ? lib.listProfiles() : [];
  const missing = REQUIRED_PROFILES.filter((name) => !profiles.includes(name));
  if (profiles.length && missing.length) {
    throw new SslCompatError(
      `@fitfak/ssl şu profilleri tanımıyor: ${missing.join(', ')}.\n`
      + `  Tanıdıkları: ${profiles.join(', ')}\n\n`
      + '  Profil adları 2.x ile değişti (server-auth -> tls-server, client-auth -> tls-client).\n'
      + '  core/certificate-profiles.js bunları eşliyor; bu hata eşlemenin kütüphaneden\n'
      + '  ayrıştığını söyler.',
    );
  }

  // ---- 3. davranış: üretilen sertifika, isteğin anahtarına mı ait ----------------------------
  //
  // Asıl kontrol bu. Sürüm numarası bir vaat, bu bir ölçüm.
  const keyMatch = verifyCsrKeyBinding(lib);
  if (!keyMatch) {
    throw new SslCompatError(
      '@fitfak/ssl bir CSR\'den, isteğin özel anahtarına AİT OLMAYAN bir sertifika üretti.\n\n'
      + '  Bu kurulumla üretilen her sertifika, kullanılmaya çalışıldığında bir TLS\n'
      + '  el sıkışmasında başarısız olacak. Sürüm kontrolünü geçtiğine göre sorun sürüm\n'
      + '  numarasında değil paketin kendisinde: kurulumu doğrulayın.\n\n'
      + `  Kurulu sürüm: ${version || 'bilinmiyor'}`,
    );
  }

  return { version, profiles, keyMatch };
}

/**
 * Bir anahtar çifti üretir, ondan bir CSR kurar, imzalar ve çıkan sertifikanın BAŞLADIĞIMIZ
 * özel anahtara ait olduğunu doğrular.
 *
 * `checkPrivateKey` Node'un kendi kontrolü: sertifikanın açık anahtarı ile verilen özel
 * anahtarın eşleşip eşleşmediğini söyler. Kendi ürettiğimiz baytları yine kendi kodumuzla
 * karşılaştırmak bir şey kanıtlamazdı -- ikisinde de aynı yanlış anlaşılma olabilir.
 */
function verifyCsrKeyBinding(lib) {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = privateKey.export({ format: 'jwk' });

    const keyInfo = {
      keyType: 'ec',
      curveName: 'P-256',
      // HAM nokta (0x04 || X || Y), SPKI DER değil: kütüphane SPKI'yi kendisi kurar ve SPKI
      // geçirmek içine ikinci bir SPKI gömülü bozuk bir yapı üretir.
      publicKeyBuf: Buffer.concat([
        Buffer.from([0x04]),
        Buffer.from(jwk.x, 'base64url'),
        Buffer.from(jwk.y, 'base64url'),
      ]),
      privateKey: BigInt(`0x${Buffer.from(jwk.d, 'base64url').toString('hex')}`),
    };

    const csrPem = lib.generateCSR(keyInfo, [[lib.oid.OIDs.commonName, 'ssl-compat-check']], []);
    const ca = lib.generateEcRootCA({ commonName: 'ssl-compat-check-ca' });
    const issued = lib.issueCertificateFromCSR(csrPem, ca, { profile: 'tls-client', validityDays: 1 });

    const certificate = new crypto.X509Certificate(issued.pem);
    // İki yönlü: sertifika özel anahtarımıza mı ait, ve açık anahtarı bizimkiyle aynı mı.
    // İlki Node'un kontrolü, ikincisi baytların gerçekten taşındığını gösterir.
    return certificate.checkPrivateKey(privateKey)
      && certificate.publicKey.export({ type: 'spki', format: 'pem' }).trim()
        === publicKey.export({ type: 'spki', format: 'pem' }).trim();
  } catch (err) {
    throw new SslCompatError(
      `@fitfak/ssl ile bir sertifika üretilemedi: ${err.message}\n\n`
      + '  Bu, kurulu sürümün bu kod tabanının beklediği arayüze sahip olmadığını gösterir.\n'
      + '  Beklenen: @fitfak/ssl@^2.1.0 (https://github.com/aybarsyldrm/ssl)',
    );
  }
}

module.exports = { assertSslCompatible, verifyCsrKeyBinding, SslCompatError, MIN_MAJOR };
