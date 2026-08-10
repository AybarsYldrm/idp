'use strict';

const crypto = require('node:crypto');

const { assertSslCompatible, verifyCsrKeyBinding, SslCompatError } = require('../core/ssl-compat');

// ÜRETİLEN SERTİFİKA, İSTEĞİN ÖZEL ANAHTARINA AİT Mİ.
//
// Bu testin var olma sebebi somut bir olay. package.json `@fitfak/ssl: ^1.0.2` diyordu ve
// kütüphanenin 2.x'i yayınlandığında o aralık onu HİÇBİR ZAMAN kurmadı -- semver'e göre doğru
// davranış, ve tam olarak istenmeyen şey. Kurulum eski sürümde kaldı, sertifikalar üretilmeye
// devam etti, ve içlerindeki açık anahtar CSR'nin özel anahtarına ait değildi.
//
// NEDEN HİÇBİR TEST BUNU YAKALAMADI
//
// Çünkü hiçbir test sertifikanın İÇİNDEKİ ANAHTARA bakmıyordu. Kontroller şunlardı: PEM
// ayrıştırılıyor mu, subject doğru mu, SAN'da SPIFFE kimliği var mı, tarihler tutuyor mu,
// zincir doğrulanıyor mu. Hepsi geçiyordu. Yanlış olan tek alan hiç okunmuyordu.
//
// Hatanın kendini gösterdiği yer sertifikayı üretenden bir ağ hattı ötesi: bir TLS el
// sıkışmasında, "key values mismatch" ya da hiçbir şey söylemeyen bir handshake failure olarak.
// Yani teşhis, üretim kodunda değil, ilgisiz bir servisin bağlantı hatasında başlıyor.
//
// Buradaki kontroller iki katman:
//
//   1. `checkPrivateKey` -- Node'un kendi kontrolü. Kendi ürettiğimiz baytları yine kendi
//      kodumuzla karşılaştırmak bir şey kanıtlamaz: ikisinde de aynı yanlış anlaşılma olabilir.
//   2. Açık anahtarın BAYT BAYT aynı olması -- baytların gerçekten taşındığını gösterir.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

let ssl;
try {
  ssl = require('@fitfak/ssl');
} catch (_) {
  console.log('SKIP - @fitfak/ssl kurulu degil');
  process.exit(0);
}

function main() {
  console.log('\n1. Kurulu sürüm bu kod tabanının beklediği şey');

  {
    const result = assertSslCompatible();
    check('sürüm 2.x', Number(String(result.version).split('.')[0]) >= 2);
    check('anahtar bağlama doğrulandı', result.keyMatch === true);

    // Profil adları 2.x ile değişti (server-auth -> tls-server). Eşleme
    // core/certificate-profiles.js'de; bu kontrol onun kütüphaneden ayrışmadığını söyler.
    for (const name of ['tls-server', 'tls-client', 'email', 'code-signing', 'tsa', 'ocsp-responder']) {
      check(`profil tanınıyor: ${name}`, result.profiles.includes(name));
    }
  }

  console.log('\n2. Doğrudan ölçüm: CSR -> sertifika -> özel anahtar');

  {
    check('kütüphane isteğin anahtarına ait bir sertifika üretiyor', verifyCsrKeyBinding(ssl) === true);
  }

  console.log('\n3. Her profil için, üretilen sertifika kendi anahtarına ait');

  {
    // Tek bir profille sınamak yetmezdi: profil, uzantıları ve kullanımı değiştirir ve
    // bunlardan biri açık anahtarın taşınma yolunu etkileseydi yalnızca o profil bozuk olurdu --
    // yani sistemin bir köşesi.
    const ca = ssl.generateEcRootCA({ commonName: 'FITFAK Test Root' });

    for (const profile of ['tls-server', 'tls-client', 'email', 'code-signing']) {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const jwk = privateKey.export({ format: 'jwk' });
      const csrPem = ssl.generateCSR({
        keyType: 'ec',
        curveName: 'P-256',
        publicKeyBuf: Buffer.concat([
          Buffer.from([0x04]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url'),
        ]),
        privateKey: BigInt(`0x${Buffer.from(jwk.d, 'base64url').toString('hex')}`),
      }, [[ssl.oid.OIDs.commonName, `${profile}.fitfak.net`]], []);

      const issued = ssl.issueCertificateFromCSR(csrPem, ca, { profile, validityDays: 1 });
      const certificate = new crypto.X509Certificate(issued.pem);

      check(`${profile}: sertifika özel anahtara ait`, certificate.checkPrivateKey(privateKey));
      check(`${profile}: açık anahtar bayt bayt aynı`,
        certificate.publicKey.export({ type: 'spki', format: 'pem' }).trim()
          === publicKey.export({ type: 'spki', format: 'pem' }).trim());
    }
  }

  console.log('\n4. BAŞKA bir anahtarın CSR\'si başka bir sertifika üretir');

  {
    // Kontrolün gerçekten bir şey ölçtüğünün kanıtı: her zaman true dönen bir `checkPrivateKey`
    // yukarıdaki tüm kontrolleri de geçirirdi.
    const ca = ssl.generateEcRootCA({ commonName: 'FITFAK Test Root 2' });
    const mine = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const someoneElse = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

    const jwk = mine.privateKey.export({ format: 'jwk' });
    const csrPem = ssl.generateCSR({
      keyType: 'ec',
      curveName: 'P-256',
      publicKeyBuf: Buffer.concat([
        Buffer.from([0x04]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url'),
      ]),
      privateKey: BigInt(`0x${Buffer.from(jwk.d, 'base64url').toString('hex')}`),
    }, [[ssl.oid.OIDs.commonName, 'mine.fitfak.net']], []);

    const issued = ssl.issueCertificateFromCSR(csrPem, ca, { profile: 'tls-client', validityDays: 1 });
    const certificate = new crypto.X509Certificate(issued.pem);

    check('kendi anahtarımla eşleşiyor', certificate.checkPrivateKey(mine.privateKey));
    check('başkasının anahtarıyla EŞLEŞMİYOR', !certificate.checkPrivateKey(someoneElse.privateKey));
  }

  console.log('\n5. Uyumsuz bir kütüphane açılışta durduruluyor');

  {
    // Sürüm numarası bir vaat, davranış bir ölçüm -- ve ikisi de kontrol ediliyor. Yanlış
    // sertifika üreten bir kütüphane, sürümü doğru görünse bile geçmemeli.
    const brokenLib = {
      ...ssl,
      // CSR'nin anahtarını yok sayıp kendi ürettiğiyle imzalayan bir sürümün yaptığı şey.
      issueCertificateFromCSR(csrPem, ca, opts) {
        const other = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const jwk = other.privateKey.export({ format: 'jwk' });
        const otherCsr = ssl.generateCSR({
          keyType: 'ec',
          curveName: 'P-256',
          publicKeyBuf: Buffer.concat([
            Buffer.from([0x04]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url'),
          ]),
          privateKey: BigInt(`0x${Buffer.from(jwk.d, 'base64url').toString('hex')}`),
        }, [[ssl.oid.OIDs.commonName, 'baska']], []);
        return ssl.issueCertificateFromCSR(otherCsr, ca, opts);
      },
    };

    check('yanlış anahtarla üreten kütüphane reddediliyor', verifyCsrKeyBinding(brokenLib) === false);

    let threw = null;
    try { assertSslCompatible(brokenLib); } catch (err) { threw = err; }
    check('ve açılışta durduruluyor', threw instanceof SslCompatError);
    // Hata mesajı, teşhisin nereden başlaması gerektiğini söylemeli. "false döndü" demek,
    // aramaya yanlış yerden başlatır.
    check('mesaj ne olduğunu anlatıyor', /AİT OLMAYAN|TLS/.test(threw.message));
  }

  console.log('\n6. Eksik profil de yakalanıyor');

  {
    const oldNames = { ...ssl, listProfiles: () => ['server-auth', 'client-auth', 'smime'] };
    let threw = null;
    try { assertSslCompatible(oldNames); } catch (err) { threw = err; }
    check('eski profil adları reddediliyor', threw instanceof SslCompatError);
    check('ve hangilerinin eksik olduğu söyleniyor', /tls-server/.test(threw.message));
  }

  console.log(`\nOK - @fitfak/ssl uyumluluğu: ${checks} kontrol geçti.`);
}

main();
process.exit(0);
