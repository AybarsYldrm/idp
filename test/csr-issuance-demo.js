'use strict';

const crypto = require('node:crypto');

const ssl = require('@fitfak/ssl');
const { ProductionPkiIssuer, skidOfCsr } = require('../core/pki-issuer');
const certificateService = require('../services/certificate-service');
const { createMockDb } = require('./mock-db');

// GÖNDERİLEN CSR'DEN GERÇEKTEN KULLANILABİLİR BİR SERTİFİKA ÇIKIYOR MU.
//
// Bu dosya, test/pki-acme-demo.js'in ATLANAN bölümünün DNS'e bağlı olmayan karşılığı. O bölüm
// `acme-test.fitfak.net`in 127.0.0.1'e çözümlenmesini istiyor ve çözümlenmediğinde -- yani
// çoğu makinede ve çoğu CI'da -- sessizce atlanıyordu. Sertifika ÜRETEN tek uçtan uca yol
// oradaydı, dolayısıyla iki ayrı hata hiçbir testte görünmedi:
//
//   1. `checkKeyUniqueness` geçiren her istek 400 ile düşüyordu. Aday SKID şöyle
//      hesaplanıyordu:
//
//          skidOfPublicKeyPem(csr.publicKeyPem || ssl.parseCSR(csrPem).publicKeyPem)
//
//      `parseCSR` `publicKeyPem` diye bir alan DÖNDÜRMÜYOR. İkinci ayrıştırma da aynı
//      `undefined`'ı veriyor ve sonuç "CSR'nin açık anahtarı okunamadı" oluyordu. Bu geri
//      dönüşü yalnızca ACME kullanıyor, yani GEÇERLİ bir CSR ile yapılan her ACME talebi,
//      CSR'nin okunamadığını söyleyen bir hatayla reddediliyordu.
//
//   2. Üretilen TLS sunucu sertifikasında hiç dNSName SAN olmuyordu. Doğrulanmış alan adı
//      CN'e yazılıyordu ve RFC 6125 §6.4.4'ten beri hiçbir modern istemci CN'e bakmıyor --
//      yani sertifika üretiliyor, indiriliyor, zinciri doğrulanıyor ve ilk TLS el sıkışmasında
//      reddediliyordu. Onu üreten koddan bir ağ hattı ötede.
//
// İkisinin ortak yanı: hata sertifikayı ÜRETEN tarafta görünmüyor. O yüzden buradaki
// kontroller "200 döndü mü" değil, "çıkan sertifika işe yarar mı" diye soruyor.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

function makeCsr(cn, { curve = 'P-256' } = {}) {
  const key = ssl.generateEcKeyPair(curve);
  const csrPem = ssl.generateCSR(
    { keyType: 'ec', curveName: key.curve, ...key },
    [[ssl.oid.OIDs.commonName, cn]],
    // CSR'nin KENDİ SAN'ı bilerek taşınmıyor (başvuran kendi alan adını yazdıramamalı).
    // Buraya yine de koyuyoruz: taşınmadığını da doğrulamak istiyoruz.
    [{ type: 'dns', value: 'saldirgan.example.com' }],
  );
  return { csrPem, key };
}

async function main() {
  const db = createMockDb(['certificates', 'secrets', 'users']);
  const issuer = await ProductionPkiIssuer.open({ db, logger: null });

  console.log('\n1. Anahtar tekilliği kontrolü GEÇERLİ bir CSR\'yi reddetmiyor');

  {
    const { csrPem } = makeCsr('api.fitfak.net');
    const seen = [];
    const issued = await issuer.signCertificateFromCsr({
      csrPem,
      profile: 'server-auth',
      subjectOverride: { cn: 'api.fitfak.net', sans: [{ type: 'dns', value: 'api.fitfak.net' }] },
      checkKeyUniqueness: async (skidHex) => { seen.push(skidHex); return false; },
    });
    check('sertifika üretildi', !!issued.serialNumberHex);
    check('tekillik kontrolü çağrıldı', seen.length === 1);

    // ASIL KONTROL. Kontrolün baktığı SKID ile sertifikaya YAZILAN SKID aynı olmalı: ayrışsalar
    // kontrol hiçbir zaman bir eşleşme bulamaz ve "bu anahtar için zaten sertifika var" hâli
    // sessizce hiç oluşmaz -- yani koruma, var gibi görünüp çalışmaz.
    check('kontrol edilen SKID, sertifikaya yazılanla aynı', seen[0] === issued.skidHex);

    // Ve o değer sertifikanın BAYTLARINDA gerçekten duruyor: iki hesabı birbiriyle
    // karşılaştırmak, ikisinde de aynı yanlış anlaşılma varsa bir şey kanıtlamaz.
    const certificate = new crypto.X509Certificate(issued.leafPem);
    check('SKID sertifikanın baytlarında var',
      Buffer.from(certificate.raw).toString('hex').includes(issued.skidHex));
  }

  console.log('\n2. Tekrar kullanılan anahtar reddediliyor');

  {
    const { csrPem } = makeCsr('tekil.fitfak.net');
    const opts = {
      csrPem,
      profile: 'server-auth',
      subjectOverride: { cn: 'tekil.fitfak.net', sans: [{ type: 'dns', value: 'tekil.fitfak.net' }] },
    };
    const first = await issuer.signCertificateFromCsr({ ...opts, checkKeyUniqueness: async () => false });
    check('ilk istek geçiyor', !!first.serialNumberHex);

    let refused = null;
    try {
      await issuer.signCertificateFromCsr({ ...opts, checkKeyUniqueness: async () => true });
    } catch (err) { refused = err; }
    check('aynı anahtarla ikinci istek 409 ile reddediliyor',
      refused && refused.code === 'key_already_certified' && refused.httpStatus === 409);
  }

  console.log('\n3. Üretilen TLS sunucu sertifikası GERÇEKTEN kullanılabilir');

  {
    const { csrPem } = makeCsr('www.fitfak.net');
    const issued = await issuer.signCertificateFromCsr({
      csrPem,
      profile: 'server-auth',
      subjectOverride: {
        cn: 'www.fitfak.net',
        sans: [{ type: 'dns', value: 'www.fitfak.net' }, { type: 'dns', value: 'fitfak.net' }],
      },
    });
    const certificate = new crypto.X509Certificate(issued.leafPem);
    const san = certificate.subjectAltName || '';

    check('dNSName SAN var', san.includes('DNS:www.fitfak.net'));
    check('siparişteki İKİNCİ ad da taşınıyor', san.includes('DNS:fitfak.net'));
    // Node'un kendi ad eşleştirmesi: sertifikanın o adı GERÇEKTEN kapsayıp kapsamadığına
    // bizim SAN dizesini okumamız değil, doğrulayıcı karar verir.
    check('Node sertifikayı bu ad için geçerli sayıyor',
      certificate.checkHost('www.fitfak.net') === 'www.fitfak.net');
    check('ikinci ad için de', certificate.checkHost('fitfak.net') === 'fitfak.net');
    check('kapsamadığı bir ad için saymıyor', !certificate.checkHost('baska.example.com'));

    // CSR'nin KENDİ SAN'ı taşınmamalı: taşınsaydı başvuran, kendi seçtiği alan adını
    // sertifikaya yazdırabilirdi.
    check("CSR'deki uydurma SAN taşınmadı", !san.includes('saldirgan.example.com'));
  }

  console.log('\n4. Sunucu adı olmayan bir istek üretilmeden reddediliyor');

  {
    const { csrPem } = makeCsr('alice');
    let refused = null;
    try {
      await issuer.signCertificateFromCsr({
        csrPem, profile: 'server-auth', subjectOverride: { cn: 'alice' },
      });
    } catch (err) { refused = err; }
    check('SAN\'sız server-auth reddediliyor', refused && refused.code === 'server_san_required');
    check('ve 400 ile, yani isteği düzeltilebilir olarak', refused.httpStatus === 400);
    // CN'den TÜRETİLMİYOR: türetme olsaydı `DNS:alice` diye bir SAN üretilirdi ve ortaya
    // geçerli görünen, hiçbir sunucuyu adlandırmayan bir sertifika çıkardı.
    check('CN\'den bir alan adı uydurulmuyor', /SAN|dNSName|sunucu adı/i.test(refused.message));
  }

  console.log('\n5. certificate-service, sunucu sertifikasını kullanıcı adıyla adlandırmıyor');

  {
    const users = db.collection('users');
    const userId = await users.insert({
      username: 'alice', email: 'alice@fitfak.net', role: 'admin',
      certProfiles: JSON.stringify(['server-auth']), createdAt: BigInt(Date.now()),
    });

    // Eskiden bu istek geçiyor ve CN'i "alice", tek SAN'ı `rfc822Name:alice@fitfak.net` olan
    // bir TLS SUNUCU sertifikası üretiyordu -- istemci CSR'sinde hangi alan adını yazarsa
    // yazsın. Artık hangi adı kapsayacağı AÇIKÇA isteniyor.
    let refused = null;
    try {
      await certificateService.requestCertificate({
        db, pkiIssuer: issuer, userId, csrPem: makeCsr('herhangi').csrPem, profile: 'server-auth',
      });
    } catch (err) { refused = err; }
    check('dnsNames olmadan server-auth reddediliyor',
      refused && refused.code === 'server_name_required');

    const ok = await certificateService.requestCertificate({
      db,
      pkiIssuer: issuer,
      userId,
      csrPem: makeCsr('herhangi').csrPem,
      profile: 'server-auth',
      dnsNames: ['ops.fitfak.net'],
    });
    const certificate = new crypto.X509Certificate(ok.certPem.split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----\n');
    check('istenen ad SAN\'da', (certificate.subjectAltName || '').includes('DNS:ops.fitfak.net'));
    check('CN kullanıcı adı DEĞİL, sunucu adı', /CN=ops\.fitfak\.net/.test(certificate.subject.replace(/\s*=\s*/g, '=')));
    check('Node bu ad için geçerli sayıyor', certificate.checkHost('ops.fitfak.net') === 'ops.fitfak.net');

    // İstemci sertifikaları etkilenmiyor: kimlik orada gerçekten hesabın kendisi.
    const client = await certificateService.requestCertificate({
      db, pkiIssuer: issuer, userId, csrPem: makeCsr('alice').csrPem, profile: 'client-auth',
    });
    const clientCert = new crypto.X509Certificate(client.certPem.split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----\n');
    check('client-auth hâlâ hesabın adını taşıyor', /CN=alice/.test(clientCert.subject.replace(/\s*=\s*/g, '=')));
    check('ve e-postasını SAN\'da', (clientCert.subjectAltName || '').includes('alice@fitfak.net'));
  }

  console.log('\n6. skidOfCsr, kütüphanenin sertifikaya yazdığı değeri veriyor');

  {
    // Ayrı ayrı sınanıyor, çünkü bu fonksiyonun YANLIŞ olması hiçbir yerde hata vermez:
    // yalnızca tekillik kaydının hiçbir zaman eşleşmemesine yol açar.
    for (const curve of ['P-256', 'P-384']) {
      const { csrPem } = makeCsr(`egri-${curve}.fitfak.net`, { curve });
      const csr = ssl.parseCSR(csrPem);
      const issued = await issuer.signCertificateFromCsr({
        csrPem,
        profile: 'server-auth',
        subjectOverride: {
          cn: `egri-${curve}.fitfak.net`,
          sans: [{ type: 'dns', value: `egri-${curve.toLowerCase()}.fitfak.net` }],
        },
      });
      check(`${curve}: skidOfCsr == sertifikadaki SKID`,
        skidOfCsr(csr).toString('hex') === issued.skidHex);
    }
  }

  console.log(`\nOK - CSR'den sertifika üretimi: ${checks} kontrol geçti.`);
}

main().catch((e) => { console.error('\nFAILED:', e.message); process.exit(1); });
