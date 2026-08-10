'use strict';

const http = require('node:http');

const pkiUrls = require('../core/pki-urls');
const { createStatusHandler } = require('../services/status-server');
const crlService = require('../services/crl-service');
const { createMockDb } = require('./mock-db');

// Bir sertifikanın İÇİNE yazılan adreslerin gerçekten cevap vermesi.
//
// Bu, üretimde aylarca fark edilmeden durabilecek bir hata sınıfı. Bir uç sertifika iki adres
// taşır -- AIA caIssuers ("beni imzalayan CA'nın sertifikası burada") ve CRL dağıtım noktası
// ("iptal listem burada") -- ve ikisi de yanlış olduğunda ortaya çıkan belirti YOKLUKTUR:
//
//   * AIA yanlışsa, zinciri tam gönderen sunucularda hiçbir şey olmaz. Yalnızca zinciri eksik
//     gönderen bir eşle konuşulduğunda "unable to get local issuer certificate" çıkar.
//   * CRL yanlışsa, sorgu 404 alır ya da BAŞKA bir yayıncının listesini alır. İkisinde de
//     doğrulayıcı "iptal edilmemiş" sonucuna varır -- yani iptal sessizce etkisiz kalır.
//
// Beş ara CA var (her amaç için ayrı) ve düzeltmeden önce hepsi TEK bir /intermediate.crt ile
// TEK bir /crl adresini gömüyordu. Yani beşten dördü için ikisi de yanlıştı.
//
// Burada @fitfak/ssl YOK. Kasıtlı: sınanan şey imzalama değil, ADRESLERİN TUTARLILIĞI -- ve o,
// imzalama katmanı kurulu olmayan bir makinede de sınanabilmeli. Gerçek imzalarla yapılan
// doğrulama test/revocation-chain-demo.js'de, openssl ile.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

const AUTHORITIES = ['workload-ca', 'client-ca', 'server-ca', 'email-ca', 'signing-ca'];

/**
 * Kasa yerine bir sözlük, imzalayıcı yerine bir kayıt defteri.
 *
 * `signCrl`'in NE İSTENDİĞİNİ kaydetmesi buradaki asıl mesele: doğru listenin döndüğünü
 * görmek yetmez, o listenin DOĞRU ANAHTARLA imzalanmış olması gerekir. İmzalayanı kaydetmeyen
 * bir sahte, hepsini kökle imzalayan bir uygulamayı da geçirirdi.
 */
function fakeIssuer() {
  const signed = [];
  return {
    signed,
    subCA: { name: 'client-ca', certPem: '-----BEGIN CERTIFICATE-----\nclient-ca\n-----END CERTIFICATE-----\n', skid: 'aabb' },
    rootCA: { name: 'root', certPem: '-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n' },
    async getAuthorityCertPem(name) {
      if (name === 'root') return this.rootCA.certPem;
      return AUTHORITIES.includes(name)
        ? `-----BEGIN CERTIFICATE-----\n${name}\n-----END CERTIFICATE-----\n`
        : null;
    },
    async listIssuingAuthorityNames() { return AUTHORITIES.slice(); },
    async getChainPem() { return this.subCA.certPem + this.rootCA.certPem; },
    async signCrl({ revokedCerts, scope, authority }) {
      signed.push({ scope, authority, serials: revokedCerts.map((c) => c.serialNumberHex) });
      return Buffer.from(JSON.stringify({ authority, serials: revokedCerts.map((c) => c.serialNumberHex) }));
    },
  };
}

function get(port, pathname) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: pathname }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks),
      }));
    }).on('error', reject);
  });
}

function memoryCache() {
  const m = new Map();
  return {
    async get(k) { return m.get(k) || null; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
    get size() { return m.size; },
  };
}

async function main() {
  console.log('\n1. Gömülen adres ile sunulan yol AYNI dosyadan geliyor');

  {
    for (const name of AUTHORITIES) {
      const embedded = pkiUrls.caIssuersUrlFor(name);
      const parsed = pkiUrls.parseCaPath(new URL(embedded).pathname);
      check(`${name}: AIA adresi kendi yoluna çözülüyor`, parsed && parsed.authority === name);

      const crlEmbedded = pkiUrls.crlUrlFor(name);
      const crlParsed = pkiUrls.parseCrlPath(new URL(crlEmbedded).pathname);
      check(`${name}: CRL adresi kendi yoluna çözülüyor`, crlParsed && crlParsed.authority === name);
    }
    // İki otoritenin aynı adrese düşmesi, tam olarak düzeltilen hatanın geri gelmesi olurdu.
    const urls = new Set(AUTHORITIES.map((n) => pkiUrls.crlUrlFor(n)));
    check('her otoritenin adresi farklı', urls.size === AUTHORITIES.length);
  }

  console.log('\n2. Yol çözümü, otorite adına benzemeyen hiçbir şeyi kabul etmiyor');

  {
    for (const bad of ['/crl/../root', '/crl/..%2Froot', '/crl/a/b', '/crl/', '/crl/UPPER', '/crl/x'.repeat(40)]) {
      check(`reddedildi: ${bad}`, pkiUrls.parseCrlPath(bad) === null);
    }
    for (const bad of ['/ca/../root.crt', '/ca/.crt', '/ca/a/b.crt', '/ca/x.pem']) {
      check(`reddedildi: ${bad}`, pkiUrls.parseCaPath(bad) === null);
    }
    check('kök listesi kendi kapsamına çözülüyor',
      pkiUrls.parseCrlPath('/crl/root').scope === 'root');
  }

  console.log('\n3. Durum sunucusu her otoritenin sertifikasını KENDİ adresinden veriyor');

  const db = createMockDb(['certificates']);
  const issuer = fakeIssuer();
  const cacheStore = memoryCache();
  const server = http.createServer(createStatusHandler({ db, pkiIssuer: issuer, cacheStore }));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  {
    for (const name of AUTHORITIES) {
      const path = new URL(pkiUrls.caIssuersUrlFor(name)).pathname;
      const res = await get(port, path);
      check(`${name}: AIA adresi 200 dönüyor`, res.status === 200);
      // Asıl kontrol: DOĞRU sertifika mı. Beş adresin de aynı sertifikayı döndürmesi,
      // düzeltmeden önceki davranıştı ve zinciri kurulamaz kılıyordu.
      check(`${name}: ve kendi sertifikasını döndürüyor`, res.body.toString().includes(name));
      check(`${name}: pkix-cert olarak`, res.headers['content-type'] === 'application/pkix-cert');
    }

    const unknown = await get(port, '/ca/hayali-ca.crt');
    check('bilinmeyen otorite 404', unknown.status === 404);

    const legacy = await get(port, '/intermediate.crt');
    // Düzeltmeden önce üretilmiş sertifikalar bu adresi taşıyor ve süreleri dolana kadar
    // dolaşımda kalacaklar. Kaldırmak, onların zincir tamamlamasını bugün kırardı.
    check('eski adres hâlâ cevap veriyor', legacy.status === 200);
  }

  console.log('\n4. Her liste YALNIZCA kendi yayıncısının iptallerini taşıyor');

  {
    const certs = db.collection('certificates');
    const rows = [
      { serialNumberHex: 'aa01', issuerName: 'workload-ca', status: 'revoked' },
      { serialNumberHex: 'aa02', issuerName: 'workload-ca', status: 'revoked' },
      { serialNumberHex: 'bb01', issuerName: 'email-ca', status: 'revoked' },
      { serialNumberHex: 'cc01', issuerName: 'server-ca', status: 'valid' },
    ];
    for (const row of rows) {
      await certs.insert({
        profile: 'client-auth', skidHex: `sk-${row.serialNumberHex}`,
        revokedAt: BigInt(Date.now()), revocationReason: 'keyCompromise', ...row,
      });
    }

    const workload = JSON.parse((await get(port, new URL(pkiUrls.crlUrlFor('workload-ca')).pathname)).body.toString());
    check('iş yükü listesi kendi iki iptalini taşıyor',
      workload.serials.length === 2 && workload.serials.includes('aa01') && workload.serials.includes('aa02'));
    check('ve BAŞKA yayıncının iptalini taşımıyor', !workload.serials.includes('bb01'));

    const email = JSON.parse((await get(port, new URL(pkiUrls.crlUrlFor('email-ca')).pathname)).body.toString());
    check('e-posta listesi yalnızca kendininkini taşıyor',
      email.serials.length === 1 && email.serials[0] === 'bb01');

    const serverCa = JSON.parse((await get(port, new URL(pkiUrls.crlUrlFor('server-ca')).pathname)).body.toString());
    check('iptal edilmemiş sertifika hiçbir listede yok', serverCa.serials.length === 0);

    // Ve her liste KENDİ yayıncısı tarafından imzalanmış olmalı. Hepsini tek bir anahtarla
    // imzalamak, RFC 5280 §6.3.3 gereği doğrulayıcıların yok saydığı listeler üretir.
    const signers = issuer.signed.filter((s) => s.scope === 'leaf').map((s) => s.authority);
    check('iş yükü listesini iş yükü CA imzaladı', signers.includes('workload-ca'));
    check('e-posta listesini e-posta CA imzaladı', signers.includes('email-ca'));
    check('hiçbir uç listesi kökle imzalanmadı', !signers.includes('root'));
  }

  console.log('\n5. Önbellek yayıncılar arasında karışmıyor');

  {
    // Ortak bir önbellek anahtarı, bir yayıncının listesini diğerine servis etmek demektir --
    // yani düzeltilen hatanın önbellek üzerinden geri gelmesi.
    check('anahtarlar yayıncıya göre ayrı',
      crlService.cacheKeyFor('workload-ca') !== crlService.cacheKeyFor('email-ca'));

    const before = issuer.signed.length;
    await get(port, new URL(pkiUrls.crlUrlFor('workload-ca')).pathname);
    check('ikinci istek önbellekten geldi, yeniden imzalanmadı', issuer.signed.length === before);

    await crlService.invalidateCrlCache(cacheStore, { authorities: AUTHORITIES });
    await get(port, new URL(pkiUrls.crlUrlFor('workload-ca')).pathname);
    check('temizlemeden sonra yeniden imzalandı', issuer.signed.length > before);

    // Bir iptal sonrası YALNIZCA bir listeyi temizlemek, diğerlerinde iptalin beş dakika daha
    // görünmemesi demektir -- yani temizlemeyi hiç yapmamakla aynı sonuç.
    await get(port, new URL(pkiUrls.crlUrlFor('email-ca')).pathname);
    const cached = issuer.signed.length;
    await crlService.invalidateCrlCache(cacheStore, { authorities: AUTHORITIES });
    await get(port, new URL(pkiUrls.crlUrlFor('email-ca')).pathname);
    check('temizleme her yayıncıyı kapsıyor', issuer.signed.length > cached);
  }

  console.log('\n6. Kök listesi ayrı ve kökle imzalanıyor');

  {
    const certs = db.collection('certificates');
    await certs.insert({
      serialNumberHex: 'dd01', issuerName: 'root', profile: 'intermediate-ca',
      skidHex: 'sk-dd01', status: 'revoked',
      revokedAt: BigInt(Date.now()), revocationReason: 'cessationOfOperation',
    });

    const root = JSON.parse((await get(port, '/crl/root')).body.toString());
    check('kök listesi ara CA iptalini taşıyor', root.serials.includes('dd01'));

    await crlService.invalidateCrlCache(cacheStore, { authorities: AUTHORITIES });
    const workload = JSON.parse((await get(port, new URL(pkiUrls.crlUrlFor('workload-ca')).pathname)).body.toString());
    // Ara CA iptali uç listesine düşseydi, uç listesi kendi yayıncısının vermediği bir seriden
    // bahsediyor olurdu -- doğrulayıcı için anlamsız bir kayıt.
    check('ve uç listesine düşmüyor', !workload.serials.includes('dd01'));
    check('kök listesini kök imzaladı',
      issuer.signed.some((s) => s.scope === 'root' && s.authority === 'root'));
  }

  console.log('\n7. Alanı olmayan eski kayıtlar kaybolmuyor');

  {
    const certs = db.collection('certificates');
    // `issuerName` bu düzeltmeyle geldi. Ondan önce yazılmış iptal kayıtlarında alan boş ve
    // onları düşürmek, alanın eklendiği güne kadar üretilmiş her iptali sessizce geçersiz
    // kılardı. O kayıtlar tek bir ara CA varken üretildi, yani varsayılana koymak doğru.
    await certs.insert({
      serialNumberHex: 'ee01', issuerName: '', profile: 'client-auth', skidHex: 'sk-ee01',
      status: 'revoked', revokedAt: BigInt(Date.now()), revocationReason: 'superseded',
    });

    await crlService.invalidateCrlCache(cacheStore, { authorities: AUTHORITIES });
    const defaultList = JSON.parse((await get(port, '/crl')).body.toString());
    check('alansız kayıt varsayılan yayıncının listesinde', defaultList.serials.includes('ee01'));
    check('ve o liste varsayılan yayıncı tarafından imzalanıyor',
      issuer.signed.at(-1).authority === issuer.subCA.name);
  }

  await new Promise((r) => server.close(r));
  console.log(`\nOK - dağıtım noktaları: ${checks} kontrol geçti.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message, err.stack); process.exit(1); },
);
