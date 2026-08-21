'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { execFileSync } = require('node:child_process');

const ssl = require('@fitfak/ssl');
const pkiUrls = require('../core/pki-urls');
const { ProductionPkiIssuer } = require('../core/pki-issuer');
const { createStatusHandler } = require('../services/status-server');
const { createMockDb } = require('./mock-db');

// SERTİFİKANIN İÇİNDE YAZAN HER ADRES, ÜRETİMDEKİ BAĞLAMAYLA BİRLİKTE CEVAP VERİYOR MU.
//
// Bu test, aylarca fark edilmeden duran ve Windows'ta iki ayrı hata olarak görünen bir
// kusurdan sonra yazıldı:
//
//     "Incomplete certificate chain / Missing Issuer"
//     "CERT_E_REVOCATION_OFFLINE"
//
// İkisinin de sebebi aynıydı ve durum sunucusunda DEĞİLDİ. services/status-server.js
// `/ca/<otorite>.crt` ve `/crl/<otorite>` yollarını doğru karşılıyordu. Ama oauth-server.js
// onu şu elle yazılmış listenin arkasına bağlıyordu:
//
//     ['/ocsp', '/crl', '/crl/root', '/intermediate.crt', '/root.crt', '/chain.pem', '/']
//
// Listede o iki desen YOKTU. Yani her uç sertifikanın taşıdığı AIA caIssuers ve CRL dağıtım
// noktası adresi -- beş ara CA'nın hepsi için -- işleyiciye VARMADAN 404 alıyordu.
//
// VAR OLAN TESTLER BUNU GÖREMEZDİ, çünkü hepsi `createStatusHandler`'ı doğrudan bir
// http.createServer'a veriyor ve üretimdeki eşleştiriciyi hiç çalıştırmıyordu. Bu dosyanın
// tek varlık sebebi o boşluk: burada istek ÖNCE eşleştiriciden geçiyor.
//
// Adresler de bizim kurucularımızdan DEĞİL, imzalanmış sertifikanın BAYTLARINDAN okunuyor.
// `caIssuersUrlFor()` ile üretip yine onunla sormak, iki tarafın da aynı biçimde yanlış
// olabildiği dairesel bir kontrol olurdu. Sertifikanın içinde ne yazıyorsa doğrulayıcı onu
// isteyecek; sınanması gereken tam olarak o.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

function hasOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; }
  catch (_) { return false; }
}

/**
 * Sertifika baytlarındaki GeneralName URI'lerini toplar.
 *
 * DER'de `uniformResourceIdentifier` bağlam etiketi [6], ilkel: `0x86 <uzunluk> <baytlar>`.
 * Uzunluk okunuyor, çünkü DER dizeleri sonlandırıcı taşımaz -- düzenli ifadeyle taramak,
 * URI'nin hemen ardındaki DER etiketini adresin parçası sanmak demek. (Bu testin ilk hâli tam
 * olarak öyle yapıyordu ve `/crl/server-ca` yerine `/crl/server-ca0` soruyordu: sonraki bayt
 * 0x30, yani ASCII '0'.)
 *
 * Bizim URL kurucularımız KULLANILMIYOR ve bu kasıtlı: `caIssuersUrlFor()` ile üretip yine
 * onunla sormak, iki tarafın da aynı biçimde yanlış olabildiği dairesel bir kontrol olurdu.
 * Doğrulayıcı sertifikanın İÇİNDE ne yazıyorsa ona GET atacak.
 */
function embeddedUrls(der) {
  const found = new Set();
  for (let i = 0; i < der.length - 1; i += 1) {
    if (der[i] !== 0x86) continue;
    let length = der[i + 1];
    let start = i + 2;
    if (length === 0x81) { length = der[i + 2]; start = i + 3; }
    else if (length & 0x80) continue; // daha uzun biçim: bir URI için gerçekçi değil
    if (start + length > der.length) continue;
    const value = der.subarray(start, start + length).toString('latin1');
    if (/^https?:\/\/[\x21-\x7e]+$/.test(value)) found.add(value);
  }
  return [...found];
}

function request(port, pathname, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: pathname, method }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks),
      }));
    });
    req.on('error', reject);
    req.end();
  });
}

/**
 * ÜRETİMDEKİ bağlama. oauth-server.js bu iki satırı aynı şekilde kuruyor: eşleştirici
 * `pkiUrls.matchesStatusRequest`, işleyici `createStatusHandler`. Eşleştiriciyi geçemeyen
 * istek 404 alıyor -- tıpkı üretimde olduğu gibi.
 */
function mountLikeProduction(handler) {
  return http.createServer((req, res) => {
    if (!pkiUrls.matchesStatusRequest(req)) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found (bağlama eşleştiricisi geçirmedi)\n');
      return;
    }
    handler(req, res);
  });
}

async function issueLeaf(issuer, { cn, profile, sans = [], spiffeId = null }) {
  const key = ssl.generateEcKeyPair('P-256');
  const csr = ssl.generateCSR(
    { keyType: 'ec', curveName: key.curve, ...key },
    [[ssl.oid.OIDs.commonName, cn]], [],
  );
  return issuer.signCertificateFromCsr({
    csrPem: csr, profile, spiffeId, subjectOverride: { cn, sans },
  });
}

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fitfak-status-routing-'));
  const db = createMockDb(['certificates', 'secrets']);
  const issuer = await ProductionPkiIssuer.open({ db, logger: null });

  const cacheStore = {
    _m: new Map(),
    async get(k) { return this._m.get(k) || null; },
    async set(k, v) { this._m.set(k, v); },
    async delete(k) { this._m.delete(k); },
  };

  const server = mountLikeProduction(createStatusHandler({ db, pkiIssuer: issuer, cacheStore }));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  // Her AMACIN kendi ara CA'sı var ve her ara CA kendi adresini gömüyor. Beşini de üretmek
  // gerekiyor: hata, beşten dördünde görünüp birinde görünmeyen türdendi.
  console.log('\n1. Her profil için bir uç sertifika üretiliyor');
  const leaves = [
    await issueLeaf(issuer, { cn: 'session.fitfak.net', profile: 'server-auth', sans: [{ type: 'dns', value: 'session.fitfak.net' }] }),
    await issueLeaf(issuer, { cn: 'alice', profile: 'client-auth' }),
    await issueLeaf(issuer, { cn: 'smtp', profile: 'workload', spiffeId: 'spiffe://fitfak.net/workload/smtp/1' }),
    await issueLeaf(issuer, { cn: 'ops@fitfak.net', profile: 'smime' }),
    await issueLeaf(issuer, { cn: 'fitfak-release', profile: 'code-signing' }),
  ];
  for (const leaf of leaves) {
    check(`${leaf.profile}: ${leaf.issuerName} tarafından imzalandı`, !!leaf.issuerName);
  }

  // ---- 2. GÖMÜLÜ HER ADRES CEVAP VERİYOR MU -------------------------------------------------
  console.log('\n2. Sertifikaya GÖMÜLÜ her durum adresi, üretimdeki bağlamayla cevap veriyor');

  const seen = new Set();
  for (const leaf of leaves) {
    const der = pkiUrls.pemToDer(leaf.leafPem);
    const urls = embeddedUrls(der).filter((u) => u.startsWith(pkiUrls.STATUS_BASE));
    check(`${leaf.profile}: sertifika ${urls.length} durum adresi taşıyor`, urls.length >= 3);

    for (const url of urls) {
      const pathname = new URL(url).pathname;
      // ASIL KONTROL. Düzeltmeden önce `/ca/server-ca.crt` ve `/crl/server-ca` burada
      // düşüyordu ve istek işleyiciye hiç ulaşmıyordu.
      check(`${leaf.profile}: ${pathname} bağlama eşleştiricisini geçiyor`,
        pkiUrls.matchesStatusRequest({ url: pathname, method: 'GET' }));

      if (seen.has(pathname)) continue;
      seen.add(pathname);

      if (pathname === pkiUrls.OCSP_PATH) {
        // OCSP POST ister; GET'e 405 dönüyor. 404 dönseydi "adres yok" demek olurdu.
        const res = await request(port, pathname);
        check(`${pathname} GET -> 405 (POST bekliyor)`, res.status === 405);
        continue;
      }

      const res = await request(port, pathname);
      check(`${pathname} -> 200`, res.status === 200);

      if (pathname.startsWith('/ca/') || pathname === pkiUrls.ROOT_CERT_PATH) {
        check(`${pathname} content-type ${pkiUrls.CERT_CONTENT_TYPE}`,
          res.headers['content-type'] === pkiUrls.CERT_CONTENT_TYPE);
        // DER'in ilk baytı SEQUENCE (0x30). PEM olsaydı 0x2d ('-') olurdu ve Windows
        // CryptRetrieveObjectByUrl onu çözemezdi -- rota doğruyken bile aynı hata.
        check(`${pathname} DER veriyor (PEM zarfı yok)`, res.body[0] === 0x30);
      }
      if (pathname.startsWith('/crl/')) {
        check(`${pathname} content-type ${pkiUrls.CRL_CONTENT_TYPE}`,
          res.headers['content-type'] === pkiUrls.CRL_CONTENT_TYPE);
        check(`${pathname} DER CRL veriyor`, res.body[0] === 0x30);
      }
    }
  }

  // ---- 3. ARA CA'LARIN KENDİ ADRESLERİ ------------------------------------------------------
  //
  // Zincir uç sertifikada bitmiyor. Windows ara sertifikanın da iptal durumunu sorar ve
  // onun CDP'si `/crl/root`, AIA'sı `/root.crt` gösteriyor. İkisi de karşılanmalı.
  console.log('\n3. Ara CA sertifikalarının kendi adresleri de karşılanıyor');
  for (const name of await issuer.listIssuingAuthorityNames()) {
    const certPem = await issuer.getAuthorityCertPem(name);
    const urls = embeddedUrls(pkiUrls.pemToDer(certPem)).filter((u) => u.startsWith(pkiUrls.STATUS_BASE));
    for (const url of urls) {
      const pathname = new URL(url).pathname;
      check(`${name} -> ${pathname} eşleştiriciyi geçiyor`,
        pkiUrls.matchesStatusRequest({ url: pathname, method: 'GET' }));
      if (pathname === pkiUrls.OCSP_PATH) continue;
      const res = await request(port, pathname);
      check(`${name} -> ${pathname} 200 dönüyor`, res.status === 200);
    }
  }

  // ---- 4. HEAD ve eski adresler --------------------------------------------------------------
  console.log('\n4. HEAD ve eski adresler');
  const headCrl = await request(port, pkiUrls.ROOT_CRL_PATH, 'HEAD');
  check('HEAD /crl/root 200 dönüyor', headCrl.status === 200);
  check('HEAD gövde göndermiyor ama content-length bildiriyor',
    headCrl.body.length === 0 && Number(headCrl.headers['content-length']) > 0);

  for (const legacy of [pkiUrls.LEGACY_CA_PATH, pkiUrls.LEGACY_CRL_PATH]) {
    const res = await request(port, legacy);
    // Düzeltmeden ÖNCE üretilmiş sertifikalar bu adresleri taşıyor ve süreleri dolana kadar
    // dolaşımdalar. Kaldırmak, onların zincir tamamlamasını bugün kırardı.
    check(`eski adres ${legacy} hâlâ cevap veriyor`, res.status === 200);
  }

  // ---- 5. Tanınmayan yollar --------------------------------------------------------------
  console.log('\n5. Tanınmayan yollar durum işleyicisine hiç gitmiyor');
  for (const bogus of ['/ca/hayali-ca.crt', '/crl/hayali-ca', '/admin', '/ca/../secrets']) {
    const res = await request(port, bogus);
    check(`${bogus} -> 404`, res.status === 404);
  }
  // Bilinmeyen ama BİÇİMİ doğru bir otorite adı eşleştiriciyi geçer ve işleyici 404 döner:
  // eşleştiricinin kasadaki adları bilmesi, ona bir depo bağımlılığı vermek olurdu.
  check('biçimi doğru bilinmeyen otorite eşleştiriciyi geçiyor',
    pkiUrls.matchesStatusRequest({ url: '/ca/hayali-ca.crt', method: 'GET' }));

  // ---- 6. TLS SUNUCU SERTİFİKASI SAN TAŞIYOR -------------------------------------------------
  //
  // RFC 6125 §6.4.4'ten beri hiçbir modern istemci CN'e bakmaz. SAN'sız bir sunucu
  // sertifikası üretilebiliyorsa, o sertifika hiçbir el sıkışmada kabul edilmez -- ve bunu
  // ancak bir ağ hattı ötede fark edersiniz.
  console.log('\n6. TLS sunucu sertifikası sunucu adını SAN\'da taşıyor');
  const serverLeaf = leaves[0];
  if (hasOpenssl()) {
    const file = path.join(dir, 'server.pem');
    fs.writeFileSync(file, serverLeaf.leafPem);
    const text = execFileSync('openssl', ['x509', '-in', file, '-noout', '-text']).toString();
    check('dNSName SAN var', /DNS:session\.fitfak\.net/.test(text));
    check('EKU serverAuth', /TLS Web Server Authentication/.test(text));
  } else {
    check('dNSName SAN var (baytlarda)',
      pkiUrls.pemToDer(serverLeaf.leafPem).toString('latin1').includes('session.fitfak.net'));
  }

  // SAN'sız bir server-auth isteği REDDEDİLMELİ -- ve CN'den TÜRETİLMEMELİ. Türetme olsaydı
  // burada `DNS:alice` diye bir SAN üretilirdi: geçerli görünen, hiçbir sunucuyu adlandırmayan
  // bir sertifika. Sessizce üretmek yerine, isteyen tarafa neyin eksik olduğunu söylüyoruz.
  let refused = null;
  try {
    await issueLeaf(issuer, { cn: 'alice', profile: 'server-auth' });
  } catch (err) { refused = err; }
  check('sunucu adı olmayan server-auth isteği REDDEDİLİYOR',
    refused && refused.code === 'server_san_required');

  // CN, SAN'lardan biri olmalı: ikisinin farklı şeyler söylediği bir sertifika okuyanı yanıltır.
  const mismatched = await issueLeaf(issuer, {
    cn: 'alice', profile: 'server-auth', sans: [{ type: 'dns', value: 'api.fitfak.net' }],
  });
  check('CN, SAN ile hizalanıyor',
    /CN\s*=\s*api\.fitfak\.net/.test(new (require('node:crypto').X509Certificate)(mismatched.leafPem).subject));

  server.close();
  console.log(`\nOK - durum yönlendirmesi: ${checks} kontrol geçti.`);
}

main().catch((e) => { console.error('\nFAILED:', e.message); process.exit(1); });
