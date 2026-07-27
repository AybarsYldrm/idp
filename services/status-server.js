'use strict';

const http = require('node:http');

const ocspService = require('./ocsp-service');
const crlService = require('./crl-service');
const { policyDirectory, POLICIES } = require('../core/pki-policy');

// status.trust.fitfak.net — iptal durumu ve CA yayını.
//
// Düz HTTP, port 80. Bunlar sertifikada AIA/CDP olarak yazan adreslerdir ve
// HTTPS OLMAMALIDIR: bir sertifikanın iptal durumunu sorgulamak için önce başka
// bir sertifikayı doğrulamak gerekseydi, sorgunun kendisi doğrulamak istediğimiz
// şeye bağımlı hale gelirdi. RFC 5280 bu yüzden bu uçları düz HTTP olarak
// tanımlar; OCSP yanıtı ve CRL zaten kendi içlerinde imzalıdır, gizlilik değil
// bütünlük gerekir ve onu taşıma katmanı değil imza sağlar.
//
// time.trust.fitfak.net (RFC 3161 TSA) AYNI IP üzerinde, ayrı hostname olarak
// çalışır ve aynı sebeple düz HTTP'dir -- bkz. @fitfak/ssl examples/timestamp-server.js

const NO_STORE = { 'cache-control': 'no-store' };

function send(res, status, headers, body) {
  res.writeHead(status, { ...headers, 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

function readBody(req, maxBytes = 64 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (c) => {
      total += c.length;
      // OCSP isteği birkaç yüz bayttır. Kimlik doğrulaması olmayan bir uçta
      // sınırsız gövde kabul etmek bedava bellek tüketimidir.
      if (total > maxBytes) { req.destroy(); reject(new Error('body too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * @param {object} opts
 * @param {object} opts.db
 * @param {object} opts.pkiIssuer
 * @param {object} opts.cacheStore  paylaşılan ephemeral store (CRL önbelleği)
 */
function createStatusHandler({ db, pkiIssuer, cacheStore }) {
  return async function handle(req, res) {
    const url = new URL(req.url, 'http://status.trust.fitfak.net');
    const pathname = url.pathname.replace(/\/+$/, '') || '/';

    try {
      // ---- OCSP ------------------------------------------------------------
      if (pathname === '/ocsp' && req.method === 'POST') {
        const der = await readBody(req);
        const responseDer = await ocspService.handleOcspRequest({ db, pkiIssuer, ocspRequestDer: der });
        // OCSP yanıtı kendi nextUpdate'ini taşır; HTTP önbelleğinin ondan uzun
        // yaşaması, iptal edilmiş bir sertifikanın 'good' cevabının ağda takılı
        // kalması demektir.
        return send(res, 200, {
          'content-type': 'application/ocsp-response',
          'cache-control': 'max-age=3600',
        }, responseDer);
      }

      // RFC 6960 Ek A.1: GET /ocsp/<base64url(DER)>
      if (pathname.startsWith('/ocsp/') && req.method === 'GET') {
        const encoded = decodeURIComponent(pathname.slice('/ocsp/'.length));
        const der = Buffer.from(encoded, 'base64');
        const responseDer = await ocspService.handleOcspRequest({ db, pkiIssuer, ocspRequestDer: der });
        return send(res, 200, {
          'content-type': 'application/ocsp-response',
          'cache-control': 'max-age=3600',
        }, responseDer);
      }

      // ---- CRL -------------------------------------------------------------
      // İki ayrı liste: /crl uç sertifikalar (ara CA imzalı), /crl/root ara
      // CA'lar (kök imzalı). Sertifikalardaki CDP adresleri buna göre yazılır.
      if ((pathname === '/crl' || pathname === '/crl/root') && (req.method === 'GET' || req.method === 'HEAD')) {
        const scope = pathname === '/crl/root' ? 'root' : 'leaf';
        const crlDer = await crlService.generateCrl({ db, pkiIssuer, cacheStore, scope });
        return send(res, 200, {
          'content-type': 'application/pkix-crl',
          'cache-control': `max-age=${Math.floor(crlService.CACHE_TTL_MS / 1000)}`,
        }, req.method === 'HEAD' ? Buffer.alloc(0) : crlDer);
      }

      // ---- CA yayını -------------------------------------------------------
      // AIA caIssuers burayı gösterir: zinciri eksik gönderen bir sunucuyla
      // karşılaşan istemci ara sertifikayı buradan tamamlar.
      if (pathname === '/intermediate.crt' && req.method === 'GET') {
        return send(res, 200, { 'content-type': 'application/pkix-cert' },
          Buffer.from(pkiIssuer.subCA.certPem));
      }
      if (pathname === '/root.crt' && req.method === 'GET') {
        return send(res, 200, { 'content-type': 'application/pkix-cert' },
          Buffer.from(pkiIssuer.rootCA.certPem));
      }
      if (pathname === '/chain.pem' && req.method === 'GET') {
        return send(res, 200, { 'content-type': 'application/x-pem-file' },
          Buffer.from(pkiIssuer.getChainPem()));
      }

      if (pathname === '/' && (req.method === 'GET' || req.method === 'HEAD')) {
        const body = `FITFAK Certificate Status Service

POST /ocsp                  RFC 6960 OCSP
GET  /ocsp/<base64url-der>  RFC 6960 Annex A.1
GET  /crl                   uc sertifika iptal listesi (ara CA imzali)
GET  /crl/root              ara CA iptal listesi (kok imzali)
GET  /intermediate.crt      ara CA sertifikasi
GET  /root.crt              kok CA sertifikasi
GET  /chain.pem             ara + kok

Contact: network@fitfak.net
`;
        return send(res, 200, { 'content-type': 'text/plain; charset=utf-8', ...NO_STORE }, body);
      }

      return send(res, 404, { 'content-type': 'text/plain; charset=utf-8', ...NO_STORE }, 'not found\n');
    } catch (err) {
      console.error('[status] hata:', err);
      return send(res, 500, { 'content-type': 'text/plain; charset=utf-8', ...NO_STORE }, 'internal error\n');
    }
  };
}

/**
 * trust.fitfak.net/policy — sertifika politikalarının yayını.
 *
 * Sertifikaların içine gömülen politika OID'i ve CPS bağlantısı buraya işaret
 * eder. Metin, sertifikaları üreten tabloyla AYNI kaynaktan (core/pki-policy.js)
 * üretilir; ayrı yazılsaydı yayınlanan politika ile kodun gerçekte uyguladığı
 * kural zamanla ayrışırdı ve bunu kimse fark etmezdi.
 */
function createPolicyHandler() {
  return function handle(req, res) {
    const url = new URL(req.url, 'https://trust.fitfak.net');
    const pathname = url.pathname.replace(/\/+$/, '') || '/';

    if (pathname === '/policy' || pathname === '/policy/index.json') {
      const body = JSON.stringify(policyDirectory(), null, 2);
      return send(res, 200, { 'content-type': 'application/json; charset=utf-8' }, body);
    }

    const match = /^\/policy\/([a-z0-9-]+)$/.exec(pathname);
    if (match) {
      const profile = match[1];
      const policy = POLICIES[profile];
      if (!policy) {
        return send(res, 404, { 'content-type': 'text/plain; charset=utf-8' }, 'bilinmeyen politika\n');
      }
      const dir = policyDirectory();
      const body = `# ${policy.name}

Politika OID : ${policy.oid}
Profil       : ${profile}
IANA PEN     : ${dir.pen}

## Kimlik doğrulama

${policy.identityProofing}

## Sertifikaya gömülen bildirim

${policy.notice}

## İptal

Iptal durumu OCSP ve CRL uzerinden yayinlanir:

  OCSP : http://status.trust.fitfak.net/ocsp
  CRL  : http://status.trust.fitfak.net/crl

Ara CA'lar icin ayri bir liste vardir (kok tarafindan imzali):

  CRL  : http://status.trust.fitfak.net/crl/root

Bir ara CA iptal edildiginde altindaki tum sertifikalar gecersizdir.

## Iletisim

network@fitfak.net
`;
      return send(res, 200, { 'content-type': 'text/plain; charset=utf-8' }, body);
    }

    return send(res, 404, { 'content-type': 'text/plain; charset=utf-8' }, 'not found\n');
  };
}

/** status.trust.fitfak.net'i bağımsız bir süreç olarak çalıştırmak için. */
function startStatusServer({ db, pkiIssuer, cacheStore, host, port = 80 }) {
  const server = http.createServer(createStatusHandler({ db, pkiIssuer, cacheStore }));
  return new Promise((resolve) => {
    server.listen(port, host, () => {
      console.log(`[status] dinliyor: http://${host}:${port} (OCSP + CRL + CA yayını)`);
      resolve(server);
    });
  });
}

module.exports = { createStatusHandler, createPolicyHandler, startStatusServer };
