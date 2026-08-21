'use strict';

const http = require('node:http');

const ocspService = require('./ocsp-service');
const crlService = require('./crl-service');
const { policyDirectory, POLICIES } = require('../core/pki-policy');
// Yolları ÇÖZEN taraf. Kuran taraf (core/pki-issuer.js) ve BAĞLAYAN taraf (oauth-server.js)
// aynı dosyayı kullanıyor. Üçüncüsü eksikti: oauth-server.js kendi elle yazdığı listeyle
// bağlıyordu ve o listede `/ca/<otorite>.crt` ile `/crl/<otorite>` yoktu -- yani her uç
// sertifikanın AIA ve CDP adresi, buradaki işleyiciye VARMADAN 404 alıyordu.
const pkiUrls = require('../core/pki-urls');
const log = require('../core/logger').mk('status');

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
//
//
// NEDEN DER, NEDEN PEM DEĞİL
//
// Sertifika yayınlayan uçlar `application/pkix-cert` ile DER gönderir (RFC 2585 §4.1).
// Burada PEM gönderiliyordu ve bu, rota 200 dönerken bile Windows'ta AYNI hatayı üretir:
// CryptRetrieveObjectByUrl AIA'dan gelen baytı DER olarak çözer, `-----BEGIN CERTIFICATE-----`
// ile başlayan bir ASCII zarfı çözemez, ara sertifika alınamaz, zincir kurulamaz.
// Dönüşüm core/pki-urls.js'de: adres ile biçim aynı sözleşmenin iki yarısı.

const NO_STORE = { 'cache-control': 'no-store' };

function send(res, status, headers, body) {
  const buffer = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(status, { ...headers, 'content-length': buffer.length });
  // HEAD'e gövde yazılmaz ama content-length YAZILIR: iptal listesinin boyutunu
  // önden soran bir istemci, cevabı oradan okur.
  res.end(res.req && res.req.method === 'HEAD' ? undefined : buffer);
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

/** Bir sertifikayı AIA/CDP uçlarının sözleşmesine uygun biçimde yollar. */
function sendCertificate(res, certPem, { maxAge }) {
  return send(res, 200, {
    'content-type': pkiUrls.CERT_CONTENT_TYPE,
    'cache-control': `max-age=${maxAge}`,
  }, pkiUrls.pemToDer(certPem));
}

const INDEX_BODY = `FITFAK Certificate Status Service

POST /ocsp                  RFC 6960 OCSP
GET  /ocsp/<base64url-der>  RFC 6960 Annex A.1
GET  /crl/<otorite>         o ara CA'nin verdigi uc sertifikalarin iptal listesi
GET  /crl/root              ara CA iptal listesi (kok imzali)
GET  /ca/<otorite>.crt      o ara CA'nin sertifikasi (AIA caIssuers buraya bakar)
GET  /root.crt              kok CA sertifikasi
GET  /chain.pem             varsayilan ara + kok  (?purpose= ya da ?authority= ile secilir)

Sertifika yayinlayan uclar DER doner (application/pkix-cert, RFC 2585 4.1).

Her uc sertifika KENDI yayincisinin adresini tasir: bir CRL yalnizca kendi
yayincisinin verdigi sertifikalar hakkinda konusur (RFC 5280 6.3.3).

GET  /crl                   varsayilan yayincinin listesi   (eski adres)
GET  /intermediate.crt      varsayilan ara CA sertifikasi   (eski adres)

Contact: network@fitfak.net
`;

/**
 * @param {object} opts
 * @param {object} opts.db
 * @param {object} opts.pkiIssuer
 * @param {object} opts.cacheStore  paylaşılan ephemeral store (CRL önbelleği)
 */
function createStatusHandler({ db, pkiIssuer, cacheStore }) {
  return async function handle(req, res) {
    // `res.req` HEAD kontrolü için gerekiyor ve her taşımada dolu gelmiyor.
    if (!res.req) res.req = req;

    const url = new URL(req.url, pkiUrls.STATUS_BASE);
    // Yolun ne olduğuna karar veren TEK yer. oauth-server.js bağlama eşleştiricisi olarak
    // aynı fonksiyonu çağırıyor, yani "bağlandı ama tanınmadı" (ya da tersi) yapısal olarak
    // mümkün değil -- iki ayrı listenin sessizce ayrışması tam olarak düzeltilen hataydı.
    const route = pkiUrls.resolveStatusRoute(req.url, req.method);

    try {
      if (!route) {
        return send(res, 404, { 'content-type': 'text/plain; charset=utf-8', ...NO_STORE }, 'not found\n');
      }

      switch (route.kind) {
        // ---- OCSP ----------------------------------------------------------
        case 'ocsp-post': {
          const der = await readBody(req);
          const responseDer = await ocspService.handleOcspRequest({ db, pkiIssuer, ocspRequestDer: der });
          // OCSP yanıtı kendi nextUpdate'ini taşır; HTTP önbelleğinin ondan uzun
          // yaşaması, iptal edilmiş bir sertifikanın 'good' cevabının ağda takılı
          // kalması demektir.
          return send(res, 200, {
            'content-type': pkiUrls.OCSP_CONTENT_TYPE,
            'cache-control': 'max-age=3600',
          }, responseDer);
        }

        case 'ocsp-get': {
          // RFC 6960 Ek A.1: GET /ocsp/<base64url(DER)>
          let der;
          try {
            der = Buffer.from(decodeURIComponent(route.encoded), 'base64');
          } catch (_) {
            der = Buffer.alloc(0);
          }
          const responseDer = await ocspService.handleOcspRequest({ db, pkiIssuer, ocspRequestDer: der });
          return send(res, 200, {
            'content-type': pkiUrls.OCSP_CONTENT_TYPE,
            'cache-control': 'max-age=3600',
          }, responseDer);
        }

        case 'ocsp-hint':
          // GET /ocsp -- adres doğru, yöntem değil. 405 bunu söyler; 404 "burada bir şey yok"
          // derdi ve adresi elle deneyen bir operatörü yanlış yere bakmaya gönderirdi.
          return send(res, 405, {
            'content-type': 'text/plain; charset=utf-8', allow: 'POST', ...NO_STORE,
          }, 'OCSP istekleri POST ile gonderilir (RFC 6960); GET icin /ocsp/<base64-der>\n');

        // ---- CRL -----------------------------------------------------------
        //
        // HER YAYINCININ KENDİ LİSTESİ VAR ve bu bir gereklilik: RFC 5280 §6.3.3'e göre bir
        // CRL yalnızca kendi yayıncısının verdiği sertifikalar hakkında konuşur. Beş ara CA
        // varken (her amaç için ayrı) tek bir "uç sertifikalar listesi", o beşten dördünün
        // verdiği her sertifika için sessizce etkisiz kalırdı.
        //
        //   /crl/root          kök imzalar, ARA CA'ların iptallerini taşır
        //   /crl/<otorite>     o ara CA imzalar, yalnızca onun verdiği uçları
        //   /crl               varsayılan yayıncının listesi -- düzeltmeden önce üretilmiş
        //                      sertifikalar bu adrese işaret ediyor ve hâlâ dolaşımdalar
        case 'crl': {
          // Bilinmeyen ama biçimi doğru bir otorite adı -- `/crl/hayali-ca` -- 404 almalı.
          // Eşleştirici kasadaki adları BİLMEZ ve bilmemeli (ona bir depo bağımlılığı vermek
          // olurdu), yani buraya ulaşan bir istek var olmayan bir yayıncıyı sorabilir. Bu
          // durumda imzalayıcı yüklenmeye çalışılıyor ve fırlatan hata 500'e dönüşüyordu:
          // "sunucu bozuk" demek, oysa sorulan şey yoktu. Doğrulayıcılar 500'ü geçici arıza
          // sayıp yeniden dener ve bir noktada iptal kontrolünü tamamen atlar.
          if (route.authority && !(await pkiIssuer.getAuthorityCertPem(route.authority))) {
            return send(res, 404, { 'content-type': 'text/plain; charset=utf-8', ...NO_STORE },
              'bilinmeyen otorite\n');
          }
          const crlDer = await crlService.generateCrl({
            db, pkiIssuer, cacheStore, scope: route.scope, authority: route.authority,
          });
          return send(res, 200, {
            'content-type': pkiUrls.CRL_CONTENT_TYPE,
            'cache-control': `max-age=${Math.floor(crlService.CACHE_TTL_MS / 1000)}`,
          }, crlDer);
        }

        // ---- CA yayını -----------------------------------------------------
        //
        // AIA caIssuers burayı gösterir: zinciri eksik gönderen bir sunucuyla karşılaşan
        // istemci ara sertifikayı buradan tamamlar. Adres, uç sertifikayı İMZALAYAN otoritenin
        // adını taşır -- sabit bir /intermediate.crt, hangi ara CA'nın imzaladığından bağımsız
        // olarak hep aynı sertifikayı döndürür ve doğrulayıcı zinciri kuramaz.
        case 'ca': {
          const certPem = await pkiIssuer.getAuthorityCertPem(route.authority);
          if (!certPem) {
            return send(res, 404, { 'content-type': 'text/plain; charset=utf-8', ...NO_STORE },
              'bilinmeyen otorite\n');
          }
          // Bir CA sertifikası yıllarca değişmez. Uzun önbellek, AIA'yı takip eden her
          // doğrulamanın bir tur atmasını engeller.
          return sendCertificate(res, certPem, { maxAge: 86400 });
        }

        // Eski adres. Düzeltmeden önce üretilmiş sertifikalar buna işaret ediyor ve geçerlilik
        // süreleri dolana kadar dolaşımda kalacaklar; kaldırmak, onların zincir tamamlamasını
        // bugün kırardı.
        case 'legacy-ca':
          return sendCertificate(res, pkiIssuer.subCA.certPem, { maxAge: 86400 });

        case 'root-ca':
          return sendCertificate(res, pkiIssuer.rootCA.certPem, { maxAge: 86400 });

        case 'chain': {
          // Zincir kasadan geliyor ve AMACA GÖRE farklı (her amacın kendi ara CA'sı var).
          // Varsayılan istemci zinciriydi ve öyle kalıyor; ama bir TLS sunucusunun zincirini
          // isteyen birine istemci ara CA'sını vermek, adresi izleyen doğrulayıcı için
          // eksik halkanın YANLIŞ olanını göndermek demekti.
          const purpose = url.searchParams.get('purpose');
          const authority = url.searchParams.get('authority');
          let chainPem;
          if (authority) {
            chainPem = await pkiIssuer.getChainPemForAuthority(authority);
            if (!chainPem) {
              return send(res, 404, { 'content-type': 'text/plain; charset=utf-8', ...NO_STORE },
                'bilinmeyen otorite\n');
            }
          } else {
            chainPem = await pkiIssuer.getChainPem(purpose || undefined);
          }
          return send(res, 200, {
            'content-type': pkiUrls.CHAIN_CONTENT_TYPE, 'cache-control': 'max-age=3600',
          }, Buffer.from(chainPem));
        }

        case 'index':
          return send(res, 200, { 'content-type': 'text/plain; charset=utf-8', ...NO_STORE }, INDEX_BODY);

        default:
          return send(res, 404, { 'content-type': 'text/plain; charset=utf-8', ...NO_STORE }, 'not found\n');
      }
    } catch (err) {
      log.error({
        error: err.message, stack: err.stack, route: route ? route.kind : null,
        path: pkiUrls.normalizePath(req.url), msg: 'durum isteği başarısız',
      });
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
    if (!res.req) res.req = req;
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

  OCSP : ${pkiUrls.OCSP_URL}
  CRL  : ${pkiUrls.STATUS_BASE}/crl/<yayinci>

Her uc sertifika KENDI yayincisinin listesini gosterir; bir CRL yalnizca kendi
yayincisinin verdigi sertifikalar hakkinda konusur (RFC 5280 6.3.3).

Ara CA'lar icin ayri bir liste vardir (kok tarafindan imzali):

  CRL  : ${pkiUrls.ROOT_CRL_URL}

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
      log.info({ host, port, msg: 'durum sunucusu dinliyor (OCSP + CRL + CA yayını)' });
      resolve(server);
    });
  });
}

module.exports = { createStatusHandler, createPolicyHandler, startStatusServer };
