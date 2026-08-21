'use strict';

// Durum servisinin SÖZLEŞMESİ: hangi adresler sertifikaların içine yazılıyor, o adreslere
// gelen isteği kim karşılıyor, ve karşılık hangi BİÇİMDE veriliyor.
//
// Bu dosya bir düzeltmenin kalıntısı ve düzeltme İKİ KEZ eksik kaldı. Adresler önce iki
// yerdeydi: core/pki-issuer.js onları sertifikaya gömüyor, services/status-server.js
// karşılıyordu. Kurucu ile çözücü buraya toplandı. Ama ÜÇÜNCÜ bir kopya vardı ve kimse
// bakmadı -- oauth-server.js, durum sunucusunu şu elle yazılmış listenin arkasına
// bağlıyordu:
//
//     ['/ocsp', '/crl', '/crl/root', '/intermediate.crt', '/root.crt', '/chain.pem', '/']
//
// Listede `/ca/<otorite>.crt` ve `/crl/<otorite>` YOK. Yani her uç sertifikanın taşıdığı
// AIA caIssuers ve CRL dağıtım noktası adresi -- BEŞ ara CA'nın hepsi için -- daha durum
// sunucusuna ULAŞMADAN 404 alıyordu. Durum sunucusu o yolları doğru karşılıyor; istek ona
// hiç varmıyor.
//
// Windows tarafında görülen tam olarak buydu:
//
//   * AIA 404 -> zincir tamamlanamıyor -> "Incomplete certificate chain / Missing Issuer"
//   * CDP 404 -> iptal listesi alınamıyor -> CERT_E_REVOCATION_OFFLINE
//
// Testler bunu göremezdi, çünkü hepsi `createStatusHandler`'ı DOĞRUDAN bir http sunucusuna
// veriyor ve üretimdeki bağlama eşleştiricisini hiç çalıştırmıyordu.
//
// Bu yüzden artık elle yazılmış liste YOK. `resolveStatusRoute()` tek karar noktası:
// oauth-server.js "bu istek durum servisine mi ait" diye ONA soruyor, status-server.js
// "bu istek NE" diye yine ONA soruyor. İkisi aynı cevabı almak zorunda, çünkü aynı
// fonksiyonu çağırıyorlar.
//
//
// BİÇİM DE BU SÖZLEŞMENİN PARÇASI
//
// `application/pkix-cert` (RFC 2585 §4.1) TEK ve DER kodlanmış bir sertifika demektir. Bu
// uçlar PEM gönderiyordu -- yani ASCII zarf, `-----BEGIN CERTIFICATE-----`. Windows'un
// CryptRetrieveObjectByUrl'ü AIA'dan gelen baytı DER olarak çözmeye çalışır ve PEM'i
// çözemez; zincir yine tamamlanmaz. Rota düzeltilip biçim düzeltilmezse Windows 404 yerine
// 200 alır ve AYNI hatayı verir. O yüzden ikisi aynı dosyada.
//
// @fitfak/ssl'e BAĞIMLI DEĞİL, kasaya da: her iki taraf da bunu yükleyebilmeli ve durum
// sunucusu imzalama katmanını hiç yüklemeden yönlendirme yapabilmeli.

const STATUS_BASE = process.env.FITFAK_TRUST_STATUS_URL || 'http://status.trust.fitfak.net';

// Kasadaki otorite adlarının biçimi. Bir yol parçası olarak kullanılmıyor -- ad kasada
// aranıyor -- ama yine de daraltılmış: kısıtsız bir yakalama, ne olduğu belli olmayan bir
// dizeyi depoya sorgu olarak geçirmek demek.
const AUTHORITY_NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

const OCSP_PATH = '/ocsp';
const OCSP_GET_PREFIX = '/ocsp/';
const OCSP_URL = `${STATUS_BASE}${OCSP_PATH}`;
const ROOT_CERT_PATH = '/root.crt';
const ROOT_CERT_URL = `${STATUS_BASE}${ROOT_CERT_PATH}`;
const ROOT_CRL_URL = `${STATUS_BASE}/crl/root`;
const CHAIN_PATH = '/chain.pem';

// Düzeltmeden ÖNCE üretilmiş sertifikalar bu iki adresi taşıyor ve geçerlilik süreleri dolana
// kadar dolaşımda kalacaklar. Sunulmaya devam etmeleri gerekiyor; yeni sertifikalara artık
// gömülmüyorlar.
const LEGACY_CA_PATH = '/intermediate.crt';
const LEGACY_CRL_PATH = '/crl';
const ROOT_CRL_PATH = '/crl/root';

// RFC 2585 §4.1: ikisi de DER. PEM göndermek, doğrulayıcının baytı çözememesi demek.
const CERT_CONTENT_TYPE = 'application/pkix-cert';
const CRL_CONTENT_TYPE = 'application/pkix-crl';
const CHAIN_CONTENT_TYPE = 'application/x-pem-file';
const OCSP_CONTENT_TYPE = 'application/ocsp-response';

/** Bir uç sertifikanın AIA caIssuers adresi: onu İMZALAYAN otoritenin sertifikası. */
function caIssuersUrlFor(authorityName) {
  return `${STATUS_BASE}/ca/${authorityName}.crt`;
}

/** Bir uç sertifikanın CRL dağıtım noktası: onu İMZALAYAN otoritenin iptal listesi. */
function crlUrlFor(authorityName) {
  return `${STATUS_BASE}/crl/${authorityName}`;
}

/** `/ca/<ad>.crt` -> otorite adı, ya da null. */
function parseCaPath(pathname) {
  if (pathname === LEGACY_CA_PATH) return { authority: null, legacy: true };
  const match = /^\/ca\/([^/]+)\.crt$/.exec(decodePathSegment(pathname));
  if (!match || !AUTHORITY_NAME_RE.test(match[1])) return null;
  return { authority: match[1], legacy: false };
}

/** `/crl/<ad>` -> { scope, authority }, ya da null. */
function parseCrlPath(pathname) {
  if (pathname === LEGACY_CRL_PATH) return { scope: 'leaf', authority: null, legacy: true };
  if (pathname === ROOT_CRL_PATH) return { scope: 'root', authority: 'root', legacy: false };
  const match = /^\/crl\/([^/]+)$/.exec(decodePathSegment(pathname));
  if (!match || !AUTHORITY_NAME_RE.test(match[1])) return null;
  return { scope: 'leaf', authority: match[1], legacy: false };
}

/**
 * `%2D` gibi kodlanmış baytları çözer.
 *
 * Yol parçaları normalde kodlanmış gelmez, ama gelen istek BİZDEN çıkmıyor: bir doğrulayıcı
 * kütüphanesinin ne göndereceği bizim seçimimiz değil. Çözülmemiş bir `%2D`, düzenli ifadeye
 * takılmayacağı için 404 olurdu -- yani düzelttiğimiz hatanın daha dar bir hâli.
 * Çözülemeyen dizi olduğu gibi bırakılıyor; atılacak karar burada değil, adı kasada aranırken.
 */
function decodePathSegment(pathname) {
  if (!pathname.includes('%')) return pathname;
  try { return decodeURIComponent(pathname); } catch (_) { return pathname; }
}

/**
 * Bir istek yolunu (sorgu dizesiyle birlikte olabilir) kanonik yola indirir.
 *
 * Tek bir yerde: oauth-server.js `.split('?')[0].replace(...)`, status-server.js ise
 * `new URL(...).pathname.replace(...)` yapıyordu. İkisi bugün aynı sonucu veriyordu ve
 * ayrıştıkları gün, bağlama eşleştiricisinin geçirdiği bir yolu işleyicinin tanımaması
 * (ya da tersi) mümkün olurdu -- düzeltilen hatanın tam olarak biçimi.
 *
 * OCSP GET yolları bunun DIŞINDA: RFC 6960 Ek A.1'de yolun kuyruğu base64'tür ve `/` ile
 * bitebilir. Sondaki eğik çizgiyi kırpmak, isteğin baytlarını bozmak olurdu.
 */
function normalizePath(requestUrl) {
  const raw = String(requestUrl || '/').split('?')[0].split('#')[0];
  if (raw.startsWith(OCSP_GET_PREFIX)) return raw;
  return raw.replace(/\/+$/, '') || '/';
}

/**
 * Bu istek durum servisine mi ait, ve neyi istiyor?
 *
 * TEK karar noktası. oauth-server.js bunu bağlama eşleştiricisi olarak, status-server.js
 * gönderim tablosu olarak kullanıyor. İkisinin ayrı listeler taşıdığı hâl, her uç
 * sertifikanın AIA ve CDP adresinin üretimde 404 dönmesiyle sonuçlandı.
 *
 * @param {string} requestUrl  ham `req.url` (sorgu dizesi olabilir)
 * @param {string} [method]
 * @returns {null|{kind, pathname, method, ...}}
 */
function resolveStatusRoute(requestUrl, method = 'GET') {
  const pathname = normalizePath(requestUrl);
  const verb = String(method || 'GET').toUpperCase();
  const readOnly = verb === 'GET' || verb === 'HEAD';

  if (pathname === OCSP_PATH) {
    // POST asıl yol; GET/HEAD'e yönergeyi anlatan bir cevap dönüyoruz. 404 dönmek, adresi
    // elle deneyen bir operatöre "burada bir şey yok" demek olurdu -- oysa var.
    return { kind: verb === 'POST' ? 'ocsp-post' : 'ocsp-hint', pathname, method: verb };
  }
  if (pathname.startsWith(OCSP_GET_PREFIX) && readOnly) {
    // RFC 6960 Ek A.1: GET /ocsp/<base64(DER)>
    return { kind: 'ocsp-get', pathname, method: verb, encoded: pathname.slice(OCSP_GET_PREFIX.length) };
  }

  const crl = parseCrlPath(pathname);
  if (crl && readOnly) return { kind: 'crl', pathname, method: verb, ...crl };

  const ca = parseCaPath(pathname);
  if (ca && !ca.legacy && readOnly) return { kind: 'ca', pathname, method: verb, ...ca };

  if (pathname === LEGACY_CA_PATH && readOnly) return { kind: 'legacy-ca', pathname, method: verb };
  if (pathname === ROOT_CERT_PATH && readOnly) return { kind: 'root-ca', pathname, method: verb };
  if (pathname === CHAIN_PATH && readOnly) return { kind: 'chain', pathname, method: verb };
  if (pathname === '/' && readOnly) return { kind: 'index', pathname, method: verb };

  return null;
}

/**
 * Bağlama eşleştiricisi: `server.addHttpHandler(matchesStatusRequest, handler, STATUS_IP)`.
 *
 * Yolu tanımayan bir istek durum işleyicisine hiç gitmez; tanıyan HER istek gider. Aradaki
 * farkı elle yazılmış bir listenin taşıması, düzeltilen hatanın kendisiydi.
 */
function matchesStatusRequest(req) {
  return resolveStatusRoute(req.url, req.method) !== null;
}

/** Bu dağıtımın sertifikalarına gömülen ve karşılanması ZORUNLU olan adresler. */
function embeddedUrlsFor(authorityNames = []) {
  const urls = [OCSP_URL, ROOT_CERT_URL, ROOT_CRL_URL];
  for (const name of authorityNames) urls.push(caIssuersUrlFor(name), crlUrlFor(name));
  return urls;
}

/**
 * PEM -> DER.
 *
 * Kasa sertifikaları PEM olarak tutuyor (okunabilir, kopyalanabilir, günlüğe yazılabilir) ama
 * AIA/CDP uçları DER yayınlamak zorunda. Dönüşüm burada, çünkü BİÇİM de bu dosyanın tanımladığı
 * sözleşmenin parçası: adresi doğru karşılayıp yanlış baytı göndermek, adresi hiç karşılamamakla
 * aynı sonucu veriyor.
 *
 * Zaten DER olan bir tampon olduğu gibi dönüyor: çağıranın elindekinin hangisi olduğunu bilmek
 * zorunda kalması, bir gün bir yerde iki kez kodlanmış bir sertifika demektir.
 */
function pemToDer(input) {
  if (Buffer.isBuffer(input) && input[0] === 0x30) return input;
  const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input || '');
  const match = /-----BEGIN [A-Z0-9 ]+-----([\s\S]*?)-----END [A-Z0-9 ]+-----/.exec(text);
  if (!match) {
    throw new Error('[pki-urls] PEM zarfı bulunamadı; DER üretilemiyor');
  }
  return Buffer.from(match[1].replace(/\s+/g, ''), 'base64');
}

module.exports = {
  STATUS_BASE,
  OCSP_URL,
  OCSP_PATH,
  ROOT_CERT_URL,
  ROOT_CERT_PATH,
  ROOT_CRL_URL,
  CHAIN_PATH,
  LEGACY_CA_PATH,
  LEGACY_CRL_PATH,
  ROOT_CRL_PATH,
  AUTHORITY_NAME_RE,
  CERT_CONTENT_TYPE,
  CRL_CONTENT_TYPE,
  CHAIN_CONTENT_TYPE,
  OCSP_CONTENT_TYPE,
  caIssuersUrlFor,
  crlUrlFor,
  parseCaPath,
  parseCrlPath,
  normalizePath,
  resolveStatusRoute,
  matchesStatusRequest,
  embeddedUrlsFor,
  pemToDer,
};
