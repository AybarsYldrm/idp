'use strict';

// Sertifikaların İÇİNE yazılan adresler ve onları karşılayan yollar -- TEK bir yerde.
//
// Bu dosya bir düzeltmenin kalıntısı. Adresler daha önce iki yerde vardı: core/pki-issuer.js
// onları sertifikaya gömüyor, services/status-server.js onları karşılıyordu. İkisi de doğru
// göründüğü sürece sorun yoktu; ayrıştıkları anda ortaya çıkan hata ise şuydu -- sertifika
// çalışan bir adres taşımıyor ve bunu HİÇBİR ŞEY söylemiyor:
//
//   * AIA caIssuers yanlışsa, zinciri eksik gönderen bir eşle karşılaşan doğrulayıcı ara
//     sertifikayı tamamlayamaz. Zinciri tam gönderen sunucularda hiçbir belirti yoktur.
//   * CRL dağıtım noktası yanlışsa, iptal sorgusu 404 alır ya da BAŞKA bir yayıncının
//     listesini alır. İkisinde de doğrulayıcı "iptal edilmemiş" sonucuna varır.
//
// İkisi de üretimde aylarca fark edilmeden durabilir. Kurucu ile çözücünün aynı dosyada
// olması, testin "gömülen adres, sunulan yolla eşleşiyor mu" diye sorabilmesini sağlıyor --
// iki ayrı düzenli ifadeyi elle karşılaştırmak yerine.
//
// @fitfak/ssl'e BAĞIMLI DEĞİL, kasaya da. İki taraf da bunu yükleyebilmeli ve durum sunucusu
// imzalama katmanını hiç yüklemeden yönlendirme yapabilmeli.

const STATUS_BASE = process.env.FITFAK_TRUST_STATUS_URL || 'http://status.trust.fitfak.net';

// Kasadaki otorite adlarının biçimi. Bir yol parçası olarak kullanılmıyor -- ad kasada
// aranıyor -- ama yine de daraltılmış: kısıtsız bir yakalama, ne olduğu belli olmayan bir
// dizeyi depoya sorgu olarak geçirmek demek.
const AUTHORITY_NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

const OCSP_URL = `${STATUS_BASE}/ocsp`;
const ROOT_CERT_URL = `${STATUS_BASE}/root.crt`;
const ROOT_CRL_URL = `${STATUS_BASE}/crl/root`;

// Düzeltmeden ÖNCE üretilmiş sertifikalar bu iki adresi taşıyor ve geçerlilik süreleri dolana
// kadar dolaşımda kalacaklar. Sunulmaya devam etmeleri gerekiyor; yeni sertifikalara artık
// gömülmüyorlar.
const LEGACY_CA_PATH = '/intermediate.crt';
const LEGACY_CRL_PATH = '/crl';
const ROOT_CRL_PATH = '/crl/root';

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
  const match = /^\/ca\/([^/]+)\.crt$/.exec(pathname);
  if (!match || !AUTHORITY_NAME_RE.test(match[1])) return null;
  return { authority: match[1], legacy: false };
}

/** `/crl/<ad>` -> { scope, authority }, ya da null. */
function parseCrlPath(pathname) {
  if (pathname === LEGACY_CRL_PATH) return { scope: 'leaf', authority: null, legacy: true };
  if (pathname === ROOT_CRL_PATH) return { scope: 'root', authority: 'root', legacy: false };
  const match = /^\/crl\/([^/]+)$/.exec(pathname);
  if (!match || !AUTHORITY_NAME_RE.test(match[1])) return null;
  return { scope: 'leaf', authority: match[1], legacy: false };
}

module.exports = {
  STATUS_BASE,
  OCSP_URL,
  ROOT_CERT_URL,
  ROOT_CRL_URL,
  LEGACY_CA_PATH,
  LEGACY_CRL_PATH,
  ROOT_CRL_PATH,
  AUTHORITY_NAME_RE,
  caIssuersUrlFor,
  crlUrlFor,
  parseCaPath,
  parseCrlPath,
};
