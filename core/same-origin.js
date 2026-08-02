'use strict';

const { AppError } = require('./errors');

// ============================================================================
// Siteler arası istek sahteciliğine (CSRF) karşı köken kontrolü.
//
// Oturum cookie'lerimiz `SameSite=Lax`. Bu, başka bir siteden yapılan
// FORM/fetch POST'larında cookie'nin GÖNDERİLMEMESİ demek -- yani temel koruma
// zaten var. O halde bu dosya niye var?
//
//  1. `Lax`, ÜST SEVİYE GEZİNMELERDE (bir bağlantıya tıklamak) GET isteklerine
//     cookie'yi verir. Durum değiştiren bir uç noktayı yanlışlıkla GET olarak
//     yazdığımız gün, koruma tek bir HTTP fiiline bağlı kalır. Burada fiile
//     değil, isteğin nereden geldiğine bakıyoruz.
//  2. `Lax` bir TARAYICI davranışıdır. Kullanıcının tarayıcısı eski ya da
//     alışılmadıksa varsayım tutmaz; sunucu tarafındaki kontrol tutar.
//  3. Alt alan adları aynı sitedir. `Lax`, kötü niyetli bir alt alan adından
//     (ya da ele geçirilmiş bir alt alan adından) gelen isteği engellemez;
//     tam köken (origin) eşitliği engeller.
//
// Gizli bir token (senkronizasyon token'ı) yerine köken başlığına bakmayı
// seçtik: token deseni her formda ayrı bir alan, her fetch'te ayrı bir başlık
// ve sunucuda ayrı bir durum ister; unutulan tek bir yer sessizce korumasız
// kalır. `Origin` başlığını tarayıcı gönderir, sayfa kodunun hatırlaması
// gereken bir şey yoktur.
//
// KAPSAM: yalnızca COOKIE ile kimliklenen uç noktalar. `Authorization: Bearer`
// ya da client_secret ile gelen makine istekleri (POST /oauth/token gibi)
// tarayıcıdan gelmediği için `Origin` göndermez ve CSRF'e zaten açık değildir
// -- kimlik bilgisi tarayıcı tarafından otomatik EKLENMİYOR.
// ============================================================================

function normalizeOrigin(value) {
  try {
    const url = new URL(value);
    return url.origin;
  } catch { return null; }
}

/**
 * @param {object} req
 * @param {object} opts
 * @param {string[]} opts.allowedOrigins - kabul edilen tam kökenler
 * @param {boolean} [opts.allowSameSite] - aynı sitenin BAŞKA bir alt alan adından
 *   gelen isteklere de izin ver. trust.fitfak.net üzerindeki uç noktalar için
 *   gerekli: onları çağıran sayfa session.fitfak.net'te, yani istek zaten
 *   köken-ötesi ama site-içi. Bu gevşetme, alt alan adlarının tümünün BİZE ait
 *   olduğu varsayımına dayanır -- üçüncü tarafa alt alan adı veriliyorsa
 *   kullanılmamalı.
 */
function assertSameOrigin(req, { allowedOrigins, allowSameSite = false }) {
  const allowed = new Set(allowedOrigins.map(normalizeOrigin).filter(Boolean));

  // `Authorization: Bearer` ile gelen istek CSRF'e yapısal olarak kapalıdır ve
  // bu kontrolün KAPSAMI DIŞINDADIR (bkz. dosya başlığındaki KAPSAM notu).
  //
  // Gerekçe: CSRF, tarayıcının kimlik bilgisini OTOMATİK eklemesinden doğar.
  // Cookie'yi tarayıcı kendiliğinden takar; `Authorization` başlığını takmaz --
  // onu ancak isteği kuran kodun kendisi yazabilir, ve o kod token'a zaten
  // sahipse çapraz-site sahteciliğine ihtiyacı yoktur.
  //
  // Bu istisna olmadan, uç noktalarımızı TARAYICI OLMAYAN meşru istemcilerin
  // (device-code ile giriş yapmış bir CLI, bir tünel istemcisi, bir betik)
  // çağırması imkânsızdı: hiçbiri Sec-Fetch-Site/Origin/Referer göndermez ve
  // istek son daldaki "kökeni belirlenemedi" ile 403 alırdı. Onları
  // `sec-fetch-site: none` uydurmaya zorlamak daha kötü bir sonuç verirdi --
  // o başlığın değerli olmasının tek sebebi, tarayıcıda SAYFA KODUNUN onu
  // değiştirememesidir; uydurulmasını normalleştirmek sinyali çöpe atar.
  const authorization = req.headers.authorization;
  if (authorization && /^Bearer\s+\S/i.test(authorization)) return;

  // Fetch Metadata: modern tarayıcılar bunu gönderir ve SAYFA KODU
  // DEĞİŞTİREMEZ (yasaklı başlık). Varsa en güvenilir sinyal budur.
  const site = req.headers['sec-fetch-site'];
  if (site) {
    // 'same-origin' bizden; 'none' kullanıcının doğrudan yazdığı/yer imi olan
    // adres (bir sayfanın tetikleyemeyeceği tek durum).
    if (site === 'same-origin' || site === 'none') return;
    // 'same-site' izinliyse bile Origin'i AYRICA doğruluyoruz: 'same-site',
    // eTLD+1 eşleşmesi demek, o alt alan adının bizim olduğu anlamına gelmez.
    if (allowSameSite && site === 'same-site') {
      const from = normalizeOrigin(req.headers.origin || '');
      if (from && allowed.has(from)) return;
      throw new AppError('cross_site_request', 'Bu istek tanınmayan bir alt alan adından geldi', { httpStatus: 403 });
    }
    throw new AppError('cross_site_request', 'Bu istek başka bir siteden geldi', { httpStatus: 403 });
  }

  const origin = req.headers.origin;
  if (origin) {
    if (allowed.has(normalizeOrigin(origin))) return;
    throw new AppError('cross_site_request', 'Bu istek başka bir kökenden geldi', { httpStatus: 403 });
  }

  // Ne Sec-Fetch-Site ne Origin var. `Referer` son çare: tarayıcı gizlilik
  // ayarlarıyla kısaltılmış olabilir, o yüzden yalnızca KÖKEN kısmına bakıyoruz.
  const referer = req.headers.referer;
  if (referer) {
    if (allowed.has(normalizeOrigin(referer))) return;
    throw new AppError('cross_site_request', 'Bu istek başka bir sayfadan geldi', { httpStatus: 403 });
  }

  // Hiçbiri yok. Bir tarayıcının durum değiştiren bir isteği bu üç başlığın
  // hiçbiri olmadan yapması beklenmez; curl/betik böyle davranır ve o istek de
  // cookie taşımaz. Reddetmek doğru varsayılan.
  throw new AppError('cross_site_request', 'İsteğin kökeni belirlenemedi', { httpStatus: 403 });
}

function createSameOriginGuard({ allowedOrigins, allowSameSite = false }) {
  return (req) => assertSameOrigin(req, { allowedOrigins, allowSameSite });
}

module.exports = { assertSameOrigin, createSameOriginGuard, normalizeOrigin };
