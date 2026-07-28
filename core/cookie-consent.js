'use strict';

const crypto = require('node:crypto');
const cookies = require('./cookies');

// ============================================================================
// Çerez kategorileri ve rıza.
//
// Bu dosyanın asıl işi bir bant göstermek değil, ÇEREZLERİ AYIRMAK. Oturum
// çerezi ile istatistik çerezi aynı kategoride sayıldığı sürece iki sonuçtan
// biri kaçınılmaz: ya istatistik çerezi rızasız yazılır, ya da "hepsini
// reddet" oturumu da kapatır. İkisi de yanlış.
//
// Ayrım şu soruya göre: KULLANICI BU ÇEREZ OLMADAN İSTEDİĞİ ŞEYİ YAPABİLİR Mİ?
//
//  - zorunlu: hayır. Oturum çerezi olmadan "giriş yap" diye bir şey yoktur;
//    cihaz çerezi olmadan "bu tarayıcıyı tanı" diye bir şey yoktur. Bunlar
//    rızaya bağlı değildir çünkü kullanıcının TALEP ETTİĞİ işlevin kendisidir.
//    Rıza sormak da yanıltıcı olurdu: reddedilemeyen bir şeyi sormak, sorunun
//    kendisini süse çevirir.
//  - istatistik: evet. Kullanıcı bunlar olmadan da her şeyi yapabilir; ölçüm
//    BİZİM işimize yarar, onun değil. O yüzden varsayılan KAPALI ve açık rıza
//    ister.
//
// Üçüncü bir kategori (reklam/izleme) yok, çünkü öyle bir çerez yazmıyoruz.
// Yazmadığımız bir kategoriyi listelemek, ileride sessizce doldurulabilecek
// bir kutu bırakmak olurdu.
// ============================================================================

const PREFS_COOKIE = 'fitfak_cprefs';
const STATS_COOKIE = 'fitfak_stat';
const PREFS_TTL_S = 180 * 24 * 3600;   // 6 ay: rızanın süresiz sayılmaması için
const STATS_TTL_S = 90 * 24 * 3600;

// Sistemin yazdığı HER çerez burada. Liste eksikse, kullanıcıya verilen
// açıklama eksiktir; o yüzden yeni bir çerez eklerken buraya da eklenmeli.
const COOKIE_CATALOG = [
  {
    name: '__Secure-fitfak_at',
    category: 'zorunlu',
    purpose: 'Oturumunuzu taşır (erişim belirteci). Bu çerez olmadan giriş yapılmış sayılmazsınız.',
    lifetime: 'Oturum süresi (kısa; yenileme belirteciyle tazelenir)',
    scope: '.fitfak.net — tüm alt alan adlarında tek oturum (SSO)',
  },
  {
    name: '__Secure-fitfak_rt',
    category: 'zorunlu',
    purpose: 'Oturumu yeniler. Yalnızca /oauth/token yoluna gönderilir.',
    lifetime: '30 gün',
    scope: '.fitfak.net, Path=/oauth/token',
  },
  {
    name: '__Secure-fitfak_accounts',
    category: 'zorunlu',
    purpose: 'Bu tarayıcıda açık olan hesapların listesi — hesap seçici bunu kullanır.',
    lifetime: '30 gün',
    scope: '.fitfak.net',
  },
  {
    name: '__Secure-fitfak_did',
    category: 'zorunlu',
    purpose: 'Bu tarayıcıyı tanır. Yeni bir cihazdan giriş yapıldığında sizi uyarabilmemiz ve her girişte yeni bir oturum satırı açmamamız için. Parmak izi DEĞİLDİR: rastgele bir tanıtıcıdır, tarayıcı özelliklerinden türetilmez.',
    lifetime: '1 yıl',
    scope: '.fitfak.net',
  },
  {
    name: PREFS_COOKIE,
    category: 'zorunlu',
    purpose: 'Bu sayfadaki tercihinizi hatırlar. Tercihi saklamayı reddetmek, tercihi her sayfada yeniden sormak demek olurdu.',
    lifetime: '6 ay',
    scope: '.fitfak.net',
  },
  {
    name: STATS_COOKIE,
    category: 'istatistik',
    purpose: 'Aynı ziyaretçinin farklı sayfa görüntülemelerini birbirine bağlar; kaç kişinin girişte takıldığını görebilmemiz için. Rastgele bir sayıdır, hesabınıza BAĞLANMAZ ve rıza vermezseniz hiç yazılmaz.',
    lifetime: '90 gün',
    scope: '.fitfak.net',
  },
];

const CATEGORIES = {
  zorunlu: {
    key: 'zorunlu',
    title: 'Zorunlu',
    detail: 'Giriş, oturum ve güvenlik için gereken çerezler. Bunlar olmadan hesabınıza giriş yapamazsınız, bu yüzden kapatılamazlar.',
    required: true,
  },
  istatistik: {
    key: 'istatistik',
    title: 'İstatistik',
    detail: 'Hangi adımlarda takıldığınızı toplu olarak görmemizi sağlar. Kapatabilirsiniz; kapalıyken bu çerez hiç yazılmaz.',
    required: false,
  },
};

/**
 * Tercih çerezini çöz.
 *
 * İmzalanmıyor. İmza, bir değeri BAŞKASININ değiştirmesine karşıdır; buradaki
 * değer kullanıcının kendi tercihi ve onu değiştirmenin tek sonucu kendi
 * tercihinin değişmesi. İmza koymak, sunucuda anahtar yönetimi eklerdi ve
 * hiçbir şey korumazdı.
 */
function readPreferences(cookieHeader) {
  const raw = parseCookieHeader(cookieHeader)[PREFS_COOKIE];
  if (!raw) return null;
  try {
    const parsed = JSON.parse(decodeURIComponent(raw));
    if (!parsed || typeof parsed !== 'object') return null;
    return {
      // Sürüm: kategori listesi değişirse eski rıza otomatik olarak geçersiz
      // sayılır ve yeniden sorulur. Kullanıcı görmediği bir kategoriye rıza
      // vermiş sayılamaz.
      version: Number(parsed.v) || 0,
      istatistik: parsed.istatistik === true,
      decidedAt: Number(parsed.t) || 0,
    };
  } catch { return null; }
}

const PREFS_VERSION = 1;

function preferencesAreCurrent(prefs) {
  return !!prefs && prefs.version === PREFS_VERSION;
}

function buildPreferencesCookie({ istatistik }, { domain } = {}) {
  const value = encodeURIComponent(JSON.stringify({
    v: PREFS_VERSION, istatistik: !!istatistik, t: Date.now(),
  }));
  return cookies.serializeCookie(PREFS_COOKIE, value, {
    domain, path: '/', maxAgeSeconds: PREFS_TTL_S,
    // HttpOnly DEĞİL: bant, sunucuya sormadan gösterilip gösterilmeyeceğine
    // karar verebilmeli. Bu bir kimlik bilgisi değil; JavaScript'ten okunması
    // hiçbir şeyi açığa çıkarmaz.
    httpOnly: false, secure: true, sameSite: 'Lax',
  });
}

function buildStatisticsCookie({ domain } = {}) {
  // Hesapla ilişkisi olmayan rastgele bir tanıtıcı. Kullanıcı kimliğinden
  // TÜRETİLMİYOR: türetilseydi, silinse bile yeniden üretilebilir olurdu ve
  // "istatistik" adı altında kalıcı bir kimlik taşırdı.
  const id = crypto.randomBytes(16).toString('base64url');
  return cookies.serializeCookie(STATS_COOKIE, id, {
    domain, path: '/', maxAgeSeconds: STATS_TTL_S,
    httpOnly: true, secure: true, sameSite: 'Lax',
  });
}

function expireStatisticsCookie({ domain } = {}) {
  return cookies.expireCookie(STATS_COOKIE, { domain, path: '/' });
}

function parseCookieHeader(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }
  return out;
}

/** İstatistik yazmadan önce sorulacak tek soru. */
function hasStatisticsConsent(cookieHeader) {
  const prefs = readPreferences(cookieHeader);
  return preferencesAreCurrent(prefs) && prefs.istatistik === true;
}

function describeCatalog() {
  return {
    version: PREFS_VERSION,
    categories: Object.values(CATEGORIES),
    cookies: COOKIE_CATALOG,
  };
}

module.exports = {
  PREFS_COOKIE, STATS_COOKIE, PREFS_VERSION, COOKIE_CATALOG, CATEGORIES,
  readPreferences, preferencesAreCurrent, buildPreferencesCookie,
  buildStatisticsCookie, expireStatisticsCookie,
  hasStatisticsConsent, describeCatalog, parseCookieHeader,
};
