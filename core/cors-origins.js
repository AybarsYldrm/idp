'use strict';

// Hangi kaynakların bu API'yi tarayıcıdan çağırabileceği.
//
// Liste ELLE TUTULMUYOR, kayıtlı yönlendirme adreslerinden türetiliyor. Sebep, iki listenin
// ayrışması: bir uygulama kaydedildiğinde yönlendirme adresi zaten beyan ediliyor ve
// doğrulanıyor. İkinci bir "izinli kaynaklar" listesi tutmak, her yeni uygulamada güncellenmesi
// gereken ve güncellenmediğinde uygulamanın sessizce çalışmadığı bir yer daha demekti -- ki
// yaşanan tam olarak buydu: liste `session.fitfak.net` ve `trust.fitfak.net` ile sabitti,
// portal ve yönetim yüzeyi hiç eklenmemişti, ve tarayıcı isteği CORS'ta ölüyordu.
//
//
// YANSITMAK NEDEN DOĞRULAMA GEREKTİRİR
//
// `Access-Control-Allow-Origin: *` ile `Access-Control-Allow-Credentials: true` birlikte
// kullanılamaz; tarayıcı reddeder. Kimlik doğrulamalı bir API'de kaynağın YANSITILMASI gerekir.
// Ve doğrulanmadan yansıtılan bir kaynak, "herhangi bir sayfa kullanıcının çerezleriyle bu
// API'yi okuyabilir" demektir -- yani CORS'un var olma sebebinin tersi.
//
// Doğrulama kaynağı olarak kayıtlı yönlendirme adresleri seçildi çünkü onlar zaten güvenlik
// açısından anlamlı: bir uygulamanın yetkilendirme kodunu alabileceği adres orada beyan edilmiş
// durumda. O adrese kod göndermeye razıysak, o kaynağın kullanıcının kimlik bilgilerini
// okumasına da razıyızdır.
//
//
// ÖNBELLEK NEDEN VAR
//
// CORS başlıkları istek işlenirken, yanıt yazılmadan önce konuluyor ve o an eşzamanlı bir
// cevap gerekiyor. Her isteğe bir veritabanı sorgusu koymak, her çapraz kaynak çağrısına bir
// tur eklerdi. Küme bir kez kuruluyor, istemci değiştiğinde yenileniyor ve ayrıca zaman aşımıyla
// tazeleniyor -- yenilemenin unutulduğu bir yol kalmasın diye.

const DEFAULT_TTL_MS = 60_000;

class CorsOriginSet {
  /**
   * @param {object}   opts
   * @param {function} opts.listClients  async () => [{ redirects: [{ redirectUri }] }]
   * @param {string[]} [opts.always]     her zaman izinli kaynaklar (bu dağıtımın kendi yüzeyleri)
   * @param {number}   [opts.ttlMs]
   * @param {object}   [opts.logger]
   */
  constructor({ listClients, always = [], ttlMs = DEFAULT_TTL_MS, logger = null }) {
    this.listClients = listClients;
    this.always = new Set(always);
    this.ttlMs = ttlMs;
    this._log = logger;
    this._origins = new Set();
    this._refreshedAt = 0;
    this._refreshing = null;
  }

  /**
   * Eşzamanlı cevap. Küme bayatsa arka planda yenilenir ama BU istek beklemez.
   *
   * Beklemek daha doğru görünür ve değildir: yeni kaydedilmiş bir uygulamanın ilk isteği en
   * fazla bir kez reddedilir ve saniyeler içinde çalışır. Beklemek ise her isteğe bir
   * veritabanı turu ekler -- sürekli bir maliyet karşılığında, yalnızca geçici bir gecikme.
   */
  allows(origin) {
    if (!origin) return false;
    if (this.always.has(origin)) return true;
    if (Date.now() - this._refreshedAt > this.ttlMs) this.refresh().catch(() => {});
    return this._origins.has(origin);
  }

  /** Bir istemci eklendiğinde/değiştiğinde çağrılır: bekleme olmadan hemen geçerli olsun. */
  async refresh() {
    // Aynı anda birden fazla yenileme, aynı sorguyu birden fazla kez çalıştırmak demek.
    if (this._refreshing) return this._refreshing;
    this._refreshing = (async () => {
      try {
        const clients = await this.listClients();
        const next = new Set();
        for (const client of clients || []) {
          for (const redirect of client.redirects || client.redirectUris || []) {
            const uri = typeof redirect === 'string' ? redirect : redirect.redirectUri;
            const origin = originOf(uri);
            // Yalnızca https ve geri döngü. Bir kayıtta düz http bir alan adı varsa onu CORS
            // için kabul etmek, ağdaki herkesin yanıtı okuyabilmesi demek olurdu -- kayıt
            // doğrulaması onu zaten reddeder ama burada ikinci bir kapı olması ucuz.
            if (origin) next.add(origin);
          }
        }
        this._origins = next;
        this._refreshedAt = Date.now();
        this._log?.debug?.({ count: next.size, msg: 'CORS kaynak listesi yenilendi' });
      } catch (err) {
        // Yenileme başarısızlığı MEVCUT listeyi bozmaz: eldeki hâlâ geçerli ve bir sonraki
        // turda tekrar denenecek. Listeyi boşaltmak, çalışan her uygulamayı kırardı.
        this._log?.warn?.({ error: err.message, msg: 'CORS kaynak listesi yenilenemedi' });
        // Zaman damgası güncelleniyor ki bir sonraki istek yeniden denemeyle boğulmasın.
        this._refreshedAt = Date.now();
      } finally {
        this._refreshing = null;
      }
    })();
    return this._refreshing;
  }

  /** Panel/teşhis için: şu anda hangi kaynaklar izinli. */
  snapshot() {
    return {
      always: [...this.always].sort(),
      fromClients: [...this._origins].sort(),
      refreshedAt: this._refreshedAt,
    };
  }
}

/**
 * Bir yönlendirme adresinin kaynağı.
 *
 * `null` dönen her şey listeye girmez. Özellikle: özel şema (myapp://callback) bir kaynak
 * değildir ve tarayıcıdan gelmez; düz http yalnızca sayısal geri döngüde kabul edilir, çünkü
 * makineden çıkmayan bir bağlantıda okunacak bir trafik yoktur.
 */
function originOf(uri) {
  if (!uri) return null;
  let url;
  try { url = new URL(String(uri)); } catch (_) { return null; }
  if (url.protocol === 'https:') return url.origin;
  if (url.protocol === 'http:' && /^(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\]|localhost)$/.test(url.hostname)) {
    return url.origin;
  }
  return null;
}

function createCorsOriginSet(options) { return new CorsOriginSet(options); }

module.exports = { CorsOriginSet, createCorsOriginSet, originOf };
