'use strict';

const { SlidingWindowCounter } = require('./rate-limiter');
const { AppError } = require('./errors');

// ============================================================================
// Kullanıcı başına kota.
//
// core/rate-limiter.js GİRİŞ akışını korur ve IP/kullanıcı adı/parmak izi
// eksenlerinde sayar -- yani kimliği HENÜZ BELLİ OLMAYAN trafiği. Bu dosya
// karşı tarafı kapatıyor: kimliği belli, oturumu geçerli bir kullanıcının
// pahalı işlemleri sınırsız çağırması.
//
// Neden ayrı bir eksen: giriş sonrası istekler zaten "meşru" sayılır ve IP
// limitine takılmaz -- ele geçirilmiş tek bir oturum, tek bir IP'den, kendi
// limitinin altında kalarak binlerce sertifika bastırabilir ya da her seferinde
// bir e-posta tetikleyen hesap silme kodunu sürekli isteyerek kullanıcının
// posta kutusunu kullanılmaz hale getirebilirdi.
//
// Sayaçlar BELLEKTE. Bilinçli: birden fazla instance koşarken her instance
// kendi sayacını tutar, yani gerçek sınır instance sayısıyla çarpılır. Bu bir
// maliyet-yükseltme aracı, bir muhasebe sistemi değil -- her istekte
// veritabanına ek bir tur atmak, koruduğu şeyden pahalıya mal olurdu (aynı
// gerekçe core/ephemeral-store.js'in başında da var).
// ============================================================================

// Sınırlar işlemin GERÇEK maliyetine göre. E-posta gönderen ve sertifika basan
// işlemler en dar; okuma yok (okuma zaten ucuz ve kullanıcının kendi verisi).
const DEFAULT_LIMITS = {
  // Her biri bir e-posta gönderir.
  'account-delete': { windowMs: 60 * 60_000, max: 3 },
  // Onay kodu denemesi: kod 6 haneli, deneme sayısı sınırlanmazsa taranabilir.
  'account-delete-confirm': { windowMs: 15 * 60_000, max: 5 },
  // Görsel çözme, sıkıştırılmamış hâlde megabaytlarca bellek demek.
  avatar: { windowMs: 60_000, max: 10 },
  // Sertifika basmak CA'yı çalıştırır ve CT günlüğüne kalıcı bir girdi yazar.
  certificate: { windowMs: 60 * 60_000, max: 20 },
  // Profil yazma ucuz ama sınırsız değil.
  profile: { windowMs: 60_000, max: 30 },
  // Genel: adı geçmeyen her işlem için.
  default: { windowMs: 60_000, max: 60 },
};

class UserQuota {
  constructor({ limits = {} } = {}) {
    this.limits = { ...DEFAULT_LIMITS, ...limits };
    this.counters = new Map(); // action -> SlidingWindowCounter
  }

  _counter(action) {
    if (!this.counters.has(action)) {
      const spec = this.limits[action] || this.limits.default;
      this.counters.set(action, new SlidingWindowCounter(spec));
    }
    return this.counters.get(action);
  }

  /** @returns {{limited: boolean, count: number, max: number, retryAfterSeconds: number}} */
  check(userId, action) {
    const spec = this.limits[action] || this.limits.default;
    const { count, limited } = this._counter(action).hit(String(userId));
    return {
      limited, count, max: spec.max,
      retryAfterSeconds: Math.ceil(spec.windowMs / 1000),
    };
  }

  /** Aşımda AppError fırlatır -- çağrı yerinde tek satır olsun diye. */
  enforce(userId, action) {
    const result = this.check(userId, action);
    if (result.limited) {
      throw new AppError(
        'rate_limited',
        'Bu işlemi çok sık yaptınız, biraz sonra tekrar deneyin',
        { httpStatus: 429, retryAfterSeconds: result.retryAfterSeconds },
      );
    }
    return result;
  }
}

module.exports = { UserQuota, DEFAULT_LIMITS };
