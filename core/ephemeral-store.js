'use strict';

// ============================================================================
// Kısa ömürlü durum (setup token, mfa challenge token, e-posta doğrulama kodu, PoW
// meydan okuması, OAuth yetkilendirme kodu, device code) için ORTAK depolama arayüzü.
//
// NEDEN ÖNEMLİ: fitfak-idp'yi bir yük dengeleyici arkasında BİRDEN FAZLA instance
// olarak koşturursanız (yatay ölçekleme), bellek-içi bir Map ARTIK YETERSİZDİR --
// örneğin `/oauth/authorize` isteği instance A'ya gidip bir yetkilendirme kodu
// üretebilir, ama hemen ardından gelen `/oauth/token` isteği instance B'ye giderse,
// B'nin belleğinde o kod HİÇ YOK gibi görünür ve SSO sessizce bozulur. Aynı sorun
// setupToken/mfaChallengeToken/e-posta kodu/PoW meydan okuması/device code için de
// geçerlidir -- hepsi çok-adımlı akışların ARA durumlarıdır.
//
// `DbEphemeralStore`, ZATEN VAR OLAN `db.collection()` arayüzünü (embedded
// @fitfak/database VEYA uzak gRPC adaptörü -- ikisi de aynı arayüzü sağladığı için
// fark etmez) paylaşılan "gerçek kaynak" olarak kullanarak bunu çözer -- ayrı bir
// Redis/memcached bağımlılığı EKLEMEDEN.
//
// Rate-limiter SAYAÇLARI (core/rate-limiter.js) BİLEREK bu soyutlamayı kullanmıyor --
// onlar zaten "kesin doğru olması gerekmeyen, maliyet-yükseltici bir sezgisel" olarak
// tasarlandı (bkz. o dosyanın kendi notları); her instance'ın kendi rate-limit
// sayaçlarını tutması, DB'ye HER İSTEKTE ekstra bir round-trip eklemekten daha iyi bir
// mühendislik ödünleşimi. Gerçek/küresel rate limiting isterseniz Cloudflare gibi bir
// kenar (edge) katmanı önerilir (zaten kullandığınızı belirttiğiniz cloudflared gibi).
// ============================================================================

class InMemoryEphemeralStore {
  constructor() { this.map = new Map(); }

  async set(key, value, ttlMs) {
    this.map.set(key, { value, expiresAt: Date.now() + ttlMs });
  }

  async get(key) {
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) { this.map.delete(key); return null; }
    return entry.value;
  }

  async delete(key) { this.map.delete(key); }
}

class DbEphemeralStore {
  constructor(db, collectionName = 'ephemeral_state') {
    this.collection = db.collection(collectionName);
  }

  async set(key, value, ttlMs) {
    const existing = await this.collection.findOne('key', key);
    const payload = { key, valueJson: JSON.stringify(value), expiresAt: BigInt(Date.now() + ttlMs) };
    if (existing) await this.collection.update(existing._id, payload);
    else await this.collection.insert(payload);
  }

  async get(key) {
    const row = await this.collection.findOne('key', key);
    if (!row) return null;
    if (Date.now() > Number(row.expiresAt)) { await this.collection.delete(row._id); return null; }
    return JSON.parse(row.valueJson);
  }

  async delete(key) {
    const row = await this.collection.findOne('key', key);
    if (row) await this.collection.delete(row._id);
  }
}

// Aynı alttaki store'u (ör. tek bir `ephemeral_state` koleksiyonu) BİRDEN FAZLA mantıksal
// amaç için (setup token'lar, OAuth kodları, device code'lar, PoW meydan okumaları)
// anahtar ÇAKIŞMASI olmadan paylaşmak için ince bir önek sarmalayıcısı.
class PrefixedEphemeralStore {
  constructor(inner, prefix) { this.inner = inner; this.prefix = prefix; }
  set(key, value, ttlMs) { return this.inner.set(`${this.prefix}${key}`, value, ttlMs); }
  get(key) { return this.inner.get(`${this.prefix}${key}`); }
  delete(key) { return this.inner.delete(`${this.prefix}${key}`); }
}

module.exports = { InMemoryEphemeralStore, DbEphemeralStore, PrefixedEphemeralStore };
