'use strict';

const crypto = require('node:crypto');
const { InMemoryEphemeralStore } = require('./ephemeral-store');

const DEFAULT_TTL_MS = 2 * 60 * 1000;

/**
 * Hashcash tarzı, SHA-256 tabanlı proof-of-work. İstemci (tarayıcı), sunucunun verdiği
 * `challenge` dizesiyle birleştirildiğinde SHA-256 çıktısının en az `difficultyBits` kadar
 * baştan-sıfır bit'e sahip olduğu bir `nonce` bulmak zorunda -- bu kaba kuvvetle (brute
 * force) arama gerektirir ve doğrulaması sunucu için tek bir hash hesaplaması kadar ucuzdur.
 * Bu, otomatik (bot/script) login/register denemelerinin BİREYSEL maliyetini kasıtlı olarak
 * yükseltir; insan kullanıcılar için (tek seferlik, tarayıcıda ~birkaç yüz ms) fark
 * edilmeyecek kadar küçük bir gecikme ekler.
 *
 * DÜRÜSTLÜK NOTU: PoW, bot'ları İMKANSIZ hale getirmez -- sadece HER denemenin maliyetini
 * yükseltir. Yeterli hesaplama gücüne sahip bir saldırgan yine de PoW'u çözebilir; bunun
 * değeri, kimlik bilgisi doldurma (credential stuffing) gibi YÜKSEK HACİMLİ otomasyonu
 * ekonomik olarak anlamsızlaştırmasıdır, tekil bir hedefli saldırıyı değil.
 *
 * ÇOKLU-INSTANCE NOTU: `store` core/ephemeral-store.js arayüzünü kullanır (varsayılan:
 * tek-instance bellek-içi). Birden fazla fitfak-idp instance'ı bir yük dengeleyici
 * arkasında koşuyorsa, meydan okuma instance A'da üretilip çözüm instance B'ye
 * gönderilebilir -- bu durumda DB-backed bir store (oauth-server.js'te enjekte edilir)
 * ŞARTTIR, aksi halde meşru kullanıcılar aralıklı "pow_failed" hatası alır.
 */
class ProofOfWorkService {
  constructor({ ttlMs = DEFAULT_TTL_MS, store } = {}) {
    this.ttlMs = ttlMs;
    this.store = store || new InMemoryEphemeralStore();
    // Periyodik temizlik SADECE bellek-içi store için gerekli/mümkün (DB-backed
    // store'larda süresi dolmuş kayıtlar zaten get() sırasında görmezden gelinir --
    // kalıcı satırların fiziksel temizliği için ayrı bir bakım işi/cron önerilir, bkz.
    // README "Kapsam ve sınırlamalar").
    if (this.store instanceof InMemoryEphemeralStore) {
      this._gcTimer = setInterval(() => this._gc(), 30_000);
      this._gcTimer.unref?.();
    }
  }

  async issueChallenge({ difficultyBits = 18 } = {}) {
    const challengeId = crypto.randomBytes(16).toString('hex');
    const challenge = crypto.randomBytes(24).toString('hex');
    await this.store.set(challengeId, { challenge, difficultyBits }, this.ttlMs);
    return { challengeId, challenge, difficultyBits, expiresAt: Date.now() + this.ttlMs };
  }

  async verifySolution({ challengeId, nonce }) {
    const entry = await this.store.get(challengeId);
    if (!entry) return { ok: false, reason: 'unknown_or_already_used_challenge' };
    await this.store.delete(challengeId); // tek kullanımlık -- sonuç ne olursa olsun tüket (replay engeli)

    if (typeof nonce !== 'string' || nonce.length === 0 || nonce.length > 128) {
      return { ok: false, reason: 'malformed_nonce' };
    }

    const digest = crypto.createHash('sha256').update(`${entry.challenge}:${nonce}`).digest();
    const leadingZeroBits = countLeadingZeroBits(digest);
    if (leadingZeroBits < entry.difficultyBits) return { ok: false, reason: 'insufficient_work' };
    return { ok: true };
  }

  _gc() {
    const now = Date.now();
    for (const [id, entry] of this.store.map) if (now > entry.expiresAt) this.store.map.delete(id);
  }

  stop() {
    clearInterval(this._gcTimer);
  }
}

function countLeadingZeroBits(buffer) {
  let count = 0;
  for (const byte of buffer) {
    if (byte === 0) { count += 8; continue; }
    let mask = 0x80;
    while (mask && (byte & mask) === 0) { count++; mask >>= 1; }
    break;
  }
  return count;
}

module.exports = { ProofOfWorkService, countLeadingZeroBits };
