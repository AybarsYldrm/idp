'use strict';

// ============================================================================
// REFERANS KODDA GÖZLEMLENEN BOŞLUK: server.js'teki enforceLoginRateLimit/
// recordFailedLoginAttempt SADECE `${username}:${remoteAddress}` bileşik anahtarıyla
// çalışıyor. Bu, bir saldırganın TEK bir IP'den YÜZLERCE farklı kullanıcı adı deneyerek
// (credential stuffing) bu limiti hiç görmeden geçebileceği anlamına gelir -- her
// (kullanıcıadı, IP) çifti kendi başına limitin altında kalır. Aşağıdaki tasarım aynı anda
// BAĞIMSIZ birden fazla eksende sayaç tutarak bunu kapatıyor: salt IP (kullanıcı adından
// bağımsız hacim), salt kullanıcı adı (dağıtık/botnet IP'lerinden gelen saldırı), salt
// fingerprint, ve ikili (IP+kullanıcı adı) kombinasyonu.
// ============================================================================

class SlidingWindowCounter {
  constructor({ windowMs, max }) {
    this.windowMs = windowMs;
    this.max = max;
    this.hits = new Map(); // key -> timestamp[]
  }

  hit(key) {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const fresh = (this.hits.get(key) || []).filter((t) => t > cutoff);
    fresh.push(now);
    this.hits.set(key, fresh);
    return { count: fresh.length, limited: fresh.length > this.max };
  }

  peek(key) {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    return (this.hits.get(key) || []).filter((t) => t > cutoff).length;
  }

  reset(key) {
    this.hits.delete(key);
  }
}

class LoginProtection {
  constructor({
    perIp = { windowMs: 60_000, max: 30 },
    perUsername = { windowMs: 60_000, max: 8 },
    perFingerprint = { windowMs: 60_000, max: 15 },
    perIpUsername = { windowMs: 300_000, max: 5 },
    // Başarısız denemeler arttıkça kilit süresi kademeli olarak uzar (ilk birkaç yanlış
    // şifre/typo için anında kilitlemiyoruz -- sadece ısrarlı başarısızlıkta).
    lockoutEscalationMs = [60_000, 5 * 60_000, 30 * 60_000, 6 * 60 * 60_000],
  } = {}) {
    this.ip = new SlidingWindowCounter(perIp);
    this.username = new SlidingWindowCounter(perUsername);
    this.fingerprint = new SlidingWindowCounter(perFingerprint);
    this.ipUsername = new SlidingWindowCounter(perIpUsername);
    this.lockoutEscalationMs = lockoutEscalationMs;
    this.violationTier = new Map(); // username -> tier index
    this.lockedUntil = new Map(); // username -> timestamp
  }

  isLockedOut(username) {
    const until = this.lockedUntil.get(username);
    return !!(until && Date.now() < until);
  }

  lockoutRemainingMs(username) {
    const until = this.lockedUntil.get(username);
    return until ? Math.max(0, until - Date.now()) : 0;
  }

  recordAttempt({ ip, username, fingerprintId }) {
    const results = {
      ip: this.ip.hit(ip || 'unknown'),
      username: username ? this.username.hit(username) : { limited: false, count: 0 },
      fingerprint: fingerprintId ? this.fingerprint.hit(fingerprintId) : { limited: false, count: 0 },
      ipUsername: username ? this.ipUsername.hit(`${ip || 'unknown'}|${username}`) : { limited: false, count: 0 },
    };
    const limited = results.ip.limited || results.username.limited || results.fingerprint.limited || results.ipUsername.limited;
    return { limited, results };
  }

  recordFailure(username) {
    if (!username) return;
    const tier = Math.min((this.violationTier.get(username) || 0) + 1, this.lockoutEscalationMs.length - 1);
    this.violationTier.set(username, tier);
    if (tier >= 2) { // ilk 1-2 hatada kilitleme (typo toleransı), sonra kademeli kilit
      this.lockedUntil.set(username, Date.now() + this.lockoutEscalationMs[tier]);
    }
  }

  recordSuccess(username) {
    if (!username) return;
    this.violationTier.delete(username);
    this.lockedUntil.delete(username);
  }

  // Şüpheli hacim/düşük güven skoruna göre PoW zorluğunu ADAPTİF olarak yükseltir --
  // dürüst kullanıcılar için sabit/düşük zorluk, şüpheli trafik için katlanarak artan maliyet.
  recommendedPowDifficultyBits({ ip, fingerprintTrust = 0.5 }) {
    const recentIpHits = this.ip.peek(ip || 'unknown');
    let bits = 18;
    if (recentIpHits > 10) bits += 4;
    if (recentIpHits > 20) bits += 4;
    if (fingerprintTrust < 0.3) bits += 4;
    return Math.min(bits, 28); // üst sınır -- meşru kullanıcıyı asla makul olmayan sürede bekletme
  }
}

module.exports = { SlidingWindowCounter, LoginProtection };
