'use strict';

const crypto = require('node:crypto');
const base32 = require('./base32');

// RFC 4226 (HOTP) dinamik kısaltma (dynamic truncation) algoritması.
function hotp(secretBuffer, counter, { digits = 6, algorithm = 'sha1' } = {}) {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac(algorithm, secretBuffer).update(counterBuf).digest();

  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode = ((hmac[offset] & 0x7f) << 24)
    | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8)
    | (hmac[offset + 3] & 0xff);
  const code = binCode % (10 ** digits);
  return String(code).padStart(digits, '0');
}

// RFC 6238 (TOTP): HOTP'un counter'ı = geçen zaman / adım süresi.
function totp(secretBuffer, { step = 30, digits = 6, algorithm = 'sha1', time = Date.now() } = {}) {
  const counter = Math.floor(time / 1000 / step);
  return hotp(secretBuffer, counter, { digits, algorithm });
}

function generateSecret(byteLength = 20) {
  return crypto.randomBytes(byteLength);
}

// Google Authenticator / Authy vb. her uygulamanın okuyabildiği standart otpauth:// URI.
// NOT: Bu proje QR kod ÇİZMİYOR (bitmap üretimi Reed-Solomon hata düzeltmesi gerektiren
// ayrı ve büyük bir problem -- kapsam dışı bırakıldı, README'de not edildi). Bu URI'yi
// istemci tarafında herhangi bir standart QR kütüphanesiyle (örn. `qrcode` npm paketi)
// çizdirin, ya da kullanıcıya `secret` alanını manuel girmesi için gösterin.
function provisioningUri({ secret, accountName, issuer, digits = 6, step = 30, algorithm = 'SHA1' }) {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({
    secret: base32.encode(secret),
    issuer,
    algorithm,
    digits: String(digits),
    period: String(step),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/**
 * Sürüklenme (clock drift) penceresi içinde bir TOTP kodunu doğrular.
 *
 * REPLAY KORUMASI: `lastUsedCounter` çağıran taraf (services/auth-service.js) tarafından
 * kalıcı olarak saklanmalı ve her başarılı doğrulamadan sonra dönen `newLastUsedCounter`
 * ile güncellenmelidir. Bu olmadan, aynı 30 saniyelik pencere içinde ağdan yakalanan bir
 * kod tekrar tekrar kullanılabilir (klasik TOTP replay açığı -- çoğu kütüphanenin
 * atladığı bir detay).
 */
function verify(secretBuffer, token, {
  step = 30, digits = 6, algorithm = 'sha1', window = 1, time = Date.now(), lastUsedCounter = -1,
} = {}) {
  const tokenStr = String(token).trim();
  if (!/^\d+$/.test(tokenStr) || tokenStr.length !== digits) {
    return { ok: false, reason: 'malformed_token' };
  }
  const currentCounter = Math.floor(time / 1000 / step);
  for (let drift = -window; drift <= window; drift++) {
    const counter = currentCounter + drift;
    if (counter <= lastUsedCounter) continue; // bu adım zaten tüketilmiş (replay girişimi)
    const candidate = hotp(secretBuffer, counter, { digits, algorithm });
    if (timingSafeEqualStrings(candidate, tokenStr)) {
      return { ok: true, newLastUsedCounter: counter };
    }
  }
  return { ok: false, reason: 'no_match' };
}

function timingSafeEqualStrings(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = { hotp, totp, generateSecret, provisioningUri, verify };
