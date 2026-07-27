'use strict';

const crypto = require('node:crypto');

// ============================================================================
// REFERANS KODDA GÖZLEMLENEN SORUN: server.js şifreleri
//   crypto.createHash('sha256').update(req.password).digest('hex')
// ile saklıyor -- SALTSIZ, TEK TUR hızlı hash. Bu şu demek: (1) aynı şifreyi kullanan iki
// kullanıcının hash'i AYNI olur (rainbow table saldırısına doğrudan açık kapı), (2) SHA-256
// saniyede milyarlarca kez hesaplanabilecek kadar HIZLI olduğu için, bir veritabanı sızıntısı
// olması durumunda çevrimdışı (offline) kaba kuvvet çok ucuza mal olur.
//
// BURADA scrypt (node:crypto'da yerleşik, harici bağımlılık YOK) kullanıyoruz: bellek-yoğun
// (memory-hard) bir KDF olduğu için GPU/ASIC ile kaba kuvveti pahalılaştırır, + her hash
// kendi rastgele salt'ını taşır (aynı şifre asla aynı hash'i üretmez).
//
// NOT: Bu proje "parola kullanımını minimize et" talebine uygun olarak parolayı BİRİNCİL
// oturum açma yöntemi yapmıyor -- WebAuthn/TOTP mevcutken parola sadece kurtarma/geriye
// dönük uyumluluk seçeneği. Ama var olduğu her yerde doğru saklanmalı.
// ============================================================================

const KEYLEN = 64;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 }; // ~20-40ms/hash modern donanımda; deploy ortamına göre ayarlayın

function hash(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, KEYLEN, SCRYPT_PARAMS);
  return `scrypt$${SCRYPT_PARAMS.N}$${SCRYPT_PARAMS.r}$${SCRYPT_PARAMS.p}$${salt.toString('base64')}$${derived.toString('base64')}`;
}

function verify(password, stored) {
  if (typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, nStr, rStr, pStr, saltB64, hashB64] = parts;
  const salt = Buffer.from(saltB64, 'base64');
  const expected = Buffer.from(hashB64, 'base64');
  const derived = crypto.scryptSync(password, salt, expected.length, {
    N: Number(nStr), r: Number(rStr), p: Number(pStr),
  });
  return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
}

module.exports = { hash, verify };
