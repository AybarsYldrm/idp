'use strict';

// Node'un yerleşik 'base64url' Buffer encoding'ine bağımlı KALMIYORUZ (bazı ortamlarda
// eski Node sürümleri hâlâ çalışıyor olabilir) -- klasik base64 + karakter değişimi + padding
// temizliği ile taşınabilir, sıfır bağımlılıklı bir uygulama. Tüm proje boyunca (JWT, WebAuthn,
// refresh token, PoW/challenge id'leri) SADECE bu modül kullanılır ki encoding her yerde tutarlı olsun.

function encode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function decode(str) {
  if (typeof str !== 'string') throw new TypeError('base64url.decode: string bekleniyor');
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const rem = b64.length % 4;
  if (rem === 2) b64 += '==';
  else if (rem === 3) b64 += '=';
  else if (rem === 1) throw new Error('base64url.decode: geçersiz uzunluk (padding hesaplanamadı)');
  return Buffer.from(b64, 'base64');
}

module.exports = { encode, decode };
