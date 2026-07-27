'use strict';

// RFC 4648 Base32 (TOTP/otpauth:// URI'leri bunu bekler; Google Authenticator, Authy vb.
// hepsi bu alfabeyi kullanır). Node çekirdeğinde base32 yok, bu yüzden minimal ve test
// edilmiş bir implementasyon burada.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function decode(str) {
  const clean = String(str).toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of clean) {
    const idx = ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`base32.decode: geçersiz karakter '${char}'`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

module.exports = { encode, decode };
