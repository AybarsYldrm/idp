'use strict';

const assert = require('node:assert');
const base32 = require('../core/base32');
const base64url = require('../core/base64url');

function main() {
  // RFC 4648 Section 10 resmi test vektörleri (padding'siz karşılaştırıyoruz çünkü
  // TOTP secret'ları için otpauth:// URI'lerinde padding genelde atılır)
  const vectors = [
    ['', ''],
    ['f', 'MY'],
    ['fo', 'MZXQ'],
    ['foo', 'MZXW6'],
    ['foob', 'MZXW6YQ'],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI'],
  ];
  for (const [input, expected] of vectors) {
    const got = base32.encode(Buffer.from(input, 'ascii'));
    assert.strictEqual(got, expected, `base32.encode('${input}') = '${got}', beklenen '${expected}'`);
    const roundTrip = base32.decode(got).toString('ascii');
    assert.strictEqual(roundTrip, input, `base32 round-trip başarısız: '${input}'`);
  }
  console.log('base32: tüm RFC 4648 test vektörleri + round-trip OK');

  // base64url round-trip + URL-unsafe karakter yokluğu (özellikle '+', '/', '=')
  for (let i = 0; i < 50; i++) {
    const len = Math.floor(Math.random() * 40) + 1;
    const buf = require('node:crypto').randomBytes(len);
    const encoded = base64url.encode(buf);
    assert.ok(!/[+/=]/.test(encoded), `base64url çıktısında URL-unsafe karakter: ${encoded}`);
    const decoded = base64url.decode(encoded);
    assert.strictEqual(Buffer.compare(decoded, buf), 0, 'base64url round-trip başarısız');
  }
  console.log('base64url: round-trip + URL-safe karakter kontrolü OK (50 rastgele buffer)');

  console.log('\nALL BASE32/BASE64URL CHECKS PASSED');
}

main();
