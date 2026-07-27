'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const cbor = require('../core/cbor');

function roundTrip(value) {
  const encoded = cbor.encode(value);
  const { value: decoded, bytesRead } = cbor.decode(encoded);
  assert.strictEqual(bytesRead, encoded.length, 'bytesRead tüm buffer ile eşleşmeli');
  return decoded;
}

function main() {
  // basit skalerler
  assert.strictEqual(roundTrip(0), 0);
  assert.strictEqual(roundTrip(23), 23);
  assert.strictEqual(roundTrip(24), 24); // 1-byte length sınırının hemen üstü
  assert.strictEqual(roundTrip(255), 255);
  assert.strictEqual(roundTrip(256), 256);
  assert.strictEqual(roundTrip(65536), 65536);
  assert.strictEqual(roundTrip(-1), -1);
  assert.strictEqual(roundTrip(-7), -7); // COSE ES256 alg değeri
  assert.strictEqual(roundTrip(-257), -257); // COSE RS256 alg değeri
  assert.strictEqual(roundTrip(true), true);
  assert.strictEqual(roundTrip(false), false);
  assert.strictEqual(roundTrip(null), null);
  assert.strictEqual(roundTrip('merhaba dünya'), 'merhaba dünya');
  console.log('cbor: skaler değerler (int/negint/bool/null/string) OK');

  // byte string
  const randomBytes = crypto.randomBytes(300); // 1-byte length sınırını (23) aşacak kadar uzun
  const decodedBytes = roundTrip(randomBytes);
  assert.ok(Buffer.isBuffer(decodedBytes));
  assert.strictEqual(Buffer.compare(decodedBytes, randomBytes), 0);
  console.log('cbor: byte string (>255 byte, çok-byte length prefix) OK');

  // array
  const arr = [1, -2, 'x', Buffer.from([1, 2, 3]), [true, false]];
  const decodedArr = roundTrip(arr);
  assert.strictEqual(decodedArr.length, arr.length);
  assert.strictEqual(decodedArr[0], 1);
  assert.strictEqual(decodedArr[1], -2);
  assert.strictEqual(decodedArr[2], 'x');
  assert.strictEqual(Buffer.compare(decodedArr[3], arr[3]), 0);
  console.log('cbor: array (karışık tipli, iç içe) OK');

  // GERÇEK ŞEKİLLİ bir COSE_Key map'i: EC2/P-256, negatif tamsayı anahtarlarla (-1,-2,-3)
  // -- WebAuthn'ın authData içine gömdüğü yapı tam olarak bu.
  const x = crypto.randomBytes(32);
  const y = crypto.randomBytes(32);
  const coseKey = new Map([
    [1, 2],   // kty: EC2
    [3, -7],  // alg: ES256
    [-1, 1],  // crv: P-256
    [-2, x],
    [-3, y],
  ]);
  const decodedCose = roundTrip(coseKey);
  assert.ok(decodedCose instanceof Map);
  assert.strictEqual(decodedCose.get(1), 2);
  assert.strictEqual(decodedCose.get(3), -7);
  assert.strictEqual(decodedCose.get(-1), 1);
  assert.strictEqual(Buffer.compare(decodedCose.get(-2), x), 0);
  assert.strictEqual(Buffer.compare(decodedCose.get(-3), y), 0);
  console.log('cbor: gerçek şekilli COSE_Key map (negatif int anahtarlar) OK');

  // attestationObject şeklinde iç içe map (fmt/attStmt/authData) -- fonksiyonel test
  const attObj = new Map([
    ['fmt', 'none'],
    ['attStmt', new Map()],
    ['authData', crypto.randomBytes(196)],
  ]);
  const decodedAttObj = roundTrip(attObj);
  assert.strictEqual(decodedAttObj.get('fmt'), 'none');
  assert.strictEqual(decodedAttObj.get('attStmt').size, 0);
  assert.strictEqual(decodedAttObj.get('authData').length, 196);
  console.log('cbor: attestationObject şekilli iç içe map OK');

  // bozuk/eksik veri güvenli şekilde hata fırlatmalı, sessizce yanlış sonuç üretmemeli
  assert.throws(() => cbor.decode(Buffer.from([0xa1])), /erken bitti/); // map header var, içerik yok
  console.log('cbor: eksik veri güvenli şekilde hata fırlatıyor (sessiz bozulma yok)');

  console.log('\nALL CBOR CHECKS PASSED');
}

main();
