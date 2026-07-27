'use strict';

const assert = require('node:assert');
const totp = require('../core/totp');

function main() {
  // RFC 4226 Appendix D resmi HOTP test vektörleri.
  // Secret = ASCII "12345678901234567890" (20 byte), SHA-1, 6 hane.
  const secret = Buffer.from('12345678901234567890', 'ascii');
  const expected = [
    '755224', '287082', '359152', '969429', '338314',
    '254676', '287922', '162583', '399871', '520489',
  ];
  for (let counter = 0; counter < expected.length; counter++) {
    const code = totp.hotp(secret, counter, { digits: 6, algorithm: 'sha1' });
    assert.strictEqual(code, expected[counter], `counter=${counter}: got ${code}, beklenen ${expected[counter]}`);
  }
  console.log('hotp: RFC 4226 Appendix D resmi test vektörlerinin TAMAMI eşleşti (counter 0-9)');

  // TOTP = HOTP(counter = floor(time / step)) -- doğrudan sarma (wrapping) doğrulaması
  const t = 59_000; // ms -> counter = floor(59/30) = 1
  const code = totp.totp(secret, { time: t, step: 30, digits: 6 });
  assert.strictEqual(code, totp.hotp(secret, 1, { digits: 6 }));
  console.log('totp: zaman->counter sarma mantığı doğru (T=59s -> counter=1)');

  // verify(): doğru kod, drift penceresi, ve replay reddi
  const mySecret = totp.generateSecret();
  const now = Date.now();
  const currentCode = totp.totp(mySecret, { time: now });

  const r1 = totp.verify(mySecret, currentCode, { time: now });
  assert.strictEqual(r1.ok, true);
  console.log('verify: geçerli kod kabul edildi, newLastUsedCounter =', r1.newLastUsedCounter);

  // AYNI kod, AYNI (veya daha yeni olmayan) counter ile TEKRAR sunulursa reddedilmeli (replay)
  const r2 = totp.verify(mySecret, currentCode, { time: now, lastUsedCounter: r1.newLastUsedCounter });
  assert.strictEqual(r2.ok, false);
  assert.strictEqual(r2.reason, 'no_match');
  console.log('verify: aynı kodun tekrar sunulması (replay) doğru şekilde reddedildi');

  // bir sonraki adımdaki kod (30sn sonrası) hâlâ kabul edilmeli (pencere içindeyse)
  const nextStepCode = totp.totp(mySecret, { time: now + 30_000 });
  const r3 = totp.verify(mySecret, nextStepCode, { time: now + 30_000, lastUsedCounter: r1.newLastUsedCounter });
  assert.strictEqual(r3.ok, true);
  console.log('verify: bir sonraki zaman adımındaki kod (drift içinde) kabul edildi');

  // pencerenin çok dışındaki bir kod (örn. 5 dakika önceki) reddedilmeli
  const farOldCode = totp.totp(mySecret, { time: now - 5 * 60_000 });
  const r4 = totp.verify(mySecret, farOldCode, { time: now });
  assert.strictEqual(r4.ok, false);
  console.log('verify: drift penceresinin çok dışındaki kod doğru şekilde reddedildi');

  // yanlış uzunlukta / sayısal olmayan token güvenli şekilde reddedilmeli (throw değil)
  assert.strictEqual(totp.verify(mySecret, '12', { time: now }).ok, false);
  assert.strictEqual(totp.verify(mySecret, 'abcdef', { time: now }).ok, false);
  console.log('verify: bozuk/geçersiz format token güvenli şekilde reddedildi');

  // provisioning URI şeklen doğru mu (otpauth:// + gerekli parametreler)
  const uri = totp.provisioningUri({ secret: mySecret, accountName: 'abuzer@fitfak.net', issuer: 'Fitfak Kimlik' });
  assert.ok(uri.startsWith('otpauth://totp/'));
  assert.ok(uri.includes('issuer=Fitfak'));
  assert.ok(uri.includes('digits=6'));
  assert.ok(uri.includes('period=30'));
  console.log('provisioningUri: otpauth:// URI doğru şekilde oluşturuldu ->', uri);

  console.log('\nALL TOTP CHECKS PASSED');
}

main();
