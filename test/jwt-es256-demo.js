'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const jwt = require('../core/jwt-es256');
const { loadOrCreateSigningKeyPair } = require('../core/keys');
const fsp = require('node:fs/promises');
const path = require('node:path');

async function main() {
  const keyDir = path.join(__dirname, '..', '.tmp-jwt-demo-keys');
  await fsp.rm(keyDir, { recursive: true, force: true });
  const { privateKey, publicKey, kid } = loadOrCreateSigningKeyPair(keyDir);
  console.log('ES256 anahtar çifti üretildi/yüklendi, kid =', kid);

  // reload'da AYNI anahtarların döndüğünü doğrula (persistans çalışıyor mu)
  const reloaded = loadOrCreateSigningKeyPair(keyDir);
  assert.strictEqual(reloaded.kid, kid);
  assert.strictEqual(
    reloaded.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  );
  console.log('anahtar kalıcılığı (loadOrCreate ikinci çağrıda aynı anahtarı döndürüyor) OK');

  // temel sign/verify
  const token = jwt.sign({ sub: 'user-123', scope: 'openid profile' }, privateKey, { kid, expiresInSeconds: 600 });
  assert.strictEqual(token.split('.').length, 3);
  const { header, payload } = jwt.verify(token, publicKey);
  assert.strictEqual(header.alg, 'ES256');
  assert.strictEqual(header.kid, kid);
  assert.strictEqual(payload.sub, 'user-123');
  assert.strictEqual(payload.scope, 'openid profile');
  assert.ok(typeof payload.iat === 'number' && typeof payload.exp === 'number');
  console.log('jwt: temel sign/verify OK, header/payload doğru');

  // kid-resolver ile doğrulama (JWKS'te birden çok anahtar simülasyonu)
  const { payload: p2 } = jwt.verify(token, (hdr) => (hdr.kid === kid ? publicKey : null));
  assert.strictEqual(p2.sub, 'user-123');
  console.log('jwt: kid-tabanlı anahtar seçici (resolver) OK');

  // yanlış public key ile doğrulama BAŞARISIZ olmalı
  const otherKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  assert.throws(() => jwt.verify(token, otherKeyPair.publicKey), /imza doğrulaması başarısız/);
  console.log('jwt: yanlış public key ile doğrulama doğru şekilde reddediliyor');

  // payload kurcalama (tamper) tespit edilmeli -- imza artık signing input ile eşleşmez
  const [h, , s] = token.split('.');
  const forgedPayload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 0, exp: 9999999999 })).toString('base64url');
  // base64url encode'u projenin kendi modülüyle tutarlı üretelim (Buffer'ın yerleşik
  // base64url'i olsa da olmasa da aynı çıktı):
  const base64url = require('../core/base64url');
  const forgedPayloadB64 = base64url.encode(Buffer.from(JSON.stringify({ sub: 'admin', iat: 0, exp: 9999999999 })));
  const forgedToken = `${h}.${forgedPayloadB64}.${s}`;
  assert.throws(() => jwt.verify(forgedToken, publicKey), /imza doğrulaması başarısız/);
  console.log('jwt: payload kurcalama (imza korunarak claim değiştirme) doğru şekilde reddediliyor');

  // süresi dolmuş token reddedilmeli
  const expiredToken = jwt.sign({ sub: 'user-123' }, privateKey, { kid, expiresInSeconds: -10 });
  assert.throws(() => jwt.verify(expiredToken, publicKey), /süresi dolmuş/);
  console.log('jwt: süresi dolmuş token doğru şekilde reddediliyor');

  // DER<->JOSE dönüşümünü rastgele veriler üzerinde ayrı ayrı da doğrulayalım (100 tekrar,
  // her seferinde farklı R/S uzunlukları -- yüksek bit bazen 1 bazen 0 olacak şekilde --
  // çıkabilsin diye çok sayıda deniyoruz)
  for (let i = 0; i < 100; i++) {
    const data = crypto.randomBytes(32);
    const t = jwt.sign({ n: i, data: data.toString('hex') }, privateKey, { kid });
    const { payload } = jwt.verify(t, publicKey);
    assert.strictEqual(payload.n, i);
  }
  console.log('jwt: 100 tekrarlı sign/verify (DER<->JOSE dönüşümü farklı R/S uzunluklarında) OK');

  console.log('\nALL JWT-ES256 CHECKS PASSED');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
