'use strict';

const path = require('node:path');
const crypto = require('node:crypto');

const { createMockDb } = require('./mock-db');
const serverSrp = require('../core/srp');
const srpAuth = require('../services/srp-auth-service');

require(path.join(__dirname, '..', 'public', 'srp-client.js'));
const browserSrp = globalThis.FitfakSrp;

// Uç noktaların kendisi: iki adımlı SRP, durumsuz HTTP üzerinde.
//
// Kripto çekirdeği ayrıca test ediliyor (srp-demo.js); burada test edilen şey
// akışın DURUM yönetimi -- ki iki adımlı bir protokolü HTTP'ye oturtmanın asıl
// zor kısmı odur.

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

function makeStore() {
  const m = new Map();
  return {
    async get(k) {
      const e = m.get(k);
      if (!e) return null;
      if (e.expiresAt < Date.now()) { m.delete(k); return null; }
      return e.value;
    },
    async set(k, v, ttl) { m.set(k, { value: v, expiresAt: Date.now() + (ttl || 60000) }); },
    async delete(k) { m.delete(k); },
    size: () => m.size,
  };
}

const config = { db: { rootSecret: crypto.randomBytes(32) } };

async function main() {
  const db = createMockDb(['users']);
  const store = makeStore();
  const password = 'CorrectHorseBatteryStaple1!';
  const email = 'aybars@fitfak.net';

  console.log('\n[1] Kayıt: doğrulayıcı tarayıcıda üretilir');
  const reg = await browserSrp.createVerifier(password);
  const userId = await db.collection('users').insert({
    username: 'aybars', email, status: 'active', emailVerified: true,
    mfaMethods: JSON.stringify(['totp']), createdAt: BigInt(Date.now()),
    passwordHash: 'eski-scrypt-degeri',
  });
  await srpAuth.setSrpCredentials({ db, userId, saltB64: reg.saltB64, verifierB64: reg.verifier });
  const stored = await db.collection('users').get(userId);
  check('doğrulayıcı saklandı', stored.srpVerifier === reg.verifier);
  check('eski parola hash\'i temizlendi', stored.passwordHash === '');

  console.log('\n[2] Doğru parola ile giriş: parola telde yok');
  const client = new browserSrp.SrpClient({ identity: email, password });
  const begin = await srpAuth.beginSrpLogin({ db, store, config, identity: email });
  const proof = await client.respond(begin);
  const finish = await srpAuth.finishSrpLogin({
    db, store, stateId: begin.stateId, A: client.start().A, M1: proof.M1,
  });
  check('sunucu M1 kanıtını kabul etti', !!finish.M2);
  check('doğru kullanıcıya çözümlendi', String(finish.userId) === String(userId));
  await client.verifyServer({ M2: finish.M2 });
  check('istemci sunucunun M2 kanıtını doğruladı', true);
  check('parola hiçbir istekte yok',
    !JSON.stringify([begin, proof, finish]).includes(password));

  console.log('\n[3] Parola tek başına oturum vermez');
  check('ikinci faktör isteniyor', finish.requiresSecondFactor !== false);

  console.log('\n[4] Durum tek kullanımlık');
  // Aynı challenge'a karşı tekrar denemek, çevrimiçi sözlük saldırısının
  // istediği şeydir; ilk kullanımda tüketiliyor.
  let replayed = false;
  try {
    await srpAuth.finishSrpLogin({ db, store, stateId: begin.stateId, A: client.start().A, M1: proof.M1 });
  } catch (e) { replayed = e.code === 'auth_failed'; }
  check('aynı stateId ikinci kez kullanılamaz', replayed);

  console.log('\n[5] Yanlış parola');
  const bad = new browserSrp.SrpClient({ identity: email, password: 'YanlisParola123!' });
  const begin2 = await srpAuth.beginSrpLogin({ db, store, config, identity: email });
  const badProof = await bad.respond(begin2);
  let rejected = false;
  try {
    await srpAuth.finishSrpLogin({ db, store, stateId: begin2.stateId, A: bad.start().A, M1: badProof.M1 });
  } catch (e) { rejected = e.code === 'auth_failed'; }
  check('yanlış parola reddedildi', rejected);

  console.log('\n[6] Kullanıcı numaralandırması yok');
  const realBegin = await srpAuth.beginSrpLogin({ db, store, config, identity: email });
  const fakeBegin = await srpAuth.beginSrpLogin({ db, store, config, identity: 'yok@fitfak.net' });
  check('var olmayan kullanıcı da challenge alıyor', !!fakeBegin.B && !!fakeBegin.saltB64);
  check('yanıt biçimi ayırt edilemiyor',
    Object.keys(realBegin).sort().join() === Object.keys(fakeBegin).sort().join());
  check('salt uzunlukları aynı',
    Buffer.from(realBegin.saltB64, 'base64').length === Buffer.from(fakeBegin.saltB64, 'base64').length);
  check('B uzunlukları aynı',
    Buffer.from(realBegin.B, 'base64').length === Buffer.from(fakeBegin.B, 'base64').length);

  const fakeBegin2 = await srpAuth.beginSrpLogin({ db, store, config, identity: 'yok@fitfak.net' });
  check('aynı bilinmeyen kullanıcı için salt kararlı', fakeBegin.saltB64 === fakeBegin2.saltB64);

  const ghost = new browserSrp.SrpClient({ identity: 'yok@fitfak.net', password: 'herhangi' });
  const ghostProof = await ghost.respond(fakeBegin);
  let ghostRejected = false;
  try {
    await srpAuth.finishSrpLogin({ db, store, stateId: fakeBegin.stateId, A: ghost.start().A, M1: ghostProof.M1 });
  } catch (e) { ghostRejected = e.code === 'auth_failed'; }
  check('sahte hesaba giriş yapılamaz', ghostRejected);

  console.log('\n[7] Bozuk doğrulayıcı reddedilir');
  let badVerifier = false;
  try {
    await srpAuth.setSrpCredentials({ db, userId, saltB64: reg.saltB64, verifierB64: Buffer.alloc(4).toString('base64') });
  } catch (e) { badVerifier = e.code === 'invalid_request'; }
  check('yanlış boyutlu doğrulayıcı reddedilir', badVerifier);

  console.log(`\nOK - SRP uç noktaları: ${checks} kontrol geçti.`);
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
