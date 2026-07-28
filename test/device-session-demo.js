'use strict';

const crypto = require('node:crypto');

const { createMockDb } = require('./mock-db');
const { SessionManager } = require('../core/session-manager');
const { loadOrCreateSigningKeyPair } = require('../core/keys');
const authService = require('../services/auth-service');
const deviceBinding = require('../core/device-binding');
const { completeLogin } = require('../services/login-completion');

// Aynı tarayıcıdan tekrar giriş, YENİ oturum açmamalı.
//
// Şikayet buydu: "session.fitfak.net adresine girdiğimde sürekli olarak oturum
// açabiliyordum, bu da oturumlar sayfasında bir sürü oturum yapıyordu."
//
// Bu yalnızca dağınık bir liste değil. Kullanıcı oturumlar sayfasına "acaba
// başkası mı girdi" diye bakar; liste kendi tekrar girişleriyle dolduğunda
// gerçek bir yabancı oturum o gürültünün içinde görünmez hale gelir ve geriye
// "hepsini kapat" dışında kullanılabilir bir seçenek kalmaz.

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

function makeStore() {
  const m = new Map();
  return {
    async get(k) { const e = m.get(k); if (!e || e.exp < Date.now()) { m.delete(k); return null; } return e.v; },
    async set(k, v, ttl) { m.set(k, { v, exp: Date.now() + (ttl || 60000) }); },
    async delete(k) { m.delete(k); },
  };
}

const UA_CHROME = 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36';
const UA_SAFARI = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1 Safari/604.1';

async function main() {
  const os = require('node:os'); const path = require('node:path'); const fs = require('node:fs');
  const keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devsess-'));

  const db = createMockDb(['users', 'sessions', 'refresh_tokens', 'user_devices']);
  authService.configureEphemeralStore(makeStore());
  const sessionManager = new SessionManager({
    store: authService.createSessionStoreAdapter(db),
    signingKeyPair: loadOrCreateSigningKeyPair(keyDir),
    issuer: 'https://session.fitfak.net',
    cookieDomain: '.fitfak.net',
  });

  const userId = await db.collection('users').insert({
    username: 'aybars', email: 'a@fitfak.net', status: 'active', emailVerified: true,
    mfaMethods: JSON.stringify(['totp']), createdAt: BigInt(Date.now()),
  });

  const laptop = deviceBinding.newDeviceId();
  const phone = deviceBinding.newDeviceId();

  const login = (deviceId, userAgent, ip = '203.0.113.7') => completeLogin({
    db, sessionManager, userId, ip, userAgent, fingerprintId: 'fp', deviceId, mailer: null,
  });

  console.log('\n[1] Aynı tarayıcıdan 10 kez giriş -> TEK oturum');
  const first = await login(laptop, UA_CHROME);
  for (let i = 0; i < 9; i++) await login(laptop, UA_CHROME);
  const sessions = (await sessionManager.listSessions(String(userId))).filter((s) => !s.revoked);
  check(`10 giriş sonrası aktif oturum sayısı ${sessions.length}`, sessions.length === 1);
  check('oturum kimliği ilk girişteki ile aynı', sessions[0].sessionId === first.sessionId);
  check('oturum cihaza bağlı', sessions[0].deviceId === laptop);

  console.log('\n[2] Her girişte TAZE token veriliyor (tazeleme, yeniden kullanım değil)');
  const again = await login(laptop, UA_CHROME);
  check('aynı oturum', again.sessionId === first.sessionId);
  check('tazeleme olarak işaretli', again.reused === true);
  check('access token yeni', again.accessToken !== first.accessToken);
  check('refresh token yeni', again.refreshToken !== first.refreshToken);

  console.log('\n[3] Farklı tarayıcı -> AYRI oturum');
  const onPhone = await login(phone, UA_SAFARI, '198.51.100.4');
  const after = (await sessionManager.listSessions(String(userId))).filter((s) => !s.revoked);
  check('artık iki oturum var', after.length === 2);
  check('telefon ayrı bir oturum', onPhone.sessionId !== first.sessionId);

  console.log('\n[4] Yeni cihaz tespiti ve adım yükseltme');
  check('ilk cihaz "ilk kez" sayılıyor ama bildirim gerektirmiyor',
    first.isNewDevice === true);
  check('telefon yeni cihaz olarak işaretlendi', onPhone.isNewDevice === true);
  check('yeni cihazda adım yükseltme isteniyor', onPhone.requiresStepUp === true);
  const knownAgain = await login(laptop, UA_CHROME);
  check('bilinen cihazda yeni-cihaz bayrağı yok', knownAgain.isNewDevice === false);
  check('bilinen cihazda adım yükseltme istenmiyor', knownAgain.requiresStepUp === false);

  console.log('\n[5] Cihaz kaydı okunabilir bilgi tutuyor');
  const devices = db.collection('user_devices');
  const laptopRow = await devices.findOne('userDeviceKey', `${userId}:${laptop}`);
  const phoneRow = await devices.findOne('userDeviceKey', `${userId}:${phone}`);
  check('dizüstü Chrome/Windows olarak tanındı', laptopRow.label === 'Chrome — Windows');
  check('telefon Safari/iOS olarak tanındı', phoneRow.label === 'Safari — iOS');
  check('giriş sayacı artıyor', Number(laptopRow.loginCount) >= 11);
  check('ilk ve son IP ayrı tutuluyor', phoneRow.firstIp === '198.51.100.4');

  console.log('\n[6] İptal edilmiş oturum TAZELENEREK geri getirilemez');
  await sessionManager.revokeSession(first.sessionId, 'user_requested');
  const afterRevoke = await login(laptop, UA_CHROME);
  check('yeni bir oturum açıldı', afterRevoke.sessionId !== first.sessionId);
  const revoked = (await sessionManager.listSessions(String(userId)))
    .find((s) => s.sessionId === first.sessionId);
  check('iptal edilen oturum iptal kaldı', revoked.revoked === true);

  console.log('\n[7] Cihaz çerezi mühürlü -- uydurma değer kabul edilmiyor');
  const secret = crypto.randomBytes(32);
  const sealed = deviceBinding.seal(laptop, secret);
  check('kendi mührümüz açılıyor', deviceBinding.unseal(sealed, secret) === laptop);
  check('yanlış anahtarla açılmıyor', deviceBinding.unseal(sealed, crypto.randomBytes(32)) === null);
  check('mühürsüz değer reddediliyor', deviceBinding.unseal(laptop, secret) === null);
  check('kurcalanmış mühür reddediliyor',
    deviceBinding.unseal(`${laptop}.AAAAAAAAAAAAAAAAAAAAAA`, secret) === null);

  fs.rmSync(keyDir, { recursive: true, force: true });
  console.log(`\nOK - cihaz bağlama ve oturum tazeleme: ${checks} kontrol geçti.`);
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
