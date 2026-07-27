'use strict';

const zlib = require('node:zlib');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createMockDb } = require('./mock-db');
const { SessionManager } = require('../core/session-manager');
const { loadOrCreateSigningKeyPair } = require('../core/keys');
const authService = require('../services/auth-service');
const profileService = require('../services/profile-service');
const { crc32 } = require('../core/image-guard');

// Kullanıcının kendi hesabı üzerindeki hakları.

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

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
function pngChunk(type, data) {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'ascii');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}
function makePng(w, h) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 6;
  const raw = Buffer.alloc(h * (1 + w * 4), 0x40);
  for (let y = 0; y < h; y++) raw[y * (1 + w * 4)] = 0;
  return Buffer.concat([
    PNG_MAGIC, pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(raw)), pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

async function main() {
  const keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'profile-'));
  const db = createMockDb([
    'users', 'sessions', 'refresh_tokens', 'user_devices', 'user_profiles',
    'webauthn_credentials', 'totp_credentials', 'certificates',
  ]);
  const ephemeral = makeStore();
  authService.configureEphemeralStore(ephemeral);
  const sessionManager = new SessionManager({
    store: authService.createSessionStoreAdapter(db),
    signingKeyPair: loadOrCreateSigningKeyPair(keyDir),
    issuer: 'https://session.fitfak.net', cookieDomain: '.fitfak.net',
  });

  const userId = await db.collection('users').insert({
    username: 'aybars', email: 'a@fitfak.net', status: 'active', emailVerified: true,
    mfaMethods: '[]', createdAt: BigInt(Date.now()),
  });

  console.log('\n[1] Profil ilk erişimde oluşturuluyor');
  const p0 = await profileService.getProfile({ db, userId });
  check('profil döndü', p0.username === 'aybars');
  check('avatar yok', p0.hasAvatar === false);
  check('güvenlik bildirimleri kapatılamaz olarak işaretli', p0.notifications.securityLocked === true);
  check('cihaz uyarısı varsayılan AÇIK', p0.notifications.newDevice === true);
  check('ürün duyuruları varsayılan KAPALI', p0.notifications.product === false);

  console.log('\n[2] Profil güncelleme ve doğrulama');
  const p1 = await profileService.updateProfile({
    db, userId, displayName: 'Aybars Yıldırım', bio: 'Merhaba', locale: 'tr-TR', timezone: 'Europe/Istanbul',
  });
  check('ad kaydedildi', p1.displayName === 'Aybars Yıldırım');

  let tooLong = false;
  try { await profileService.updateProfile({ db, userId, displayName: 'x'.repeat(100) }); }
  catch (e) { tooLong = e.code === 'invalid_argument'; }
  check('çok uzun ad reddedildi', tooLong);

  let badTz = false;
  try { await profileService.updateProfile({ db, userId, timezone: 'Mars/Olympus' }); }
  catch (e) { badTz = e.code === 'invalid_argument'; }
  check('geçersiz zaman dilimi reddedildi', badTz);

  let badLocale = false;
  try { await profileService.updateProfile({ db, userId, locale: 'xx-XX' }); }
  catch (e) { badLocale = e.code === 'invalid_argument'; }
  check('desteklenmeyen dil reddedildi', badLocale);

  // U+202E (right-to-left override) adı ters gösterir; bir kullanıcının
  // başka biri gibi görünmesi için kullanılır.
  const spoofed = await profileService.updateProfile({ db, userId, displayName: 'admin‮gpj.exe' });
  check('yön değiştiren karakter temizlendi', !spoofed.displayName.includes('‮'));

  console.log('\n[3] Avatar');
  const avatar = await profileService.setAvatar({ db, userId, bytes: makePng(128, 128) });
  check('avatar kabul edildi', avatar.width === 128 && avatar.height === 128);
  check('etag üretildi', avatar.etag.length === 64);
  const stored = await profileService.getAvatar({ db, userId });
  check('avatar okunabiliyor', stored.bytes.length > 0);
  check('content-type baytlardan', stored.contentType === 'image/png');

  let rejected = false;
  try { await profileService.setAvatar({ db, userId, bytes: makePng(300, 300) }); }
  catch (e) { rejected = e.code === 'image_rejected'; }
  check('256\'dan büyük avatar reddedildi', rejected);

  let svgRejected = false;
  try { await profileService.setAvatar({ db, userId, bytes: Buffer.from('<svg onload=alert(1)>') }); }
  catch (e) { svgRejected = e.code === 'image_rejected'; }
  check('SVG reddedildi', svgRejected);

  const p2 = await profileService.getProfile({ db, userId });
  check('profil avatar URL\'i veriyor', !!p2.avatarUrl && p2.hasAvatar === true);
  await profileService.deleteAvatar({ db, userId });
  check('avatar silinebiliyor', (await profileService.getAvatar({ db, userId })) === null);

  console.log('\n[4] E-posta tercihleri');
  const prefs = await profileService.updateNotificationPreferences({
    db, userId, product: true, newsletter: true, newDevice: false,
  });
  check('ürün duyuruları açıldı', prefs.notifications.product === true);
  check('cihaz uyarısı kapatılabildi', prefs.notifications.newDevice === false);
  check('güvenlik uyarıları hâlâ kilitli', prefs.notifications.securityLocked === true);
  check('güvenlik uyarıları hâlâ açık', prefs.notifications.security === true);

  console.log('\n[5] Hesap silme onay gerektiriyor');
  await db.collection('user_devices').insert({
    userDeviceKey: `${userId}:d1`, userId: String(userId), deviceId: 'd1',
    firstSeenAt: 0n, lastSeenAt: 0n, firstIp: '', lastIp: '', userAgent: '', label: 'x',
    trusted: false, loginCount: 1n,
  });
  await db.collection('certificates').insert({
    serialNumberHex: 'abcd01', userId: String(userId), subjectCn: 'aybars', profile: 'client-auth',
    certPem: '', notBefore: 0n, notAfter: 0n, status: 'valid', revokedAt: 0n,
    revocationReason: '', createdAt: 0n, issuedVia: 'test', skidHex: 'ff01',
  });
  const session = await sessionManager.createSession({ userId, ip: '1.2.3.4', userAgent: 'x', deviceId: 'd1' });

  const req = await profileService.requestAccountDeletion({
    db, userId, mailer: null, ephemeralStore: ephemeral,
  });
  check('onay isteniyor', req.requiresConfirmation === true);

  let wrongCode = false;
  try {
    await profileService.confirmAccountDeletion({
      db, userId, code: '000000', ephemeralStore: ephemeral, sessionManager,
    });
  } catch (e) { wrongCode = e.code === 'invalid_code'; }
  check('yanlış kod reddedildi', wrongCode);

  // Kod doğrulamadan ÖNCE tüketildiği için ikinci deneme de reddedilir --
  // 6 haneli bir kod aksi halde denenerek kırılabilirdi.
  let secondTry = false;
  try {
    await profileService.confirmAccountDeletion({
      db, userId, code: '111111', ephemeralStore: ephemeral, sessionManager,
    });
  } catch (e) { secondTry = e.code === 'invalid_code'; }
  check('kod tek kullanımlık (deneme yapılamıyor)', secondTry);

  console.log('\n[6] Silme gerçekten siliyor');
  await profileService.requestAccountDeletion({ db, userId, mailer: null, ephemeralStore: ephemeral });
  const pending = JSON.parse(await ephemeral.get(`delete:${userId}`));
  const result = await profileService.confirmAccountDeletion({
    db, userId, code: pending.code, ephemeralStore: ephemeral, sessionManager,
  });
  check('silme tamamlandı', result.deleted === true);
  check('kullanıcı kaydı gitti', (await db.collection('users').get(userId)) === null);
  check('profil gitti', (await db.collection('user_profiles').findOne('userId', String(userId))) === null);
  check('cihaz kayıtları gitti', result.devices >= 1);
  check('oturum silindi', result.sessions >= 1);
  check('oturum artık çözümlenmiyor',
    (await sessionManager.store.getSessionById(session.sessionId)) === null);

  console.log('\n[7] Sertifikalar silinmiyor, İPTAL EDİLİYOR');
  // Kaydı silmek sertifikayı geçersiz kılmaz -- OCSP onu 'unknown' sayardı,
  // yani doğrulayan taraf iptal edildiğini ÖĞRENEMEZDİ.
  check('iptal edilen sertifika sayısı raporlandı', result.certificatesRevoked === 1);
  const cert = await db.collection('certificates').findOne('serialNumberHex', 'abcd01');
  check('sertifika kaydı DURUYOR', !!cert);
  check('durumu revoked', cert.status === 'revoked');
  check('iptal sebebi kaydedildi', cert.revocationReason === 'cessationOfOperation');

  fs.rmSync(keyDir, { recursive: true, force: true });
  console.log(`\nOK - profil ve hesap hakları: ${checks} kontrol geçti.`);
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
