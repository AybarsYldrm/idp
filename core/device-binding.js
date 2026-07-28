'use strict';

const crypto = require('node:crypto');
const cookies = require('./cookies');

// Tarayıcı (cihaz) bağlama.
//
// Üç ayrı sorunu tek mekanizma çözüyor, çünkü üçü de aynı eksik bilginin
// sonucu: "bu tarayıcıyı daha önce gördük mü?"
//
// 1. OTURUM ÇOĞALMASI. Her giriş koşulsuz yeni bir oturum satırı yaratıyordu.
//    Aynı tarayıcıdan üst üste giren kullanıcı, oturumlar sayfasında onlarca
//    kayıt görüyordu -- hepsi kendisi. Bu yalnızca çirkin değil, tehlikeli:
//    listede gerçekten şüpheli bir oturum varsa, kendi gürültüsünün içinde
//    kaybolur ve "hepsini kapat" dışında bir seçenek kalmaz.
//
// 2. ADIM YÜKSELTME. Bilinen bir tarayıcıda ikinci faktör her seferinde
//    istenmeyebilir; hiç görülmemiş bir tarayıcıda (gizli sekme, başka cihaz)
//    her zaman istenmeli. Google'ın davranışı budur ve "parolayı bilen ama
//    tarayıcıyı ele geçirmemiş" saldırganı durduran şey de tam olarak budur.
//
// 3. ŞÜPHELİ GİRİŞ BİLDİRİMİ. Yeni bir cihazdan giriş, kullanıcıya haber
//    verilmesi gereken tek olaydır; her girişte e-posta göndermek bildirimleri
//    değersizleştirir ve gerçekten önemli olan kaçırılır.
//
// Cihaz kimliği bir PARMAK İZİ DEĞİLDİR. Parmak izleri tarayıcı güncellemesiyle,
// ekran değişikliğiyle, eklentiyle değişir -- yani aynı tarayıcı zamanla "yeni
// cihaz" gibi görünür ve yukarıdaki üç davranış da bozulur. Bunun yerine
// sunucunun ürettiği rastgele bir değer çerezde taşınır. Parmak izi ise ayrı
// bir sinyal olarak kalır (anti-bot), kimlik olarak değil.

const DEVICE_COOKIE_NAME = '__Secure-fitfak_did';
const DEVICE_COOKIE_TTL_S = 400 * 24 * 60 * 60; // ~13 ay; Chrome çerez üst sınırı 400 gün

/**
 * Cihaz kimliği HMAC ile mühürlenir.
 *
 * Sahte bir değer yazmak kimlik doğrulamayı atlatmaz -- cihaz kimliği yalnızca
 * GRUPLAMA yapar, yetki vermez. Mühür, uydurma değerlerin cihaz kayıtlarını
 * kirletmesini ve bir saldırganın kurbanın cihaz kimliğini tahmin edip "bilinen
 * cihaz" gibi görünmesini engeller.
 */
function seal(deviceId, secret) {
  const mac = crypto.createHmac('sha256', secret).update(deviceId).digest('base64url').slice(0, 22);
  return `${deviceId}.${mac}`;
}

function unseal(value, secret) {
  if (typeof value !== 'string') return null;
  const idx = value.lastIndexOf('.');
  if (idx <= 0) return null;
  const deviceId = value.slice(0, idx);
  const mac = value.slice(idx + 1);
  const expected = crypto.createHmac('sha256', secret).update(deviceId).digest('base64url').slice(0, 22);
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  if (!/^[A-Za-z0-9_-]{22,64}$/.test(deviceId)) return null;
  return deviceId;
}

function newDeviceId() {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * İstekten cihaz kimliğini okur. Yoksa ya da mührü tutmuyorsa yeni bir tane
 * üretir ve `isNew` ile bunu bildirir.
 */
function resolveDevice(req, { secret, parseCookies }) {
  const raw = parseCookies(req)[DEVICE_COOKIE_NAME];
  const existing = unseal(raw, secret);
  if (existing) return { deviceId: existing, isNew: false };
  return { deviceId: newDeviceId(), isNew: true };
}

function buildDeviceCookie(deviceId, { secret, cookieDomain }) {
  return cookies.serializeCookie(DEVICE_COOKIE_NAME, seal(deviceId, secret), {
    domain: cookieDomain,
    path: '/',
    maxAgeSeconds: DEVICE_COOKIE_TTL_S,
    httpOnly: true,
    secure: true,
    // Strict DEĞİL: SSO akışı çapraz-site GET yönlendirmeleriyle döner ve
    // Strict olsaydı dönüşte çerez gönderilmez, her SSO turu tarayıcıyı "yeni
    // cihaz" olarak gösterirdi.
    sameSite: 'Lax',
  });
}

/**
 * Kullanıcı + cihaz kaydı. İlk görülmeyse kaydedilir ve "yeni cihaz" bilgisi
 * döner -- adım yükseltme ve bildirim kararları buna dayanır.
 */
async function recordDevice({ db, userId, deviceId, ip, userAgent }) {
  const devices = db.collection('user_devices');
  const key = `${userId}:${deviceId}`;
  const existing = await devices.findOne('userDeviceKey', key);

  if (existing) {
    await devices.update(existing._id, {
      lastSeenAt: BigInt(Date.now()),
      lastIp: String(ip || ''),
      loginCount: BigInt((existing.loginCount || 0n) + 1n),
    });
    return { isNewDevice: false, device: existing };
  }

  // Kullanıcının HİÇ cihazı yoksa bu, kayıttan sonraki ilk giriştir; onu
  // "şüpheli yeni cihaz" diye bildirmek gürültüden ibaret olur.
  //
  // Sayı değil VARLIK sorgulanıyor: findOne indeksten tek kayıt okur, find()
  // ise eşleşen her cihazı çözerdi -- her giriş için gereksiz iş. (find() ayrıca
  // gömülü motorda var, mock/uzak adaptörde yok; findOne her üçünde de var.)
  const anyPriorDevice = await devices.findOne('userId', String(userId));

  await devices.insert({
    userDeviceKey: key,
    userId: String(userId),
    deviceId,
    firstSeenAt: BigInt(Date.now()),
    lastSeenAt: BigInt(Date.now()),
    firstIp: String(ip || ''),
    lastIp: String(ip || ''),
    userAgent: String(userAgent || '').slice(0, 255),
    label: describeUserAgent(userAgent),
    trusted: false,
    loginCount: 1n,
  });

  return { isNewDevice: true, isFirstEverDevice: !anyPriorDevice, device: null };
}

/**
 * Kullanıcıya gösterilecek okunabilir cihaz adı. User-agent ayrıştırma kesin
 * bir bilim değil ve olmasına gerek de yok -- amaç "bu ben miydim?" sorusuna
 * yardım etmek, envanter tutmak değil.
 */
function describeUserAgent(ua) {
  const s = String(ua || '');
  if (!s) return 'Bilinmeyen cihaz';
  const os = /Windows NT/i.test(s) ? 'Windows'
    : /Android/i.test(s) ? 'Android'
      : /iPhone|iPad|iPod/i.test(s) ? 'iOS'
        : /Mac OS X/i.test(s) ? 'macOS'
          : /Linux/i.test(s) ? 'Linux' : 'Bilinmeyen sistem';
  const browser = /Edg\//i.test(s) ? 'Edge'
    : /OPR\//i.test(s) ? 'Opera'
      : /Chrome\//i.test(s) ? 'Chrome'
        : /Firefox\//i.test(s) ? 'Firefox'
          : /Safari\//i.test(s) ? 'Safari' : 'Bilinmeyen tarayıcı';
  return `${browser} — ${os}`;
}

/**
 * Bu kullanıcı + cihaz için HÂLÂ GEÇERLİ bir oturum var mı?
 *
 * Varsa yenisini açmak yerine o kullanılır. Aynı tarayıcıdan tekrar giriş
 * yapmak yeni bir "oturum" değildir; aynı oturumun tazelenmesidir.
 */
async function findReusableSession({ sessionManager, userId, deviceId }) {
  if (!deviceId) return null;
  const sessions = await sessionManager.listSessions(String(userId));
  const candidates = sessions
    .filter((s) => !s.revoked && s.deviceId === deviceId)
    .sort((a, b) => Number(b.lastSeenAt || 0) - Number(a.lastSeenAt || 0));
  return candidates[0] || null;
}

module.exports = {
  DEVICE_COOKIE_NAME, DEVICE_COOKIE_TTL_S,
  seal, unseal, newDeviceId,
  resolveDevice, buildDeviceCookie,
  recordDevice, findReusableSession, describeUserAgent,
};
