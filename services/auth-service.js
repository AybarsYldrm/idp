'use strict';

const crypto = require('node:crypto');
const { AppError } = require('../core/errors');
const password = require('../core/password');
const totp = require('../core/totp');
const fingerprintModule = require('../core/fingerprint');
const { scanFindAll } = require('../db/query-utils');
const mailerModule = require('../core/mailer');
const { InMemoryEphemeralStore } = require('../core/ephemeral-store');

// ============================================================================
// ZORUNLU MFA KURULUM AKIŞI (gereksinim #4)
// ----------------------------------------------------------------------------
//   1. POST /auth/register        -> hesap 'pending_mfa_setup' durumunda oluşturulur,
//                                     TAM oturum DEĞİL, sadece dar kapsamlı bir `setupToken`
//                                     döner (SADECE MFA kurulum uç noktalarını çağırabilir).
//   2. TOTP kaydı VE/VEYA WebAuthn kaydı `setupToken` ile tamamlanır
//                                  -> markMfaMethodEnrolled() çağrılır, status='active' olur.
//   3. Bundan sonraki normal login (parola VEYA WebAuthn) artık tam işler.
//
// İKİNCİ FAKTÖR POLİTİKASI (neden "her zaman TOTP sor" DEĞİL):
//   - WebAuthn + UV (user verification, biyometrik/PIN) TEK BAŞINA zaten possession+
//     knowledge/inherence kanıtlıyor -> tek ceremony ile tam MFA sağlanmış olur, ayrıca
//     TOTP istemek gereksiz sürtünme ekler (çoğu büyük IdP -- GitHub, Google -- de böyle
//     davranır).
//   - Parola (sadece knowledge) VEYA UV=false WebAuthn (sadece possession) TEK BAŞINA
//     yeterli değildir -> ikinci bir bağımsız faktör (TOTP kodu, ya da UV şartı olmadan
//     ikinci bir WebAuthn assertion) zorunlu kılınır.
// Bu politika services/webauthn-service.js ile birlikte aşağıda uygulanıyor.
// ============================================================================

// ---- kısa ömürlü, çok-adımlı akış durumu için PAYLAŞILAN depolama ----
// Varsayılan: tek-instance bellek-içi Map (test/geliştirme için yeterli). Üretimde
// birden fazla instance koşuyorsanız oauth-server.js açılışta configureEphemeralStore()
// ile core/ephemeral-store.js'in DbEphemeralStore'unu enjekte eder -- bu durumda
// setupToken/mfaChallengeToken/e-posta kodu gibi TÜM ara durumlar instance'lar arası
// paylaşılır (bkz. core/ephemeral-store.js başlığındaki NEDEN ÖNEMLİ notu).
let ephemeralStore = new InMemoryEphemeralStore();
function configureEphemeralStore(store) { ephemeralStore = store; }

function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Aynı e-postaya en fazla 60 sn'de bir doğrulama kodu -- kaba kuvvet/spam önleme.
async function enforceEmailRateLimit(email) {
  const key = `emailrate:${email}`;
  const nextAllowed = await ephemeralStore.get(key);
  if (nextAllowed && Date.now() < nextAllowed) {
    const waitS = Math.ceil((nextAllowed - Date.now()) / 1000);
    throw new AppError('email_rate_limited', `Çok fazla istek. ${waitS} saniye sonra tekrar deneyin.`, { httpStatus: 429 });
  }
  await ephemeralStore.set(key, Date.now() + 60_000, 65_000);
}

async function sendVerificationEmail(mailer, { toEmail, username, code }) {
  if (!mailer) return; // mailer yapılandırılmamışsa (ör. FITFAK_IDP_DEV_DB=1 ile yerel geliştirme) sessizce atla
  const html = mailerModule.buildEmailHtml({
    title: 'E-posta adresini doğrula',
    bodyHtml: mailerModule.otpBadgeHtml(code, `Merhaba ${mailerModule.escHtml(username)}, hesabını aktifleştirmek için aşağıdaki doğrulama kodunu kullan. Kod 15 dakika içinde geçerliliğini yitirir.`),
  });
  await mailer.send({ from: mailer.defaultFrom, to: toEmail, subject: 'E-posta doğrulama kodun', message: html });
}

// ---- genel amaçlı ara-token yardımcıları (namespace önekiyle TEK store paylaşılır) ----
async function issueEphemeralToken(namespace, userId, ttlMs, extra = {}) {
  const token = crypto.randomBytes(24).toString('hex');
  await ephemeralStore.set(`${namespace}:${token}`, { userId, ...extra }, ttlMs);
  return token;
}
async function peekEphemeralToken(namespace, token) {
  return ephemeralStore.get(`${namespace}:${token}`);
}
async function consumeEphemeralToken(namespace, token) {
  const entry = await peekEphemeralToken(namespace, token);
  if (entry) await ephemeralStore.delete(`${namespace}:${token}`);
  return entry;
}

async function issueSetupToken(userId) { return issueEphemeralToken('setup', userId, 15 * 60_000); }
async function verifySetupToken(token) { return peekEphemeralToken('setup', token); } // tüketilmez: birden çok kurulum çağrısı aynı token'ı kullanabilir
async function issueMfaChallengeToken(userId) { return issueEphemeralToken('mfa', userId, 5 * 60_000); }
async function consumeMfaChallengeToken(token) { return consumeEphemeralToken('mfa', token); } // tek kullanımlık

// ============================================================================
// ANTI-BOT UYGULAMASI (gereksinim #6) -- login/register uçlarının GİRİŞİNDE çağrılır.
// (Rate-limiter/PoW BİLEREK ephemeralStore'u kullanmıyor -- bkz. core/ephemeral-
// store.js başlığındaki not: bunlar kesin doğru olması gerekmeyen sezgiseller.)
// ============================================================================
async function enforceAntiAutomation({ antiBot, ip, username, headers, socket, clientFingerprint, powChallengeId, powNonce }) {
  const serverSignals = fingerprintModule.extractServerSignals(headers, socket);
  const { fingerprintId, trustScore } = fingerprintModule.combine({ clientFingerprint, serverSignals });

  if (username && (await antiBot.rateLimiter.isLockedOut(username))) {
    const remainingS = Math.ceil((await antiBot.rateLimiter.lockoutRemainingMs(username)) / 1000);
    throw new AppError('locked_out', `Çok fazla başarısız deneme. ${remainingS} saniye sonra tekrar deneyin.`, { httpStatus: 429 });
  }

  const { limited } = await antiBot.rateLimiter.recordAttempt({ ip, username, fingerprintId });
  if (limited) throw new AppError('rate_limited', 'Çok fazla istek gönderildi. Lütfen biraz bekleyin.', { httpStatus: 429 });

  const powResult = await antiBot.pow.verifySolution({ challengeId: powChallengeId, nonce: powNonce });
  if (!powResult.ok) {
    throw new AppError('pow_failed', 'İstemci doğrulaması (proof-of-work) başarısız. Sayfayı yenileyip tekrar deneyin.', { httpStatus: 403 });
  }

  return { fingerprintId, trustScore };
}

const PASSWORD_MIN_LENGTH = 12;

// Kayıt anında zorunlu parola karmaşıklığı: en az 12 karakter + büyük/küçük harf +
// rakam + özel karakter. scrypt'in kendisi zaten yavaş/maliyetli olsa da, KISA/zayıf
// parolalar kaba kuvvete karşı hâlâ pratik bir risktir -- bu kontrol o riski azaltır.
function validatePasswordComplexity(passwordPlain) {
  if (typeof passwordPlain !== 'string' || passwordPlain.length < PASSWORD_MIN_LENGTH) {
    throw new AppError('weak_password', `Şifre en az ${PASSWORD_MIN_LENGTH} karakter olmalı`, { httpStatus: 400 });
  }
  const hasUpper = /[A-Z]/.test(passwordPlain);
  const hasLower = /[a-z]/.test(passwordPlain);
  const hasDigit = /[0-9]/.test(passwordPlain);
  const hasSpecial = /[^A-Za-z0-9]/.test(passwordPlain);
  if (!hasUpper || !hasLower || !hasDigit || !hasSpecial) {
    throw new AppError(
      'weak_password',
      'Şifre en az bir büyük harf, bir küçük harf, bir rakam ve bir özel karakter içermeli',
      { httpStatus: 400 },
    );
  }
}

async function sendAccountExistsNotification(mailer, { toEmail, username }) {
  if (!mailer) return;
  const html = mailerModule.buildEmailHtml({
    title: 'Hesabınla ilgili bir kayıt denemesi oldu',
    bodyHtml: `<p style="margin:0 0 20px; font-size:14px; color:#5f6b76; line-height:1.65; font-family:'Segoe UI', Helvetica, Arial, sans-serif;">Merhaba ${mailerModule.escHtml(username)}, e-posta adresinle (ya da kullanıcı adınla) fitfak kimlik üzerinde YENİ bir hesap oluşturulmaya çalışıldı. Zaten bir hesabın olduğu için yeni bir hesap açılmadı. Bu sen değilsen, şifreni değiştirmeni öneririz. Bu sensen, doğrudan giriş yapabilirsin.</p>`,
  });
  await mailer.send({
    from: mailer.defaultFrom, to: toEmail, subject: 'fitfak kimlik -- kayıt denemesi bildirimi', message: html,
  });
}

// ============================================================================
// KAYIT (registration) -- artık İLK ADIM olarak e-posta doğrulaması gerektiriyor:
// register() -> 'pending_email_verification' (kod e-postaya gönderilir, henüz
// setupToken YOK) -> verifyEmail() (kod doğru ise) -> 'pending_mfa_setup' (BURADA
// setupToken verilir, eskisi gibi) -> MFA kurulumu -> 'active'.
//
// KULLANICI NUMARALANDIRMA (USER ENUMERATION) KORUMASI: kullanıcı adı/e-posta ZATEN
// KAYITLIYSA, bunu asla `username_taken`/`email_taken` gibi AÇIK bir hatayla bildirmiyoruz
// (bu, bir saldırganın hangi e-postaların/kullanıcı adlarının sistemde kayıtlı olduğunu
// taramasına izin verirdi). Bunun yerine: yanıt HER ZAMAN aynı ("kayıt alındı, e-postanı
// kontrol et"), ama GERÇEK hesap sahibine "adına bir kayıt denemesi oldu" bildirimi
// gönderilir ve mevcut hesabın durumuna HİÇBİR ŞEKİLDE dokunulmaz (yeni bir setupToken/
// e-posta kodu ÜRETİLMEZ -- aksi halde saldırgan mevcut bir hesabı ele geçirebilirdi).
// Zamanlama (timing) farkından bilgi sızmaması için scrypt maliyeti her koşulda taklit
// edilir.
// ============================================================================
async function register({
  db, username, email, passwordPlain, mailer,
}) {
  validatePasswordComplexity(passwordPlain);

  const users = db.collection('users');
  const existingByUsername = await users.findOne('username', username);
  const existingByEmail = await users.findOne('email', email);

  if (existingByUsername || existingByEmail) {
    const existing = existingByEmail || existingByUsername;
    try {
      await sendAccountExistsNotification(mailer, { toEmail: existing.email, username: existing.username });
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[auth-service] hesap-zaten-var bildirimi gönderilemedi:', e.message);
    }
    // Gerçek kayıt yolunun scrypt maliyetini taklit et -- yanıt SÜRESİNDEN bile hesabın
    // var olup olmadığı çıkarılamasın.
    password.hash(passwordPlain);
    return { userId: null, email, requiresEmailVerification: true };
  }

  const passwordHash = password.hash(passwordPlain);
  const userId = await users.insert({
    username, email, passwordHash,
    status: 'pending_email_verification', mfaMethods: '[]', isAdmin: false,
    createdAt: BigInt(Date.now()), emailVerified: false, role: 'user',
  });

  const code = generateVerificationCode();
  await ephemeralStore.set(`emailcode:${email}`, { code, userId: String(userId) }, 15 * 60_000);
  try {
    await sendVerificationEmail(mailer, { toEmail: email, username, code });
  } catch (e) {
    // E-posta gönderilemedi diye kaydı İPTAL ETMİYORUZ -- kullanıcı "kodu tekrar gönder"
    // ile yeniden deneyebilir. Ama operasyonel olarak fark edilsin diye logluyoruz.
    // eslint-disable-next-line no-console
    console.error('[auth-service] doğrulama e-postası gönderilemedi:', e.message);
  }

  return { userId: String(userId), email, requiresEmailVerification: true };
}

// Kod süresi dolduysa ya da kutuya düşmediyse yeniden gönderim (rate-limitli).
async function resendVerificationEmail({ db, email, mailer }) {
  await enforceEmailRateLimit(email);
  const users = db.collection('users');
  const user = await users.findOne('email', email);
  if (!user) throw new AppError('not_found', 'Bu e-posta ile kayıtlı hesap bulunamadı', { httpStatus: 404 });
  if (user.status !== 'pending_email_verification') {
    throw new AppError('already_verified', 'Bu hesabın e-postası zaten doğrulanmış', { httpStatus: 400 });
  }
  const code = generateVerificationCode();
  await ephemeralStore.set(`emailcode:${email}`, { code, userId: String(user._id) }, 15 * 60_000);
  await sendVerificationEmail(mailer, { toEmail: email, username: user.username, code });
  return { sent: true };
}

// Doğru kod girilince: e-posta doğrulanmış sayılır, hesap MFA kurulum aşamasına geçer
// (setupToken BURADA verilir -- eskiden register()'ın hemen verdiği token).
async function verifyEmail({ db, email, code }) {
  const record = await ephemeralStore.get(`emailcode:${email}`);
  if (!record || record.code !== String(code || '').trim()) {
    throw new AppError('invalid_code', 'Doğrulama kodu geçersiz veya süresi dolmuş', { httpStatus: 401 });
  }
  await ephemeralStore.delete(`emailcode:${email}`);

  const users = db.collection('users');
  const user = await users.get(record.userId);
  if (!user) throw new AppError('not_found', 'Kullanıcı bulunamadı', { httpStatus: 404 });

  await users.update(record.userId, { status: 'pending_mfa_setup', emailVerified: true });
  const setupToken = await issueSetupToken(record.userId);
  return { userId: record.userId, setupToken, requiresMfaSetup: true };
}

// ============================================================================
// PAROLA İLE GİRİŞ (1. faktör) -- her zaman ya "MFA kur" ya da "2. faktörü tamamla"
// ile sonuçlanır; asla doğrudan tam oturum vermez.
//
// `antiBot` OPSİYONELDİR (testlerde/izole çağrılarda atlanabilir) ama üretimde HER ZAMAN
// geçirilmelidir: enforceAntiAutomation() sadece "bu deneme yapılabilir mi" (ön kapı)
// kontrolü yapıyor -- sonucu (doğru/yanlış parola) rate-limiter'a GERİ bildirmezse
// kademeli kilitleme mekanizması hiçbir zaman tetiklenmez/temizlenmez. Bu yüzden
// recordFailure/recordSuccess çağrısı kasıtlı olarak BURADA, doğrulamanın hemen
// yanında -- ayrı bir yerde unutulması ihtimaline karşı.
// ============================================================================
async function loginWithPassword({
  db, username, passwordPlain, antiBot,
}) {
  const users = db.collection('users');
  // Microsoft/Google tarzı: kullanıcı adı ALANINA e-posta da yazılabilir. Önce kullanıcı
  // adı olarak, bulunamazsa e-posta olarak arıyoruz -- iki ayrı giriş formu göstermeye
  // gerek yok. `identifier` rate-limit/kilit sayaçlarında da tutarlı olsun diye çözümlenen
  // GERÇEK kullanıcı adını değil, kullanıcının GİRDİĞİ değeri kullanıyoruz (aksi halde
  // saldırgan aynı hesabı iki farklı yazımla deneyerek sayaçları ikiye bölebilirdi... ama
  // kilitlenme kullanıcıya bağlı olduğu için başarısızlık kaydını GERÇEK kullanıcı adına
  // yazıyoruz -- aşağıya bkz.).
  const user = (await users.findOne('username', username)) || (await users.findOne('email', username));
  const valid = !!(user && user.passwordHash && password.verify(passwordPlain, user.passwordHash));

  if (!valid) {
    await antiBot?.rateLimiter?.recordFailure(user ? user.username : username);
    throw new AppError('invalid_credentials', 'Kullanıcı adı/e-posta veya şifre hatalı', { httpStatus: 401 });
  }
  await antiBot?.rateLimiter?.recordSuccess(user.username);

  if (user.status === 'pending_email_verification') {
    return { requiresEmailVerification: true, email: user.email };
  }
  if (user.status === 'pending_mfa_setup') {
    return { requiresMfaSetup: true, setupToken: await issueSetupToken(String(user._id)), userId: String(user._id) };
  }

  const availableMethods = JSON.parse(user.mfaMethods || '[]');
  return {
    requiresSecondFactor: true,
    mfaChallengeToken: await issueMfaChallengeToken(String(user._id)),
    availableMethods,
  };
}

// ============================================================================
// PAROLA SIFIRLAMA (forgot password)
//
// KULLANICI NUMARALANDIRMA KORUMASI: `requestPasswordReset` e-posta kayıtlı OLSA DA
// OLMASA DA aynı yanıtı ve aynı süreyi harcar (kayıtlı değilse bile scrypt maliyeti
// taklit edilir) -- aksi halde saldırgan hangi e-postaların sistemde olduğunu
// tarayabilirdi.
//
// OTURUM GÜVENLİĞİ: `confirmPasswordReset` başarılı olduğunda kullanıcının TÜM aktif
// oturumları iptal edilir. Bunun nedeni: parola sıfırlamanın en yaygın gerekçesi
// "hesabım ele geçirilmiş olabilir"dir -- saldırganın ZATEN açık olan oturumu parola
// değişse bile çalışmaya devam ederse sıfırlamanın hiçbir anlamı kalmaz.
// ============================================================================
async function requestPasswordReset({ db, email, mailer }) {
  await enforceEmailRateLimit(email);
  const users = db.collection('users');
  const user = await users.findOne('email', email);

  if (!user) {
    // Kayıtlı olmayan e-posta: hiçbir şey yapma AMA gerçek yolun maliyetini taklit et
    // (zamanlama farkından hesabın varlığı çıkarılamasın) ve AYNI yanıtı dön.
    password.hash(crypto.randomBytes(16).toString('hex'));
    return { requested: true };
  }

  const code = generateVerificationCode();
  await ephemeralStore.set(`resetcode:${email}`, { code, userId: String(user._id) }, 15 * 60_000);
  try {
    const html = mailerModule.buildEmailHtml({
      title: 'Parola sıfırlama kodun',
      bodyHtml: mailerModule.otpBadgeHtml(code, `Merhaba ${mailerModule.escHtml(user.username)}, parolanı sıfırlamak için aşağıdaki kodu kullan. Kod 15 dakika geçerlidir. Bu isteği sen yapmadıysan bu e-postayı yok sayabilirsin -- parolan değişmez.`),
    });
    if (mailer) {
      await mailer.send({
        from: mailer.defaultFrom, to: email, subject: 'Parola sıfırlama kodun', message: html,
      });
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[auth-service] parola sıfırlama e-postası gönderilemedi:', e.message);
  }
  return { requested: true };
}

async function confirmPasswordReset({
  db, sessionManager, email, code, newPassword,
}) {
  const record = await ephemeralStore.get(`resetcode:${email}`);
  if (!record || record.code !== String(code || '').trim()) {
    throw new AppError('invalid_code', 'Sıfırlama kodu geçersiz veya süresi dolmuş', { httpStatus: 401 });
  }
  validatePasswordComplexity(newPassword);

  const users = db.collection('users');
  const user = await users.get(record.userId);
  if (!user) throw new AppError('not_found', 'Kullanıcı bulunamadı', { httpStatus: 404 });

  await users.update(record.userId, { passwordHash: password.hash(newPassword) });
  await ephemeralStore.delete(`resetcode:${email}`);

  // TÜM oturumları iptal et -- bkz. yukarıdaki OTURUM GÜVENLİĞİ notu.
  let revokedCount = 0;
  if (sessionManager) {
    const sessions = await sessionManager.listSessions(record.userId);
    const active = sessions.filter((s) => !s.revoked);
    await Promise.all(active.map((s) => sessionManager.revokeSession(s.sessionId, 'password_reset')));
    revokedCount = active.length;
  }
  return { reset: true, revokedSessions: revokedCount };
}

// ============================================================================
// 2. FAKTÖR: TOTP ile tamamlama -> BURADA tam oturum (session) üretilir.
//
// TOTP kodu sadece 6 haneli (10^6 olasılık) olduğu için BU adım da kaba kuvvete karşı
// kendi başına korunmalı -- rate-limiter'ın "kullanıcı adı" eksenini burada `totp:<userId>`
// diye ÖNEKLEYEREK kullanıyoruz ki parola-deneme sayaçlarıyla KARIŞMASIN (iki farklı saldırı
// yüzeyi, bağımsız sayaçlar).
// ============================================================================
async function completeLoginWithTotp({ db, sessionManager, mfaChallengeToken, code, ip, userAgent, fingerprintId, antiBot }) {
  // BİLEREK consumeMfaChallengeToken DEĞİL, peekEphemeralToken (TÜKETMEYEN) kullanılıyor:
  // token SADECE başarılı tamamlanışta tüketilmeli. Aksi halde yanlış yazılmış tek bir
  // TOTP hanesi kullanıcıyı parola adımına GERİ döndürürdü -- gereksiz ve kötü bir UX.
  const pending = await peekEphemeralToken('mfa', mfaChallengeToken);
  if (!pending) throw new AppError('invalid_mfa_challenge', 'Geçersiz veya süresi dolmuş 2FA isteği', { httpStatus: 401 });
  const rateLimitKey = `totp:${pending.userId}`; // parola-deneme sayaçlarıyla karışmasın diye önekli

  const totpCreds = db.collection('totp_credentials');
  const row = await totpCreds.findOne('userId', pending.userId);
  if (!row) throw new AppError('totp_not_enrolled', 'Bu hesapta TOTP kurulu değil', { httpStatus: 400 });

  const secret = Buffer.from(row.secretBase64, 'base64');
  const result = totp.verify(secret, code, { lastUsedCounter: Number(row.lastUsedCounter) });
  if (!result.ok) {
    await antiBot?.rateLimiter?.recordFailure(rateLimitKey);
    throw new AppError('invalid_totp_code', 'Doğrulama kodu geçersiz veya süresi dolmuş', { httpStatus: 401 });
  }
  await antiBot?.rateLimiter?.recordSuccess(rateLimitKey);

  await totpCreds.update(row._id, { lastUsedCounter: BigInt(result.newLastUsedCounter) });
  await consumeEphemeralToken('mfa', mfaChallengeToken); // başarı -- şimdi tüket (tek kullanımlık)

  return sessionManager.createSession({ userId: pending.userId, ip, userAgent, fingerprintId });
}

// ============================================================================
// TOTP KURULUMU (kayıt sonrası zorunlu akışın bir parçası, ya da sonradan eklenen bir yöntem)
// ============================================================================
async function beginTotpEnrollment({ db, setupToken, accountLabel, issuer = 'Fitfak Kimlik' }) {
  const pending = await verifySetupToken(setupToken);
  if (!pending) throw new AppError('invalid_setup_token', 'Geçersiz veya süresi dolmuş kurulum isteği', { httpStatus: 401 });

  const secret = totp.generateSecret();
  // Kurulum tamamlanana (finishTotpEnrollment) kadar secret'ı DB'ye YAZMIYORUZ --
  // kullanıcı ilk kodu doğru girene kadar "yarım kalmış" bir kayıt oluşmasın diye
  // kısa ömürlü aynı setupToken store'unda tutuyoruz.
  await ephemeralStore.set(`setup:${setupToken}`, { ...pending, pendingTotpSecret: secret.toString('base64') }, 15 * 60_000);

  return {
    secretBase32: require('../core/base32').encode(secret),
    provisioningUri: totp.provisioningUri({ secret, accountName: accountLabel, issuer }),
  };
}

async function finishTotpEnrollment({ db, setupToken, code }) {
  const pending = await peekEphemeralToken('setup', setupToken);
  if (!pending || !pending.pendingTotpSecret) {
    throw new AppError('invalid_setup_token', 'Önce TOTP kurulumunu başlatmalısınız', { httpStatus: 400 });
  }
  const secret = Buffer.from(pending.pendingTotpSecret, 'base64');
  const result = totp.verify(secret, code, { lastUsedCounter: -1 });
  if (!result.ok) throw new AppError('invalid_totp_code', 'Doğrulama kodu hatalı', { httpStatus: 401 });

  const totpCreds = db.collection('totp_credentials');
  await totpCreds.insert({
    userId: pending.userId, secretBase64: pending.pendingTotpSecret,
    lastUsedCounter: BigInt(result.newLastUsedCounter), createdAt: BigInt(Date.now()),
  });
  await markMfaMethodEnrolled({ db, userId: pending.userId, method: 'totp' });

  return { enrolled: true };
}

// ============================================================================
// Kayıt/ilk giriş akışlarının ortak sonu: bir MFA yöntemi eklendiğinde hesabı 'active' yap.
// ============================================================================
async function markMfaMethodEnrolled({ db, userId, method }) {
  const users = db.collection('users');
  const user = await users.get(userId);
  if (!user) throw new AppError('user_not_found', 'Kullanıcı bulunamadı', { httpStatus: 404 });
  const methods = new Set(JSON.parse(user.mfaMethods || '[]'));
  methods.add(method);
  await users.update(userId, { mfaMethods: JSON.stringify([...methods]), status: 'active' });
}

async function logout({ sessionManager, sessionId }) {
  await sessionManager.revokeSession(sessionId, 'user_logout');
}

// ============================================================================
// SessionManager <-> @fitfak/database KÖPRÜSÜ
// ----------------------------------------------------------------------------
// core/session-manager.js kasıtlı olarak DB'den habersizdir (test edilebilirlik için --
// bkz. test/mock-store.js). Üretimde gerçek DatabaseManager koleksiyonlarına bağlamak
// için bu adaptör kullanılır.
//
// DÜZELTME: `listSessionsForUser` artık `db/query-utils.js`'teki `scanFindAll`'ı
// kullanıyor -- kullanıcının kendi referans `server.js`'inde (ör. ListUsers,
// FindRecord'un '*' dalı) gösterdiği GERÇEK desen buydu: `collection.scan()` ile tüm
// kayıtlar üzerinde async iterasyon + elle filtreleme. `findAll` diye bir metod
// GERÇEKTEN yok (production'da tam da bu satırda `TypeError: creds.findAll is not a
// function` olarak çökmüştü) -- artık düzeltildi.
// ============================================================================
function createSessionStoreAdapter(db) {
  const sessions = db.collection('sessions');
  const refreshTokens = db.collection('refresh_tokens');

  return {
    async createSession(rec) {
      return sessions.insert({
        sessionId: rec.sessionId, userId: rec.userId, ip: rec.ip || '', userAgent: rec.userAgent || '',
        fingerprintId: rec.fingerprintId || '', audiences: JSON.stringify(rec.audiences || ['self']), scope: rec.scope || '',
        createdAt: BigInt(rec.createdAt.getTime()), lastSeenAt: BigInt(rec.lastSeenAt.getTime()),
        revoked: false, revokedReason: '',
      });
    },
    async getSessionById(sessionId) {
      const row = await sessions.findOne('sessionId', sessionId);
      return row ? toSessionView(row) : null;
    },
    async touchSession(sessionId, { lastSeenAt, ip, userAgent }) {
      const row = await sessions.findOne('sessionId', sessionId);
      if (!row) return;
      await sessions.update(row._id, {
        lastSeenAt: BigInt(lastSeenAt.getTime()), ip: ip || row.ip, userAgent: userAgent || row.userAgent,
      });
    },
    // Bir oturum, SSO sayesinde ZAMAN İÇİNDE birden fazla relying party için token
    // üretebilir (kullanıcı dns.fitfak.net'e gider, sonra başka bir servise gider, hep
    // AYNI alttaki oturumdan sessizce yeni token'lar alır) -- bu yüzden `audiences` TEK bir
    // alan değil, EKLENEN bir küme. gRPC IdentityService'in (oauth-server.js) "sadece
    // KENDİ RP'nizin oturumlarını görün/iptal edin" sınırı buna dayanıyor.
    async addAudienceToSession(sessionId, clientId) {
      const row = await sessions.findOne('sessionId', sessionId);
      if (!row) return;
      const current = JSON.parse(row.audiences || '["self"]');
      if (!current.includes(clientId)) {
        current.push(clientId);
        await sessions.update(row._id, { audiences: JSON.stringify(current) });
      }
    },
    async revokeSession(sessionId, reason) {
      const row = await sessions.findOne('sessionId', sessionId);
      if (!row) return;
      await sessions.update(row._id, { revoked: true, revokedReason: reason || '' });
    },
    async listSessionsForUser(userId) {
      const rows = await scanFindAll(sessions, 'userId', userId);
      return rows.map(toSessionView);
    },
    async insertRefreshToken(rec) {
      // `audience`/`scope` BİLEREK BURADA (oturumun değil, refresh token'ın kendi
      // kaydında) tutuluyor -- bkz. core/session-manager.js'in _issueTokenPair yorumu:
      // bir oturumun paralel, RP-başına refresh-token "soy ağaçları" olabilir, her biri
      // rotate() edildiğinde KENDİ audience/scope'unu korumalı.
      await refreshTokens.insert({
        hash: rec.hash, sessionId: rec.sessionId, audience: rec.audience || '', scope: rec.scope || '',
        createdAt: BigInt(rec.createdAt.getTime()), expiresAt: BigInt(rec.expiresAt.getTime()), used: false,
      });
    },
    async findRefreshTokenByHash(hash) {
      const row = await refreshTokens.findOne('hash', hash);
      if (!row) return null;
      return {
        sessionId: row.sessionId, audience: row.audience, scope: row.scope,
        expiresAt: new Date(Number(row.expiresAt)), used: row.used,
      };
    },
    async markRefreshTokenUsed(hash) {
      const row = await refreshTokens.findOne('hash', hash);
      if (row) await refreshTokens.update(row._id, { used: true });
    },
  };
}

function toSessionView(row) {
  return {
    sessionId: row.sessionId, userId: row.userId, ip: row.ip, userAgent: row.userAgent,
    fingerprintId: row.fingerprintId, audiences: JSON.parse(row.audiences || '["self"]'), scope: row.scope,
    createdAt: new Date(Number(row.createdAt)), lastSeenAt: new Date(Number(row.lastSeenAt)),
    revoked: row.revoked, revokedReason: row.revokedReason,
  };
}

// ============================================================================
// RBAC: kullanıcı listeleme + rol yönetimi (yönetici panelinde kullanılır --
// bkz. oauth-server.js /admin/* rotaları ve public/admin-panel.html).
// ============================================================================
async function listAllUsers({ db }) {
  const users = db.collection('users');
  const result = [];
  // eslint-disable-next-line no-restricted-syntax
  for await (const rec of users.scan()) {
    result.push({
      userId: String(rec._id), username: rec.username, email: rec.email,
      status: rec.status, role: rec.role || 'user', emailVerified: !!rec.emailVerified,
      certProfiles: JSON.parse(rec.certProfiles || '[]'),
      createdAt: Number(rec.createdAt),
    });
  }
  return result;
}

async function setUserRole({ db, targetUserId, role, actingUserId }) {
  if (!['user', 'admin'].includes(role)) {
    throw new AppError('invalid_role', "Geçersiz rol değeri (yalnızca 'user' ya da 'admin' olabilir)", { httpStatus: 400 });
  }
  if (String(targetUserId) === String(actingUserId) && role !== 'admin') {
    throw new AppError('cannot_demote_self', 'Kendi yönetici rolünüzü kendiniz kaldıramazsınız', { httpStatus: 400 });
  }
  const users = db.collection('users');
  const target = await users.get(targetUserId);
  if (!target) throw new AppError('not_found', 'Kullanıcı bulunamadı', { httpStatus: 404 });
  await users.update(targetUserId, { role, isAdmin: role === 'admin' });
  return { updated: true };
}

// SADECE testler/manuel ops-debug içindir -- HİÇBİR HTTP rotasına bağlanmamalı (bkz.
// oauth-server.js -- kasıtlı olarak orada kullanılmıyor). register() güvenlik gereği
// kodun kendisini asla döndürmez; bu fonksiyon sadece otomatik testlerin gerçek e-posta
// almadan akışı sürdürebilmesi için var.
async function _debugPeekVerificationCode(email) {
  const record = await ephemeralStore.get(`emailcode:${email}`);
  return record?.code || null;
}

module.exports = {
  configureEphemeralStore,
  issueEphemeralToken,
  peekEphemeralToken,
  consumeEphemeralToken,
  enforceAntiAutomation,
  register,
  resendVerificationEmail,
  requestPasswordReset,
  confirmPasswordReset,
  validatePasswordComplexity,
  verifyEmail,
  loginWithPassword,
  completeLoginWithTotp,
  beginTotpEnrollment,
  finishTotpEnrollment,
  markMfaMethodEnrolled,
  logout,
  createSessionStoreAdapter,
  listAllUsers,
  setUserRole,
  _debugPeekVerificationCode,
  // webauthn-service.js'in setup-token/mfa-challenge-token akışına katılabilmesi için:
  verifySetupToken,
  issueMfaChallengeToken,
  consumeMfaChallengeToken,
};

// SADECE testler için -- HİÇBİR HTTP rotasına bağlanmamalı (bkz. _debugPeekVerificationCode).
module.exports._debugPeekResetCode = async function _debugPeekResetCode(email) {
  const record = await ephemeralStore.get(`resetcode:${email}`);
  return record?.code || null;
};
