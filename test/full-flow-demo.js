'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const path = require('node:path');
const fsp = require('node:fs/promises');

const { loadOrCreateSigningKeyPair } = require('../core/keys');
const { SessionManager } = require('../core/session-manager');
const { WebAuthnService } = require('../core/webauthn');
const { ProofOfWorkService } = require('../core/proof-of-work');
const { LoginProtection } = require('../core/rate-limiter');
const totpModule = require('../core/totp');
const base64url = require('../core/base64url');

const authService = require('../services/auth-service');
const webauthnService = require('../services/webauthn-service');
const { OAuthService, createStaticClientStore } = require('../services/oauth-service');

const { createMockDb } = require('./mock-db');
const { MockAuthenticator } = require('./mock-authenticator');

const RP_ID = 'fitfak.net';
const ORIGIN = 'https://session.fitfak.net';

async function solvePow(pow, { difficultyBits }) {
  const { challengeId, challenge } = await pow.issueChallenge({ difficultyBits });
  let nonce = 0;
  // Küçük zorluk seviyelerinde (test için 4-8 bit) bu döngü milisaniyeler içinde biter;
  // gerçek zorluk (18-28 bit) tarayıcıda yüz-milisaniye mertebesinde sürer.
  for (;;) {
    const candidate = String(nonce);
    const digest = crypto.createHash('sha256').update(`${challenge}:${candidate}`).digest();
    let leadingZeroBits = 0;
    outer: for (const byte of digest) {
      if (byte === 0) { leadingZeroBits += 8; continue; }
      let mask = 0x80;
      while (mask) { if (byte & mask) break outer; leadingZeroBits++; mask >>= 1; }
      break;
    }
    if (leadingZeroBits >= difficultyBits) return { challengeId, nonce: candidate };
    nonce++;
  }
}

async function main() {
  // ---------------------------------------------------------------------
  // KURULUM
  // ---------------------------------------------------------------------
  const keyDir = path.join(__dirname, '..', '.tmp-full-flow-keys');
  await fsp.rm(keyDir, { recursive: true, force: true });
  const signingKeyPair = loadOrCreateSigningKeyPair(keyDir);

  // Koleksiyon listesi db/schema.js'ten türetiliyor. Elle yazılmış bir liste,
  // şemaya yeni bir koleksiyon eklendiğinde sessizce eskir ve testi gerçek
  // sunucunun çalıştığı yapılandırmadan ayırır.
  const db = createMockDb(Object.keys(require('../db/schema')));
  const sessionManager = new SessionManager({
    store: authService.createSessionStoreAdapter(db),
    signingKeyPair, issuer: 'https://session.fitfak.net', cookieDomain: '.fitfak.net',
  });
  const webauthn = new WebAuthnService({ rpId: RP_ID, rpName: 'Fitfak Kimlik', origin: ORIGIN });
  const antiBot = { rateLimiter: new LoginProtection(), pow: new ProofOfWorkService() };
  const clientStore = createStaticClientStore([
    // firstParty: kendi panelimiz, onay ekranı atlanır. Üçüncü taraf bir
    // client'ta silent SSO artık yetmez -- kullanıcı onayı da gerekir; o yol
    // test/consent-demo.js'te.
    { clientId: 'dns-fitfak-net', name: 'DNS Paneli', redirectUris: ['https://dns.fitfak.net/callback'], allowedScopes: ['openid', 'profile', 'dns:read'], firstParty: true },
  ]);
  const oauthService = new OAuthService({ sessionManager, clientStore, db, issuer: 'https://session.fitfak.net' });

  const ip = '203.0.113.9';
  const userAgent = 'integration-test-agent/1.0';

  // ---------------------------------------------------------------------
  // 1) KAYIT + E-POSTA DOĞRULAMA (yeni adım)
  // ---------------------------------------------------------------------
  const reg = await authService.register({ db, username: 'abuzer', email: 'abuzer@fitfak.net', passwordPlain: 'CorrectHorseBatteryStaple1!' });
  assert.ok(reg.requiresEmailVerification);
  const userRowAfterReg0 = await db.collection('users').get(reg.userId);
  assert.strictEqual(userRowAfterReg0.status, 'pending_email_verification');
  console.log('full-flow: kayıt OK -- hesap pending_email_verification durumunda (mailer verilmediği için kod sadece bellekte)');

  const verifyCode = await authService._debugPeekVerificationCode('abuzer@fitfak.net');
  await assert.rejects(() => authService.verifyEmail({ db, email: 'abuzer@fitfak.net', code: '000000' }));
  const emailVerifyResult = await authService.verifyEmail({ db, email: 'abuzer@fitfak.net', code: verifyCode });
  assert.ok(emailVerifyResult.requiresMfaSetup && emailVerifyResult.setupToken);
  Object.assign(reg, emailVerifyResult); // sonraki adımlar reg.setupToken/reg.userId kullanıyor
  const userRowAfterReg = await db.collection('users').get(reg.userId);
  assert.strictEqual(userRowAfterReg.status, 'pending_mfa_setup');
  assert.strictEqual(userRowAfterReg.emailVerified, true);
  console.log('full-flow: e-posta doğrulandı -- hesap artık pending_mfa_setup durumunda, tam oturum DEĞİL sadece setupToken döndü');

  // ---------------------------------------------------------------------
  // 2) ZORUNLU MFA KURULUMU: TOTP
  // ---------------------------------------------------------------------
  const enroll = await authService.beginTotpEnrollment({ db, setupToken: reg.setupToken, accountLabel: 'abuzer' });
  assert.ok(enroll.provisioningUri.startsWith('otpauth://totp/'));
  const secretBuf = Buffer.from(require('../core/base32').decode(enroll.secretBase32));

  await assert.rejects(() => authService.finishTotpEnrollment({ db, setupToken: reg.setupToken, code: '000000' }));
  console.log('full-flow: yanlış TOTP kurulum kodu doğru şekilde reddedildi');

  const validSetupCode = totpModule.totp(secretBuf, {});
  await authService.finishTotpEnrollment({ db, setupToken: reg.setupToken, code: validSetupCode });
  const userAfterTotp = await db.collection('users').get(reg.userId);
  assert.strictEqual(userAfterTotp.status, 'active');
  assert.deepStrictEqual(JSON.parse(userAfterTotp.mfaMethods), ['totp']);
  console.log('full-flow: TOTP kurulumu tamamlandı -- hesap artık active, mfaMethods=["totp"]');

  // ---------------------------------------------------------------------
  // 3) PAROLA + TOTP İLE NORMAL GİRİŞ
  // ---------------------------------------------------------------------
  const loginStep1 = await authService.loginWithPassword({ db, username: 'abuzer', passwordPlain: 'CorrectHorseBatteryStaple1!', antiBot });
  assert.ok(loginStep1.requiresSecondFactor && loginStep1.mfaChallengeToken);
  assert.deepStrictEqual(loginStep1.availableMethods, ['totp']);
  console.log('full-flow: parola doğru -- 2. faktör (TOTP) isteniyor, tam oturum HENÜZ verilmedi');

  await assert.rejects(() => authService.completeLoginWithTotp({ db, sessionManager, mfaChallengeToken: loginStep1.mfaChallengeToken, code: '111111', ip, userAgent, antiBot }));
  // NOT: enrollment kodu (validSetupCode) ve bu login kodu aynı 30s adımında üretilirse
  // (test milisaniyeler içinde koştuğu için normalde öyle olurdu) İKİSİ DE AYNI 6 haneli
  // koda karşılık gelir -- ve enrollment zaten o sayaç değerini TÜKETTİĞİ için bu ikinci
  // deneme replay olarak (doğru bir şekilde) reddedilirdi. Gerçekçi bir "biraz sonra tekrar
  // giriş yapma" senaryosunu simüle etmek için kodu kasıtlı olarak BİR SONRAKİ adımdan
  // (+30sn) üretiyoruz -- verify()'nin varsayılan ±1 adımlık sürüklenme penceresi buna hâlâ
  // izin veriyor, ama artık enrollment ile ÇAKIŞMIYOR.
  const validLoginCode = totpModule.totp(secretBuf, { time: Date.now() + 30_000 });
  const session1 = await authService.completeLoginWithTotp({ db, sessionManager, mfaChallengeToken: loginStep1.mfaChallengeToken, code: validLoginCode, ip, userAgent, antiBot });
  assert.ok(session1.sessionId && session1.accessToken && session1.refreshToken);
  console.log('full-flow: yanlış TOTP denemesinden SONRA aynı token ile doğru kod kabul edildi (gereksiz yeniden-giriş yok) -- tam oturum verildi');

  const { payload: p1 } = sessionManager.verifyAccessToken(session1.accessToken);
  assert.strictEqual(p1.sub, reg.userId);
  console.log('full-flow: access token doğru sub claim\'i ile doğrulandı');

  // ---------------------------------------------------------------------
  // 4) YENİ BİR PASSKEY EKLEME (zaten aktif/giriş yapmış hesaba)
  // ---------------------------------------------------------------------
  const regOpts = await webauthnService.beginRegistration({ db, webauthnService: webauthn, userId: reg.userId, username: 'abuzer', displayName: 'Abuzer' });
  const authenticator = new MockAuthenticator({ alg: 'ES256', rpId: RP_ID, origin: ORIGIN });
  const regCred = authenticator.register({ challenge: base64url.decode(regOpts.publicKey.challenge), userVerified: true });
  const regResult = await webauthnService.finishRegistration({ db, webauthnService: webauthn, challengeId: regOpts.challengeId, credential: regCred, userId: reg.userId, nickname: 'Test Güvenlik Anahtarı' });
  assert.ok(regResult.registered);
  const userAfterPasskey = await db.collection('users').get(reg.userId);
  assert.deepStrictEqual(JSON.parse(userAfterPasskey.mfaMethods).sort(), ['totp', 'webauthn']);
  console.log('full-flow: yeni passkey kaydedildi, mfaMethods=["totp","webauthn"]');

  // ---------------------------------------------------------------------
  // 5) PAROLASIZ (WebAuthn BİRİNCİL) GİRİŞ -- UV=true -> doğrudan tam oturum
  // ---------------------------------------------------------------------
  const authOpts1 = await webauthnService.beginAuthentication({ db, webauthnService: webauthn, username: 'abuzer' });
  const authCred1 = authenticator.authenticate({ challenge: base64url.decode(authOpts1.publicKey.challenge), userVerified: true });
  const waLogin1 = await webauthnService.finishAuthentication({ db, sessionManager, webauthnService: webauthn, challengeId: authOpts1.challengeId, credential: authCred1, ip, userAgent });
  assert.ok(waLogin1.sessionId && waLogin1.accessToken);
  console.log('full-flow: WebAuthn birincil giriş (UV=true) -- tek ceremony ile doğrudan tam oturum verildi (ek TOTP istenmedi)');

  // ---------------------------------------------------------------------
  // 6) PAROLASIZ GİRİŞ -- UV=false -> possession-only, ikinci faktör (TOTP) zorunlu
  // ---------------------------------------------------------------------
  const authOpts2 = await webauthnService.beginAuthentication({ db, webauthnService: webauthn, username: 'abuzer' });
  const authCred2 = authenticator.authenticate({ challenge: base64url.decode(authOpts2.publicKey.challenge), userVerified: false });
  const waLogin2 = await webauthnService.finishAuthentication({ db, sessionManager, webauthnService: webauthn, challengeId: authOpts2.challengeId, credential: authCred2, ip, userAgent });
  assert.ok(waLogin2.requiresSecondFactor && waLogin2.mfaChallengeToken);
  assert.deepStrictEqual(waLogin2.availableMethods, ['totp']);
  assert.strictEqual(waLogin2.reason, 'webauthn_without_user_verification');
  // NOT: completeLoginWithTotp'un KENDİSİ (mfaChallengeToken tüketimi + tam oturum üretimi)
  // 3. adımda zaten kanıtlandı; burada üçüncü bir gerçek TOTP kodu daha üretip tüketmek
  // (RFC 6238'in ±1 adımlık sürüklenme penceresinde, gerçek zaman ilerlemeden, sadece 2
  // BAĞIMSIZ kod kullanılabilir -- 2. ve 3. adımlar bunları zaten harcadı) yerine, burada asıl
  // test edilen YENİ mantık olan "UV=false -> possession-only -> 2. faktör zorunlu" dallanmasının
  // doğru çalıştığını doğruluyoruz.
  console.log('full-flow: WebAuthn girişi UV=false (PIN\'siz anahtar) -- sadece possession kanıtlandı, 2. faktör (TOTP) doğru şekilde isteniyor');

  // ---------------------------------------------------------------------
  // 7) OTURUM LİSTELEME
  // ---------------------------------------------------------------------
  const allSessions = await sessionManager.listSessions(reg.userId);
  assert.ok(allSessions.length >= 2); // session1 (parola+TOTP) + waLogin1 (WebAuthn UV=true)
  console.log(`full-flow: listSessions ${allSessions.length} aktif oturum döndürdü (parola+TOTP, WebAuthn-UV)`);

  // ---------------------------------------------------------------------
  // 8) OAuth 2.0 SSO: authorize + PKCE token değişimi
  // ---------------------------------------------------------------------
  const codeVerifier = base64url.encode(crypto.randomBytes(32));
  const codeChallenge = base64url.encode(crypto.createHash('sha256').update(codeVerifier).digest());

  const noCookieResult = await oauthService.authorize({
    clientId: 'dns-fitfak-net', redirectUri: 'https://dns.fitfak.net/callback', responseType: 'code',
    scope: 'openid profile dns:read', state: 'xyz', codeChallenge, codeChallengeMethod: 'S256', currentSession: null,
  });
  assert.strictEqual(noCookieResult.requiresLogin, true);
  console.log('full-flow: SSO çerezi yokken authorize() doğru şekilde requiresLogin döndürdü');

  const currentSession = { userId: reg.userId, sessionId: session1.sessionId, revoked: false };
  const authorizeResult = await oauthService.authorize({
    clientId: 'dns-fitfak-net', redirectUri: 'https://dns.fitfak.net/callback', responseType: 'code',
    scope: 'openid profile dns:read', state: 'xyz', codeChallenge, codeChallengeMethod: 'S256', currentSession,
  });
  assert.ok(authorizeResult.redirectTo && authorizeResult.redirectTo.startsWith('https://dns.fitfak.net/callback?code='));
  const redirectUrl = new URL(authorizeResult.redirectTo);
  const code = redirectUrl.searchParams.get('code');
  assert.strictEqual(redirectUrl.searchParams.get('state'), 'xyz');
  console.log('full-flow: geçerli SSO oturumuyla authorize() -- login formu GÖSTERMEDEN doğrudan yetkilendirme kodu üretti (silent SSO)');

  await assert.rejects(() => oauthService.token({
    grantType: 'authorization_code', code, redirectUri: 'https://dns.fitfak.net/callback',
    codeVerifier: 'yanlis-verifier', clientId: 'dns-fitfak-net',
  }));
  console.log('full-flow: yanlış code_verifier (PKCE) doğru şekilde reddedildi -- kod artık tüketildiği için tekrar denenemez');

  const authorizeResult2 = await oauthService.authorize({
    clientId: 'dns-fitfak-net', redirectUri: 'https://dns.fitfak.net/callback', responseType: 'code',
    scope: 'openid profile dns:read', codeChallenge, codeChallengeMethod: 'S256', currentSession,
  });
  const code2 = new URL(authorizeResult2.redirectTo).searchParams.get('code');
  const rpTokens = await oauthService.token({
    grantType: 'authorization_code', code: code2, redirectUri: 'https://dns.fitfak.net/callback',
    codeVerifier, clientId: 'dns-fitfak-net',
  });
  assert.ok(rpTokens.accessToken && rpTokens.refreshToken);
  const { payload: rpPayload } = sessionManager.verifyAccessToken(rpTokens.accessToken);
  assert.strictEqual(rpPayload.aud, 'dns-fitfak-net');
  console.log('full-flow: DOĞRU code_verifier ile PKCE token değişimi başarılı, aud=dns-fitfak-net ile scope\'lu token üretildi');

  // ---------------------------------------------------------------------
  // 9) userinfo + introspect
  // ---------------------------------------------------------------------
  const userinfo = await oauthService.userinfo({ accessToken: rpTokens.accessToken });
  assert.strictEqual(userinfo.username, 'abuzer');
  console.log('full-flow: /oauth/userinfo doğru kullanıcı bilgisini döndürdü');

  const introspectBefore = await oauthService.introspect({ token: rpTokens.accessToken });
  assert.strictEqual(introspectBefore.active, true);

  // ---------------------------------------------------------------------
  // 10) REFRESH (rotasyon) -- OAuthService üzerinden
  // ---------------------------------------------------------------------
  const refreshed = await oauthService.token({ grantType: 'refresh_token', refreshToken: rpTokens.refreshToken, ip, userAgent });
  assert.notStrictEqual(refreshed.refreshToken, rpTokens.refreshToken);
  console.log('full-flow: refresh_token grant\'i ile rotasyon OK');

  // ---------------------------------------------------------------------
  // 11) İPTAL (revoke) -- JWT hâlâ süresi dolmamış olsa BİLE introspect artık inactive görmeli
  // ---------------------------------------------------------------------
  await sessionManager.revokeSession(session1.sessionId, 'test_revocation');
  const introspectAfter = await oauthService.introspect({ token: rpTokens.accessToken });
  assert.strictEqual(introspectAfter.active, false);
  console.log('full-flow: oturum iptal edildikten sonra introspect() -- imzası hâlâ geçerli olan token için bile -- doğru şekilde active:false döndü');

  // ---------------------------------------------------------------------
  // 12) ANTİ-BOT ENTEGRASYONU
  // ---------------------------------------------------------------------
  const goodSolution = await solvePow(antiBot.pow, { difficultyBits: 8 });
  const checkOk = await authService.enforceAntiAutomation({
    antiBot, ip: '198.51.100.1', username: 'baska-kullanici',
    headers: { 'user-agent': 'Mozilla/5.0 test' }, socket: {}, clientFingerprint: { canvasHash: 'abc' },
    powChallengeId: goodSolution.challengeId, powNonce: goodSolution.nonce,
  });
  assert.ok(checkOk.fingerprintId);
  console.log('full-flow: enforceAntiAutomation -- geçerli PoW çözümüyle doğru şekilde geçti');

  const badChallenge = await antiBot.pow.issueChallenge({ difficultyBits: 8 });
  await assert.rejects(() => authService.enforceAntiAutomation({
    antiBot, ip: '198.51.100.2', username: 'baska-kullanici-2',
    headers: {}, socket: {}, clientFingerprint: {}, powChallengeId: badChallenge.challengeId, powNonce: 'yanlis-nonce-000',
  }));
  console.log('full-flow: enforceAntiAutomation -- çözülmemiş PoW doğru şekilde reddedildi');

  for (let i = 0; i < 3; i++) {
    await assert.rejects(() => authService.loginWithPassword({ db, username: 'abuzer', passwordPlain: 'yanlis-sifre', antiBot }));
  }
  assert.ok(antiBot.rateLimiter.isLockedOut('abuzer'));
  console.log('full-flow: ısrarlı yanlış parola denemeleri sonrası hesap doğru şekilde kilitlendi (rate-limiter + loginWithPassword entegrasyonu çalışıyor)');

  // ---------------------------------------------------------------------
  // 13) LOGOUT
  // ---------------------------------------------------------------------
  await authService.logout({ sessionManager, sessionId: waLogin1.sessionId });
  await assert.rejects(() => sessionManager.refresh({ refreshToken: waLogin1.refreshToken }));
  console.log('full-flow: logout sonrası ilgili oturumun refresh token\'ı doğru şekilde geçersiz');

  console.log('\nALL FULL-FLOW INTEGRATION CHECKS PASSED (register -> zorunlu MFA -> parola+TOTP -> passkey ekleme -> parolasız giriş -> SSO/OAuth+PKCE -> refresh -> revoke -> anti-bot)');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
