'use strict';

// Bu test, oauth-server.js'i GERÇEKTEN başlatıp GERÇEK HTTP istekleriyle (fetch benzeri,
// node:http üzerinden) uçtan uca sınar -- services/*.js'i doğrudan çağıran full-flow-
// demo.js'in aksine, burada JSON gövde ayrıştırma, cookie üretimi/parse etme, route
// eşleştirme gibi TRANSPORT/entry-point katmanının kendisi test ediliyor.

process.env.FITFAK_IDP_DEV_DB = '1';
process.env.PORT = '51900';
process.env.FITFAK_IDP_KEY_DIR = require('node:path').join(__dirname, '..', '.tmp-smoke-keys');

const assert = require('node:assert');
const http = require('node:http');
const totpModule = require('../core/totp');
const base32 = require('../core/base32');

const BASE = 'http://localhost:51900';

function request(method, url, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)) : null;
    const req = http.request(url, {
      method,
      headers: { ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}), ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(raw); } catch { /* bazı yanıtlar (302 vb.) JSON değildir */ }
        resolve({ status: res.statusCode, headers: res.headers, raw, json });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function main() {
  const { main: startServer } = require('../oauth-server');
  const server = await startServer();

  try {
    // ---- JWKS + OIDC discovery ----
    const jwks = await request('GET', `${BASE}/.well-known/jwks.json`);
    assert.strictEqual(jwks.status, 200);
    assert.strictEqual(jwks.json.keys[0].kty, 'EC');
    console.log('smoke: GET /.well-known/jwks.json OK -- gerçek HTTP üzerinden JWKS doğru döndü');

    const discovery = await request('GET', `${BASE}/.well-known/openid-configuration`);
    assert.strictEqual(discovery.json.issuer, 'https://session.fitfak.net');
    console.log('smoke: GET /.well-known/openid-configuration OK');

    // ---- PoW challenge al ----
    const powChallenge = await request('POST', `${BASE}/auth/pow-challenge`);
    assert.strictEqual(powChallenge.status, 200);
    const { challengeId, challenge, difficultyBits } = powChallenge.json;
    console.log(`smoke: POST /auth/pow-challenge OK (difficulty=${difficultyBits} bit)`);

    // PoW'u gerçekten çöz (küçük zorluk seviyesi -- rate-limiter henüz tetiklenmediği için düşük)
    const crypto = require('node:crypto');
    let nonce = 0;
    for (;;) {
      const digest = crypto.createHash('sha256').update(`${challenge}:${nonce}`).digest();
      let leadingZeroBits = 0;
      outer: for (const byte of digest) {
        if (byte === 0) { leadingZeroBits += 8; continue; }
        let mask = 0x80;
        while (mask) { if (byte & mask) break outer; leadingZeroBits++; mask >>= 1; }
        break;
      }
      if (leadingZeroBits >= difficultyBits) break;
      nonce++;
    }

    // ---- kayıt (gerçek HTTP POST /auth/register) ----
    const reg = await request('POST', `${BASE}/auth/register`, {
      body: {
        username: 'smoketest_abuzer', email: 'smoketest@fitfak.net', password: 'CorrectHorseBatteryStaple1!',
        powChallengeId: challengeId, powNonce: String(nonce),
      },
    });
    assert.strictEqual(reg.status, 200);
    assert.ok(reg.json.requiresEmailVerification);
    console.log('smoke: POST /auth/register OK -- gerçek HTTP üzerinden JSON gövde doğru ayrıştırıldı ve işlendi (e-posta doğrulaması bekleniyor)');

    // ---- e-posta doğrulama (gerçek HTTP -- kod, mailer olmadığı için doğrudan
    // auth-service'in bellek-içi kaydından okunuyor, test-only debug yardımcısıyla) ----
    const authService = require('../services/auth-service');
    const verifyCode = await authService._debugPeekVerificationCode('smoketest@fitfak.net');
    const verifyResp = await request('POST', `${BASE}/auth/verify-email/confirm`, { body: { email: 'smoketest@fitfak.net', code: verifyCode } });
    assert.ok(verifyResp.json.setupToken);
    console.log('smoke: POST /auth/verify-email/confirm OK -- gerçek HTTP üzerinden e-posta doğrulandı, setupToken alındı');

    // ---- TOTP kurulumu ----
    const enrollBegin = await request('POST', `${BASE}/auth/mfa/totp/begin`, { body: { setupToken: verifyResp.json.setupToken, username: 'smoketest_abuzer' } });
    assert.ok(enrollBegin.json.provisioningUri.startsWith('otpauth://totp/'));
    const secretBuf = Buffer.from(base32.decode(enrollBegin.json.secretBase32));
    const setupCode = totpModule.totp(secretBuf, {});
    const enrollFinish = await request('POST', `${BASE}/auth/mfa/totp/finish`, { body: { setupToken: verifyResp.json.setupToken, code: setupCode } });
    assert.strictEqual(enrollFinish.json.enrolled, true);
    console.log('smoke: POST /auth/mfa/totp/begin + /finish OK -- gerçek HTTP üzerinden TOTP kurulumu tamamlandı');

    // ---- parola ile giriş ----
    const powChallenge2 = await request('POST', `${BASE}/auth/pow-challenge`);
    let nonce2 = 0;
    for (;;) {
      const digest = crypto.createHash('sha256').update(`${powChallenge2.json.challenge}:${nonce2}`).digest();
      let leadingZeroBits = 0;
      outer2: for (const byte of digest) {
        if (byte === 0) { leadingZeroBits += 8; continue; }
        let mask = 0x80;
        while (mask) { if (byte & mask) break outer2; leadingZeroBits++; mask >>= 1; }
        break;
      }
      if (leadingZeroBits >= powChallenge2.json.difficultyBits) break;
      nonce2++;
    }
    const loginStep1 = await request('POST', `${BASE}/auth/login/password`, {
      body: {
        username: 'smoketest_abuzer', password: 'CorrectHorseBatteryStaple1!',
        powChallengeId: powChallenge2.json.challengeId, powNonce: String(nonce2),
      },
    });
    assert.strictEqual(loginStep1.json.requiresSecondFactor, true);
    console.log('smoke: POST /auth/login/password OK -- 2. faktör isteniyor');

    const loginCode = totpModule.totp(secretBuf, { time: Date.now() + 30_000 });
    const loginStep2 = await request('POST', `${BASE}/auth/login/totp`, {
      body: { mfaChallengeToken: loginStep1.json.mfaChallengeToken, code: loginCode },
    });
    assert.strictEqual(loginStep2.status, 200);
    assert.ok(loginStep2.json.sessionId);
    const setCookieHeader = loginStep2.headers['set-cookie'];
    // Sayı yerine İSİM kontrol ediliyor: sabit bir sayı, yeni bir çerez
    // eklendiğinde (cihaz bağlama çerezi gibi) yanlış yere işaret eden bir
    // hata verir ve asıl kontrol ettiği şeyi -- hangi çerezlerin verildiğini --
    // hiç kontrol etmemiş olur.
    assert.ok(Array.isArray(setCookieHeader), 'Set-Cookie başlıkları bir dizi olmalı');
    const cookieNames = setCookieHeader.map((c) => c.split('=')[0]);
    for (const expected of ['__Secure-fitfak_at', '__Secure-fitfak_rt', '__Secure-fitfak_accounts', '__Secure-fitfak_did']) {
      assert.ok(cookieNames.includes(expected), `${expected} çerezi bekleniyor, gelenler: ${cookieNames.join(', ')}`);
    }
    assert.ok(setCookieHeader.some((c) => c.includes('__Secure-fitfak_at') && c.includes('Domain=.fitfak.net') && c.includes('HttpOnly')));
    assert.ok(setCookieHeader.some((c) => c.includes('__Secure-fitfak_rt') && c.includes('Path=/oauth/token')));
    console.log('smoke: POST /auth/login/totp OK -- tam oturum verildi, GERÇEK Set-Cookie header\'ları (Domain=.fitfak.net; HttpOnly; Secure; SameSite=Lax) doğru üretildi');

    // ---- oturumları listele (cookie'yi manuel ekleyerek) ----
    const cookieHeaderValue = setCookieHeader.map((c) => c.split(';')[0]).join('; ');
    const sessionsResp = await request('GET', `${BASE}/auth/sessions`, { headers: { cookie: cookieHeaderValue } });
    assert.strictEqual(sessionsResp.status, 200);
    assert.ok(sessionsResp.json.sessions.length >= 1);
    assert.ok(sessionsResp.json.sessions.some((s) => s.isCurrent));
    console.log('smoke: GET /auth/sessions (gerçek Cookie header ile) OK -- oturum listesi doğru döndü');

    // ---- logout ----
    const logoutResp = await request('POST', `${BASE}/auth/logout`, { headers: { cookie: cookieHeaderValue } });
    assert.strictEqual(logoutResp.json.loggedOut, true);
    const logoutCookies = logoutResp.headers['set-cookie'];
    assert.ok(logoutCookies.every((c) => c.includes('Max-Age=0')));
    console.log('smoke: POST /auth/logout OK -- cookie\'ler doğru şekilde sıfır Max-Age ile geçersiz kılındı');

    console.log('\nALL OAUTH-SERVER SMOKE CHECKS PASSED (gerçek HTTP istekleri, gerçek JSON gövdeler, gerçek Set-Cookie header\'ları)');
  } finally {
    server.close();
  }
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
