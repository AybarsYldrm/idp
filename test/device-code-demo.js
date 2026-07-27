'use strict';

process.env.FITFAK_IDP_DEV_DB = '1';
process.env.PORT = '51940';
process.env.FITFAK_IDP_HTTP2_PORT = '51941';
process.env.FITFAK_IDP_KEY_DIR = require('node:path').join(__dirname, '..', '.tmp-devicecode-keys');
process.env.FITFAK_IDP_DNS_CLIENT_ID = 'dns-fitfak-net';
process.env.FITFAK_IDP_DNS_CLIENT_SECRET = 'test-dns-client-secret-do-not-use-in-prod';
process.env.FITFAK_IDP_DNS_REDIRECT_URI = 'https://dns.fitfak.net/oauth/callback';
process.env.FITFAK_IDP_DEVICE_POLL_INTERVAL_S = '1';

const assert = require('node:assert');
const http = require('node:http');
const crypto = require('node:crypto');
const totpModule = require('../core/totp');
const base32 = require('../core/base32');
const { deviceLogin } = require('../client/device-login');

const BASE = 'http://localhost:51940';

function request(method, url, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? Buffer.from(JSON.stringify(body)) : null;
    const req = http.request(url, {
      method,
      headers: { ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}), ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(raw); } catch { /* boş */ }
        resolve({ status: res.statusCode, headers: res.headers, json });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function solvePow(challengeId, challenge, difficultyBits) {
  let nonce = 0;
  for (;;) {
    const digest = crypto.createHash('sha256').update(`${challenge}:${nonce}`).digest();
    let lz = 0;
    outer: for (const b of digest) {
      if (b === 0) { lz += 8; continue; }
      let m = 0x80;
      while (m) { if (b & m) break outer; lz++; m >>= 1; }
      break;
    }
    if (lz >= difficultyBits) return String(nonce);
    nonce++;
  }
}

async function registerAndLogin({ username, email }) {
  const pow1 = await request('POST', `${BASE}/auth/pow-challenge`);
  const nonce1 = solvePow(pow1.json.challengeId, pow1.json.challenge, pow1.json.difficultyBits);
  await request('POST', `${BASE}/auth/register`, {
    body: {
      username, email, password: 'CorrectHorseBatteryStaple1!', powChallengeId: pow1.json.challengeId, powNonce: nonce1,
    },
  });
  const authService = require('../services/auth-service');
  const verifyCode = await authService._debugPeekVerificationCode(email);
  const verifyResp = await request('POST', `${BASE}/auth/verify-email/confirm`, { body: { email, code: verifyCode } });
  const enrollBegin = await request('POST', `${BASE}/auth/mfa/totp/begin`, { body: { setupToken: verifyResp.json.setupToken, username } });
  const secretBuf = Buffer.from(base32.decode(enrollBegin.json.secretBase32));
  await request('POST', `${BASE}/auth/mfa/totp/finish`, { body: { setupToken: verifyResp.json.setupToken, code: totpModule.totp(secretBuf, {}) } });

  const pow2 = await request('POST', `${BASE}/auth/pow-challenge`);
  const nonce2 = solvePow(pow2.json.challengeId, pow2.json.challenge, pow2.json.difficultyBits);
  const loginStep1 = await request('POST', `${BASE}/auth/login/password`, {
    body: { username, password: 'CorrectHorseBatteryStaple1!', powChallengeId: pow2.json.challengeId, powNonce: nonce2 },
  });
  const loginStep2 = await request('POST', `${BASE}/auth/login/totp`, {
    body: { mfaChallengeToken: loginStep1.json.mfaChallengeToken, code: totpModule.totp(secretBuf, { time: Date.now() + 30_000 }) },
  });
  const cookieHeader = loginStep2.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');
  return { cookieHeader };
}

async function main() {
  const { main: startServer } = require('../oauth-server');
  const server = await startServer();

  try {
    const { cookieHeader } = await registerAndLogin({ username: 'devicecode_user', email: 'devicecode_user@fitfak.net' });
    console.log('device-code: test kullanıcısı kayıt+MFA+giriş ile hazırlandı');

    // ---------------------------------------------------------------------
    // 1) MUTLU YOL: gerçek deviceLogin() CLI yardımcısı + "başka bir tarayıcıda" onay
    // ---------------------------------------------------------------------
    let capturedUserCode = null;
    let capturedVerificationUri = null;
    const loginPromise = deviceLogin({
      baseUrl: BASE,
      clientId: 'dns-fitfak-net',
      onPrompt: ({ userCode, verificationUri }) => {
        capturedUserCode = userCode;
        capturedVerificationUri = verificationUri;
      },
    });

    // deviceLogin()'in POST /oauth/device/code'u tamamlayıp onPrompt'u çağırmasını bekle
    for (let i = 0; i < 50 && !capturedUserCode; i++) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(capturedUserCode, 'onPrompt çağrılmalıydı');
    assert.ok(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(capturedUserCode), `user_code beklenen XXXX-XXXX biçiminde değil: ${capturedUserCode}`);
    assert.strictEqual(capturedVerificationUri, 'https://session.fitfak.net/device');
    console.log(`device-code: kullanıcıya gösterilecek kod üretildi (${capturedUserCode}), doğru biçimde`);

    // "başka bir tarayıcıda" giriş yapmış kullanıcının kodu görüp onaylaması
    const infoResp = await request('GET', `${BASE}/device/info?user_code=${encodeURIComponent(capturedUserCode)}`);
    assert.strictEqual(infoResp.status, 200);
    assert.strictEqual(infoResp.json.clientName, 'DNS Paneli');
    assert.strictEqual(infoResp.json.status, 'pending');
    console.log('device-code: /device/info doğru client adını ve pending durumunu döndürdü');

    const approveResp = await request('POST', `${BASE}/device/approve`, {
      body: { userCode: capturedUserCode }, headers: { cookie: cookieHeader },
    });
    assert.strictEqual(approveResp.json.approved, true);
    console.log('device-code: /device/approve (giriş yapmış kullanıcının çerezleriyle) başarılı');

    // deviceLogin() promise'i artık çözülmeli (bir sonraki poll turunda)
    const tokens = await loginPromise;
    assert.ok(tokens.accessToken && tokens.refreshToken);
    console.log('device-code: deviceLogin() CLI yardımcısı poll ederek gerçek token çifti aldı');

    // token gerçekten geçerli mi -- introspect ile doğrula
    const introspectResp = await request('POST', `${BASE}/oauth/introspect`, {
      body: { token: tokens.accessToken },
      headers: { 'x-client-id': 'dns-fitfak-net', 'x-client-secret': 'test-dns-client-secret-do-not-use-in-prod' },
    });
    assert.strictEqual(introspectResp.json.active, true);
    assert.strictEqual(introspectResp.json.aud, 'dns-fitfak-net');
    console.log('device-code: alınan access token introspect ile doğrulandı -- active:true, doğru aud');

    // aynı user_code ikinci kez onaylanamaz (kod tek kullanımlık tüketildi)
    const reApprove = await request('POST', `${BASE}/device/approve`, {
      body: { userCode: capturedUserCode }, headers: { cookie: cookieHeader },
    });
    assert.strictEqual(reApprove.status, 400);
    console.log('device-code: tüketilmiş bir user_code\'u tekrar onaylamaya çalışmak doğru şekilde reddedildi');

    // ---------------------------------------------------------------------
    // 2) REDDETME YOLU
    // ---------------------------------------------------------------------
    let capturedUserCode2 = null;
    const loginPromise2 = deviceLogin({
      baseUrl: BASE,
      clientId: 'dns-fitfak-net',
      onPrompt: ({ userCode }) => { capturedUserCode2 = userCode; },
    });
    for (let i = 0; i < 50 && !capturedUserCode2; i++) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, 20));
    }
    await request('POST', `${BASE}/device/deny`, { body: { userCode: capturedUserCode2 }, headers: { cookie: cookieHeader } });
    await assert.rejects(() => loginPromise2, (e) => e.code === 'access_denied');
    console.log('device-code: reddedilen bir istek deviceLogin() tarafında doğru şekilde access_denied hatası verdi');

    // ---------------------------------------------------------------------
    // 3) GEÇERSİZ KOD
    // ---------------------------------------------------------------------
    const badInfo = await request('GET', `${BASE}/device/info?user_code=ZZZZ-9999`);
    assert.strictEqual(badInfo.status, 400);
    console.log('device-code: bilinmeyen user_code doğru şekilde reddedildi');

    // ---------------------------------------------------------------------
    // 4) RFC 8628 slow_down: interval'den DAHA HIZLI poll edilirse açıkça bildirilmeli
    // ---------------------------------------------------------------------
    const startResp = await request('POST', `${BASE}/oauth/device/code`, { body: { client_id: 'dns-fitfak-net' } });
    const fastPoll1 = await request('POST', `${BASE}/oauth/token`, {
      body: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: startResp.json.device_code, client_id: 'dns-fitfak-net' },
    });
    assert.strictEqual(fastPoll1.json.error, 'authorization_pending', 'ilk poll normal şekilde authorization_pending dönmeli');
    // interval (1sn) BEKLEMEDEN hemen tekrar sorgula
    const fastPoll2 = await request('POST', `${BASE}/oauth/token`, {
      body: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: startResp.json.device_code, client_id: 'dns-fitfak-net' },
    });
    assert.strictEqual(fastPoll2.json.error, 'slow_down', 'interval\'den hızlı ikinci poll slow_down döndürmeli');
    console.log('device-code: RFC 8628 slow_down -- interval\'den hızlı poll doğru şekilde tespit edildi ve bildirildi');

    console.log('\nALL DEVICE-CODE CHECKS PASSED (RFC 8628, gerçek CLI yardımcısı + gerçek HTTP sunucusu ile)');
  } finally {
    server.close();
  }
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
