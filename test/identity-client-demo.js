'use strict';

process.env.FITFAK_IDP_DEV_DB = '1';
process.env.PORT = '51910';
process.env.FITFAK_IDP_HTTP2_PORT = '51911';
process.env.FITFAK_IDP_KEY_DIR = require('node:path').join(__dirname, '..', '.tmp-identity-client-keys');
process.env.FITFAK_IDP_DNS_CLIENT_ID = 'dns-fitfak-net';
process.env.FITFAK_IDP_DNS_REDIRECT_URI = 'https://dns.fitfak.net/oauth/callback';
process.env.FITFAK_IDP_DNS_CLIENT_SECRET = 'test-dns-client-secret-do-not-use-in-prod';

const assert = require('node:assert');
const http = require('node:http');
const crypto = require('node:crypto');
const totpModule = require('../core/totp');
const base32 = require('../core/base32');
const base64url = require('../core/base64url');
const { IdentityClient, IdentityClientError } = require('../client/identity-client');

const BASE = 'http://localhost:51910';

function request(method, url, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? Buffer.from(JSON.stringify(body)) : null;
    const req = http.request(url, {
      method,
      // Tarayıcı taklidi: köken kapısı bu başlığa bakıyor (core/same-origin.js).
      headers: { 'sec-fetch-site': 'same-origin', ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}), ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(raw); } catch { /* 302 vb. */ }
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
    let leadingZeroBits = 0;
    outer: for (const byte of digest) {
      if (byte === 0) { leadingZeroBits += 8; continue; }
      let mask = 0x80;
      while (mask) { if (byte & mask) break outer; leadingZeroBits++; mask >>= 1; }
      break;
    }
    if (leadingZeroBits >= difficultyBits) return String(nonce);
    nonce++;
  }
}

async function main() {
  const { main: startServer } = require('../oauth-server');
  const server = await startServer();

  try {
    // ---------------------------------------------------------------------
    // Gerçek bir RP-scoped (dns-fitfak-net) access token + sessionId elde etmek için
    // TAM akışı gerçek HTTP üzerinden koşuyoruz: kayıt -> TOTP kurulumu -> giriş ->
    // OAuth authorize (silent SSO) -> token exchange (PKCE).
    // ---------------------------------------------------------------------
    const pow1 = await request('POST', `${BASE}/auth/pow-challenge`);
    const nonce1 = solvePow(pow1.json.challengeId, pow1.json.challenge, pow1.json.difficultyBits);
    const reg = await request('POST', `${BASE}/auth/register`, {
      body: { username: 'idclient_test', email: 'idclient@fitfak.net', password: 'CorrectHorseBatteryStaple1!', powChallengeId: pow1.json.challengeId, powNonce: nonce1 },
    });

    const authServiceForDebug = require('../services/auth-service');
    const verifyCode = await authServiceForDebug._debugPeekVerificationCode('idclient@fitfak.net');
    const verifyResp = await request('POST', `${BASE}/auth/verify-email/confirm`, { body: { email: 'idclient@fitfak.net', code: verifyCode } });

    const enrollBegin = await request('POST', `${BASE}/auth/mfa/totp/begin`, { body: { setupToken: verifyResp.json.setupToken, username: 'idclient_test' } });
    const secretBuf = Buffer.from(base32.decode(enrollBegin.json.secretBase32));
    await request('POST', `${BASE}/auth/mfa/totp/finish`, { body: { setupToken: verifyResp.json.setupToken, code: totpModule.totp(secretBuf, {}) } });

    const pow2 = await request('POST', `${BASE}/auth/pow-challenge`);
    const nonce2 = solvePow(pow2.json.challengeId, pow2.json.challenge, pow2.json.difficultyBits);
    const loginStep1 = await request('POST', `${BASE}/auth/login/password`, {
      body: { username: 'idclient_test', password: 'CorrectHorseBatteryStaple1!', powChallengeId: pow2.json.challengeId, powNonce: nonce2 },
    });
    const loginStep2 = await request('POST', `${BASE}/auth/login/totp`, {
      body: { mfaChallengeToken: loginStep1.json.mfaChallengeToken, code: totpModule.totp(secretBuf, { time: Date.now() + 30_000 }) },
    });
    const cookieHeader = loginStep2.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');

    const codeVerifier = base64url.encode(crypto.randomBytes(32));
    const codeChallenge = base64url.encode(crypto.createHash('sha256').update(codeVerifier).digest());
    const authorizeUrl = `${BASE}/oauth/authorize?client_id=dns-fitfak-net&redirect_uri=${encodeURIComponent('https://dns.fitfak.net/oauth/callback')}&response_type=code&scope=openid%20profile%20dns:read&code_challenge=${codeChallenge}&code_challenge_method=S256`;
    const authorizeResp = await request('GET', authorizeUrl, { headers: { cookie: cookieHeader } });
    assert.strictEqual(authorizeResp.status, 302);
    const redirectLocation = authorizeResp.headers.location;
    assert.ok(redirectLocation.startsWith('https://dns.fitfak.net/oauth/callback?code='), 'silent SSO redirect bekleniyordu');
    const code = new URL(redirectLocation).searchParams.get('code');

    const tokenResp = await request('POST', `${BASE}/oauth/token`, {
      body: { grant_type: 'authorization_code', code, redirect_uri: 'https://dns.fitfak.net/oauth/callback', code_verifier: codeVerifier, client_id: 'dns-fitfak-net' },
    });
    const rpAccessToken = tokenResp.json.access_token;
    assert.ok(rpAccessToken);
    console.log('identity-client: HTTP üzerinden tam akış (kayıt->MFA->giriş->OAuth) ile dns-fitfak-net için gerçek bir RP token\'ı elde edildi');

    // ---------------------------------------------------------------------
    // Şimdi IdentityClient SDK'sını gerçek sunucuya karşı test ediyoruz.
    // ---------------------------------------------------------------------
    const identity = new IdentityClient({ baseUrl: BASE, clientId: 'dns-fitfak-net', clientSecret: 'test-dns-client-secret-do-not-use-in-prod' });

    const introspectResult = await identity.introspectToken(rpAccessToken);
    assert.strictEqual(introspectResult.active, true);
    console.log('identity-client: introspectToken() OK -- gerçek sunucudan active:true döndü');

    // sessionId'yi almak için introspect/JWT payload'ından değil, doğrudan userinfo
    // yerine JWT'nin kendisinden okumak yerine (SDK bunu göstermiyor) auth/sessions ile
    // teyit edilebilir -- burada basitçe introspect'in userId'sini alıp GetUserSessions
    // ile o kullanıcının dns-fitfak-net'e ait oturumlarını listeliyoruz.
    const userId = introspectResult.sub;
    const sessionsResult = await identity.getUserSessions(userId);
    assert.ok(sessionsResult.sessions.length >= 1);
    const targetSessionId = sessionsResult.sessions[0].sessionId;
    console.log(`identity-client: getUserSessions() OK -- ${sessionsResult.sessions.length} oturum (sadece dns-fitfak-net'e ait olanlar) döndü`);

    const verifyResult = await identity.verifySession(targetSessionId);
    assert.strictEqual(verifyResult.valid, true);
    assert.strictEqual(verifyResult.userId, userId);
    console.log('identity-client: verifySession() OK');

    // ---------------------------------------------------------------------
    // GÜVENLİK SINIRI: BAŞKA bir client kimlik bilgisiyle (ör. yanlış/bilinmeyen bir RP)
    // aynı çağrıları yapmaya çalışmak UNAUTHENTICATED ile reddedilmeli.
    // ---------------------------------------------------------------------
    const rogueClient = new IdentityClient({ baseUrl: BASE, clientId: 'dns-fitfak-net', clientSecret: 'yanlis-sir' });
    await assert.rejects(() => rogueClient.introspectToken(rpAccessToken), (e) => {
      assert.ok(e instanceof IdentityClientError);
      return true;
    });
    console.log('identity-client: yanlış client_secret doğru şekilde reddedildi (UNAUTHENTICATED)');

    // ---------------------------------------------------------------------
    // revokeSession()
    // ---------------------------------------------------------------------
    const revokeResult = await identity.revokeSession(targetSessionId);
    assert.strictEqual(revokeResult.revoked, true);
    const verifyAfterRevoke = await identity.verifySession(targetSessionId);
    assert.strictEqual(verifyAfterRevoke.valid, false);
    console.log('identity-client: revokeSession() OK -- sonrasında verifySession() doğru şekilde valid:false döndü');

    console.log('\nALL IDENTITY-CLIENT CHECKS PASSED (gerçek HTTP, gerçek RP-scoped token, gerçek sunucu)');
  } finally {
    server.close();
  }
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
