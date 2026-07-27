'use strict';

process.env.FITFAK_IDP_DEV_DB = '1';
process.env.PORT = '51930';
process.env.FITFAK_IDP_HTTP2_PORT = '51931';
process.env.FITFAK_IDP_KEY_DIR = require('node:path').join(__dirname, '..', '.tmp-multiacct-keys');
process.env.FITFAK_IDP_DNS_CLIENT_ID = 'dns-fitfak-net';
process.env.FITFAK_IDP_DNS_CLIENT_SECRET = 'test-dns-client-secret-do-not-use-in-prod';
process.env.FITFAK_IDP_DNS_REDIRECT_URI = 'https://dns.fitfak.net/oauth/callback';

const assert = require('node:assert');
const http = require('node:http');
const crypto = require('node:crypto');
const totpModule = require('../core/totp');
const base32 = require('../core/base32');

const BASE = 'http://localhost:51930';

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

// Basit çerez kavanozu -- gerçek bir tarayıcının Set-Cookie'leri BİRİKTİRMESİNİ taklit
// eder (her yanıttaki YENİ cookie'ler öncekilerin ÜZERİNE yazılır, isim bazında).
function makeCookieJar() {
  const jar = new Map();
  return {
    apply(setCookieHeaders) {
      (setCookieHeaders || []).forEach((raw) => {
        const [pair] = raw.split(';');
        const idx = pair.indexOf('=');
        jar.set(pair.slice(0, idx), pair.slice(idx + 1));
      });
    },
    header() { return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; '); },
  };
}

async function registerAndFullyLogin(jar, { username, email }) {
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
    headers: { cookie: jar.header() },
  });
  const loginStep2 = await request('POST', `${BASE}/auth/login/totp`, {
    body: { mfaChallengeToken: loginStep1.json.mfaChallengeToken, code: totpModule.totp(secretBuf, { time: Date.now() + 30_000 }) },
    headers: { cookie: jar.header() },
  });
  jar.apply(loginStep2.headers['set-cookie']);
  return loginStep2.json.sessionId;
}

async function main() {
  const { main: startServer } = require('../oauth-server');
  const server = await startServer();

  try {
    const jar = makeCookieJar();

    // ---- Hesap A ile giriş ----
    const sessionA = await registerAndFullyLogin(jar, { username: 'multiacct_a', email: 'multiacct_a@fitfak.net' });
    let accountsResp = await request('GET', `${BASE}/auth/accounts`, { headers: { cookie: jar.header() } });
    assert.strictEqual(accountsResp.json.accounts.length, 1);
    assert.strictEqual(accountsResp.json.accounts[0].isActive, true);
    console.log('multi-account: Hesap A ile giriş sonrası accounts listesinde 1 hesap var (aktif)');

    // ---- AYNI tarayıcıda (aynı cookie kavanozu) Hesap B ile de giriş yap ----
    const sessionB = await registerAndFullyLogin(jar, { username: 'multiacct_b', email: 'multiacct_b@fitfak.net' });
    accountsResp = await request('GET', `${BASE}/auth/accounts`, { headers: { cookie: jar.header() } });
    assert.strictEqual(accountsResp.json.accounts.length, 2, 'iki hesap da listede olmalı (B eklendi, A silinmedi)');
    const bEntry = accountsResp.json.accounts.find((a) => a.sessionId === sessionB);
    assert.strictEqual(bEntry.isActive, true, 'en son giriş yapılan (B) şu an aktif olmalı');
    console.log('multi-account: Hesap B ile de giriş yapıldı -- accounts listesinde artık 2 hesap var, A silinmedi, B aktif');

    // ---- /oauth/authorize: 2 hesap varken SESSİZCE birini seçmek yerine seçim ekranına yönlendirmeli ----
    const authorizeResp = await request('GET', `${BASE}/oauth/authorize?client_id=dns-fitfak-net&redirect_uri=${encodeURIComponent('https://dns.fitfak.net/oauth/callback')}&response_type=code&scope=openid`, { headers: { cookie: jar.header() } });
    assert.strictEqual(authorizeResp.status, 302);
    assert.ok(authorizeResp.headers.location.includes('choose_account=1'), 'hesap seçici ekranına yönlendirilmeli, sessizce SSO YAPILMAMALI');
    console.log('multi-account: /oauth/authorize -- 2 geçerli hesap varken SESSİZCE seçmek yerine doğru şekilde hesap seçiciye yönlendirdi');

    // ---- Hesap A'ya geç ----
    const switchResp = await request('POST', `${BASE}/auth/switch-account`, { body: { sessionId: sessionA }, headers: { cookie: jar.header() } });
    assert.strictEqual(switchResp.json.switched, true);
    assert.strictEqual(switchResp.json.username, 'multiacct_a');
    jar.apply(switchResp.headers['set-cookie']);
    accountsResp = await request('GET', `${BASE}/auth/accounts`, { headers: { cookie: jar.header() } });
    assert.ok(accountsResp.json.accounts.find((a) => a.username === 'multiacct_a').isActive);
    assert.strictEqual(accountsResp.json.accounts.length, 2, 'hesap değiştirmek listeyi küçültmemeli, sadece aktifi değiştirmeli');
    console.log('multi-account: switch-account ile Hesap A aktif hale getirildi, Hesap B listede kalmaya devam ediyor');

    // ---- normal logout: sadece aktif hesabı (A) çıkarır, B listede kalır ----
    const logoutResp = await request('POST', `${BASE}/auth/logout`, { headers: { cookie: jar.header() } });
    assert.strictEqual(logoutResp.json.loggedOut, true);
    jar.apply(logoutResp.headers['set-cookie']);
    accountsResp = await request('GET', `${BASE}/auth/accounts`, { headers: { cookie: jar.header() } });
    assert.strictEqual(accountsResp.json.accounts.length, 1, 'normal logout SADECE aktif hesabı kaldırmalı');
    assert.strictEqual(accountsResp.json.accounts[0].username, 'multiacct_b');
    console.log('multi-account: normal /auth/logout SADECE Hesap A\'yı kaldırdı, Hesap B hâlâ bu tarayıcıda açık');

    // ---- artık TEK hesap (B) kaldığı için authorize SESSİZCE (seçici olmadan) çalışmalı ----
    const authorizeResp2 = await request('GET', `${BASE}/oauth/authorize?client_id=dns-fitfak-net&redirect_uri=${encodeURIComponent('https://dns.fitfak.net/oauth/callback')}&response_type=code&scope=openid&code_challenge=x&code_challenge_method=S256`, { headers: { cookie: jar.header() } });
    assert.strictEqual(authorizeResp2.status, 302);
    assert.ok(!authorizeResp2.headers.location.includes('choose_account'), 'tek hesap kaldığında seçici GÖSTERİLMEMELİ, doğrudan silent SSO olmalı');
    console.log('multi-account: sadece 1 hesap kalınca authorize() tekrar sessizce (seçici olmadan) çalışıyor');

    // ---- logout-all: kalan tek hesabı da temizler ----
    const logoutAllResp = await request('POST', `${BASE}/auth/logout-all`, { headers: { cookie: jar.header() } });
    assert.strictEqual(logoutAllResp.json.loggedOut, true);
    assert.strictEqual(logoutAllResp.json.count, 1);
    jar.apply(logoutAllResp.headers['set-cookie']);
    accountsResp = await request('GET', `${BASE}/auth/accounts`, { headers: { cookie: jar.header() } });
    assert.strictEqual(accountsResp.json.accounts.length, 0);
    console.log('multi-account: /auth/logout-all kalan tüm hesapları temizledi');

    console.log('\nALL MULTI-ACCOUNT CHECKS PASSED (Microsoft/Google tarzı hesap seçici, gerçek HTTP + çerez kavanozu ile)');
  } finally {
    server.close();
  }
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
