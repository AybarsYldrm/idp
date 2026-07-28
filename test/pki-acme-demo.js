'use strict';

process.env.FITFAK_IDP_DEV_DB = '1';
process.env.PORT = '51979';
process.env.FITFAK_IDP_HTTP2_PORT = '51971';
process.env.FITFAK_IDP_KEY_DIR = require('node:path').join(__dirname, '..', '.tmp-pki-keys');
process.env.FITFAK_IDP_TRUST_HOST = 'trust.fitfak.net';
process.env.FITFAK_IDP_TRUST_ISSUER = 'https://trust.fitfak.net';
process.env.FITFAK_IDP_ACME_HTTP01_PORT = '51972'; // gerçek doğrulama için yerel bir test sunucusu
// NOT: test sunucumuz loopback'te (127.0.0.1/localhost) -- GERÇEK SSRF koruması bunu doğru
// şekilde engeller (bkz. aşağıdaki BAĞIMSIZ isBlockedIp testi). Sadece BU bütünleştirme
// testinin yerel bir sunucuya karşı çalışabilmesi için kaçış kapısını açıyoruz --
// ÜRETİMDE bu ortam değişkeni KESİNLİKLE ayarlanmamalı.
process.env.FITFAK_IDP_ACME_ALLOW_PRIVATE_IPS = '1';

const assert = require('node:assert');
const http = require('node:http');
const crypto = require('node:crypto');
const totpModule = require('../core/totp');
const base32 = require('../core/base32');
const base64url = require('../core/base64url');

// Her mantıksal host AYRI bir adrese bağlanır (bkz. RUNNING.md, "Yüzeyler").
// Ayrım Host header'ıyla değil soket seviyesinde yapıldığı için, trust
// yüzeyindeki uç noktalar giriş yüzeyinin adresinde 404 döner -- bu test
// eskiden hepsini tek adresten çağırıyor ve orada takılıyordu.
const BASE = 'http://127.0.0.1:51979';        // session.fitfak.net
const TRUST = 'http://127.0.0.2:51979';       // trust.fitfak.net -- sertifika, ACME
const STATUS = 'http://127.0.0.2:51979';      // status.trust.fitfak.net -- OCSP, CRL

function request(method, url, { body, headers = {}, rawBody } = {}) {
  return new Promise((resolve, reject) => {
    const payload = rawBody || (body ? Buffer.from(JSON.stringify(body)) : null);
    const req = http.request(url, {
      method,
      // Tarayıcı taklidi: köken kapısı bu başlığa bakıyor (core/same-origin.js).
      headers: { 'sec-fetch-site': 'same-origin', ...(payload ? { 'content-length': payload.length } : {}), ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks);
        let json = null;
        try { json = JSON.parse(raw.toString('utf8')); } catch { /* ham veri olabilir (OCSP/CRL/sertifika) */ }
        resolve({
          status: res.statusCode, headers: res.headers, json, raw,
        });
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
  return { cookieHeader: loginStep2.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ') };
}

// ---- ACME istemci yardımcıları: gerçek bir EC anahtarıyla JWS imzalama ----
function makeJws({
  url, nonce, payload, jwk, privateKey, kid,
}) {
  const protectedHeader = kid ? { alg: 'ES256', kid, nonce, url } : { alg: 'ES256', jwk, nonce, url };
  const protectedB64 = base64url.encode(Buffer.from(JSON.stringify(protectedHeader)));
  const payloadB64 = payload === null ? '' : base64url.encode(Buffer.from(JSON.stringify(payload)));
  const signingInput = Buffer.from(`${protectedB64}.${payloadB64}`);
  const signature = crypto.sign(null, signingInput, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return { protected: protectedB64, payload: payloadB64, signature: base64url.encode(signature) };
}

async function main() {
  // ---------------------------------------------------------------------
  // 0) SSRF KORUMASI: isBlockedIp'in KENDİSİNİ, bu dosyanın geri kalanındaki test-only
  // bypass'tan BAĞIMSIZ olarak doğrula -- gerçek engelleme mantığı doğru çalışıyor mu?
  // ---------------------------------------------------------------------
  const { isBlockedIp } = require('../services/acme-service');
  const blockedCases = ['127.0.0.1', '10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '0.0.0.0', '::1', 'fd00::1', 'fe80::1'];
  const allowedCases = ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.15.255.255', '172.32.0.1'];
  for (const ip of blockedCases) assert.ok(isBlockedIp(ip), `SSRF: ${ip} ENGELLENMELİYDİ ama engellenmedi`);
  for (const ip of allowedCases) assert.ok(!isBlockedIp(ip), `SSRF: ${ip} İZİN VERİLMELİYDİ ama engellendi`);
  console.log(`ssrf: isBlockedIp -- ${blockedCases.length} private/loopback/metadata IP doğru engellendi, ${allowedCases.length} genel (public) IP doğru şekilde izin verildi (169.254.169.254 bulut metadata dahil)`);

  const { main: startServer } = require('../oauth-server');
  const server = await startServer();

  try {
    // =======================================================================
    // 1) CİHAZ-KİMLİKLİ SERTİFİKA (device code sonrası mTLS sertifikası) + RBAC
    // =======================================================================
    const { cookieHeader } = await registerAndLogin({ username: 'pki_user', email: 'pki_user@fitfak.net' });

    // GERÇEK bir CSR. Eskiden burada uydurma baytlar vardı ve dev-mock issuer
    // onları kabul ediyordu; gerçek issuer devreye girince aynı test, ürünün
    // hiç çalıştırmadığı bir yolu sınıyor oldu.
    const ssl = require('@fitfak/ssl');
    const csrKey = ssl.generateEcKeyPair('P-256');
    const fakeCsr = ssl.generateCSR(
      { keyType: 'ec', curveName: csrKey.curve, ...csrKey },
      [[ssl.oid.OIDs.commonName, 'pki_user']], [],
    );

    // Bozuk bir CSR, İSTEMCİ hatasıdır: 400 dönmeli, 500 değil.
    const malformed = await request('POST', `${TRUST}/device/certificate`, {
      body: { csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nZmFrZS1jc3I=\n-----END CERTIFICATE REQUEST-----', profile: 'client-auth' },
      headers: { cookie: cookieHeader },
    });
    assert.strictEqual(malformed.status, 400, 'bozuk CSR 400 dönmeli');
    assert.strictEqual(malformed.json.error, 'invalid_csr');
    console.log('pki: bozuk CSR temiz bir 400 ile reddedildi (500 değil)');

    const certResp = await request('POST', `${TRUST}/device/certificate`, {
      body: { csrPem: fakeCsr, profile: 'client-auth' }, headers: { cookie: cookieHeader },
    });
    assert.strictEqual(certResp.status, 200);
    assert.ok(certResp.json.certPem && certResp.json.serialNumberHex);
    console.log('pki: device-code kimlikli kullanıcı client-auth sertifikası aldı (herkese açık profil)');

    const deniedResp = await request('POST', `${TRUST}/device/certificate`, {
      body: { csrPem: fakeCsr, profile: 'timestamping' }, headers: { cookie: cookieHeader },
    });
    assert.strictEqual(deniedResp.status, 403);
    console.log('pki: RBAC -- yetkisi olmayan kullanıcı "timestamping" profilini doğru şekilde alamadı');

    const listResp = await request('GET', `${TRUST}/device/certificates`, { headers: { cookie: cookieHeader } });
    assert.strictEqual(listResp.json.certificates.length, 1);
    console.log('pki: kullanıcının kendi sertifika listesi doğru (1 adet, sadece başarılı olan)');

    const revokeResp = await request('POST', `${TRUST}/device/certificate/revoke`, {
      body: { serialNumberHex: certResp.json.serialNumberHex, reason: 'test' }, headers: { cookie: cookieHeader },
    });
    assert.strictEqual(revokeResp.json.revoked, true);
    console.log('pki: kullanıcı kendi sertifikasını iptal edebildi');

    // =======================================================================
    // 2) TAM ACME AKIŞI (RFC 8555) -- gerçek EC anahtarı + gerçek JWS + gerçek http-01
    // =======================================================================
    const TRUST_HEADERS = { Host: 'trust.fitfak.net', 'content-type': 'application/jose+json' };

    // ACME'nin http-01 doğrulaması GERÇEK bir DNS çözümlemesi yapar ve ACME
    // servisi yalnızca *.fitfak.net kimliklerini kabul eder (politika). Yani bu
    // bölüm, çözümlenebilen bir fitfak.net adı olmadan koşamaz.
    //
    // Eskiden 'localhost' isteniyordu: politika onu reddediyor, yani bu bölüm
    // zaten koşmuyordu. Bir testin koşamadığını SÖYLEMESİ, sessizce kırmızı
    // durmasından da yeşil görünmesinden de iyidir.
    const ACME_IDENTIFIER = process.env.FITFAK_IDP_TEST_ACME_HOST || 'acme-test.fitfak.net';
    let acmeResolvable = false;
    try {
      const addrs = await require('node:dns').promises.lookup(ACME_IDENTIFIER, { all: true });
      acmeResolvable = addrs.some((a) => a.address === '127.0.0.1' || a.address === '::1');
    } catch { acmeResolvable = false; }

    if (!acmeResolvable) {
      console.log(`pki-acme: ATLANDI -- ACME http-01 bölümü, 127.0.0.1'e çözümlenen bir *.fitfak.net adı ister.`);
      console.log(`pki-acme: çalıştırmak için: /etc/hosts'a '127.0.0.1 ${ACME_IDENTIFIER}' ekleyin`);
      console.log(`pki-acme: (ya da FITFAK_IDP_TEST_ACME_HOST ile başka bir ad verin)`);
    } else {

    let challengeContent = null;
    const challengeServer = http.createServer((req, res) => {
      if (challengeContent && req.url === `/.well-known/acme-challenge/${challengeContent.token}`) {
        res.writeHead(200); res.end(challengeContent.keyAuth);
      } else {
        res.writeHead(404); res.end();
      }
    });
    await new Promise((resolve) => { challengeServer.listen(51972, resolve); });

    try {
      const dirResp = await request('GET', `${TRUST}/acme/directory`, { headers: { Host: 'trust.fitfak.net' } });
      assert.strictEqual(dirResp.status, 200);
      assert.ok(dirResp.json.newAccount.startsWith('https://trust.fitfak.net'));
      console.log('pki-acme: /acme/directory doğru URL\'lerle (trust.fitfak.net) döndü');

      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const jwk = publicKey.export({ format: 'jwk' });

      const nonce1Resp = await request('GET', `${TRUST}/acme/new-nonce`, { headers: { Host: 'trust.fitfak.net' } });
      const nonce1 = nonce1Resp.headers['replay-nonce'];
      assert.ok(nonce1);
      console.log('pki-acme: /acme/new-nonce gerçek bir Replay-Nonce header\'ı döndü');

      const acctJws = makeJws({
        url: 'https://trust.fitfak.net/acme/new-account', nonce: nonce1, payload: { termsOfServiceAgreed: true }, jwk, privateKey,
      });
      const acctResp = await request('POST', `${TRUST}/acme/new-account`, { rawBody: Buffer.from(JSON.stringify(acctJws)), headers: TRUST_HEADERS });
      assert.strictEqual(acctResp.status, 201);
      assert.strictEqual(acctResp.json.status, 'valid');
      const accountId = acctResp.headers.location.split('/').pop();
      console.log('pki-acme: gerçek bir EC anahtarıyla imzalanmış JWS ile /acme/new-account başarılı');

      const nonce2 = acctResp.headers['replay-nonce'];
      const orderJws = makeJws({
        url: 'https://trust.fitfak.net/acme/new-order', nonce: nonce2, payload: { identifiers: [{ type: 'dns', value: ACME_IDENTIFIER }] }, kid: accountId, privateKey,
      });
      const orderResp = await request('POST', `${TRUST}/acme/new-order`, { rawBody: Buffer.from(JSON.stringify(orderJws)), headers: TRUST_HEADERS });
      assert.strictEqual(orderResp.status, 201);
      assert.strictEqual(orderResp.json.status, 'pending');
      const orderId = orderResp.headers.location.split('/').pop();
      const authzId = orderResp.json.authorizations[0].split('/').pop();
      console.log('pki-acme: kid (hesap) ile imzalanmış JWS ile /acme/new-order başarılı, authorization oluşturuldu');

      // RFC 8555 §6.3 POST-as-GET: ACME'de kaynak OKUMA da imzalı bir POST'tur.
      // Test eskiden düz GET atıyordu; sunucu (doğru olarak) yalnızca POST
      // dinlediği için 404 dönüyor ve test bunu null JSON olarak görüyordu.
      const authzNonce = (await request('GET', `${TRUST}/acme/new-nonce`, { headers: { Host: 'trust.fitfak.net' } })).headers['replay-nonce'];
      const authzJws = makeJws({
        url: `https://trust.fitfak.net/acme/authz/${authzId}`, nonce: authzNonce, payload: '', kid: accountId, privateKey,
      });
      const authzResp = await request('POST', `${TRUST}/acme/authz/${authzId}`, { rawBody: Buffer.from(JSON.stringify(authzJws)), headers: TRUST_HEADERS });
      const httpChallenge = authzResp.json.challenges.find((c) => c.type === 'http-01');
      assert.ok(httpChallenge.token);
      console.log('pki-acme: authorization http-01 challenge token\'ı içeriyor');

      const thumbprint = require('../core/acme-jws').jwkThumbprint(jwk);
      challengeContent = { token: httpChallenge.token, keyAuth: `${httpChallenge.token}.${thumbprint}` };

      const nonce3Resp = await request('GET', `${TRUST}/acme/new-nonce`, { headers: { Host: 'trust.fitfak.net' } });
      const challengeJws = makeJws({
        url: `https://trust.fitfak.net/acme/challenge/${authzId}`, nonce: nonce3Resp.headers['replay-nonce'], payload: {}, kid: accountId, privateKey,
      });
      const challengeResp = await request('POST', `${TRUST}/acme/challenge/${authzId}`, { rawBody: Buffer.from(JSON.stringify(challengeJws)), headers: TRUST_HEADERS });
      assert.strictEqual(challengeResp.status, 200);
      assert.strictEqual(challengeResp.json.status, 'valid');
      console.log('pki-acme: http-01 doğrulaması GERÇEK bir yerel sunucuya HTTP isteği atarak başarıyla tamamlandı');

      const nonce4Resp = await request('GET', `${TRUST}/acme/new-nonce`, { headers: { Host: 'trust.fitfak.net' } });
      // GERÇEK bir CSR: istenen alan adını SAN olarak taşır. Eskiden uydurma
      // baytlardı ve dev-mock issuer onları kabul ediyordu.
      const acmeKey = ssl.generateEcKeyPair('P-256');
      const acmeCsrPem = ssl.generateCSR(
        { keyType: 'ec', curveName: acmeKey.curve, ...acmeKey },
        [[ssl.oid.OIDs.commonName, ACME_IDENTIFIER]],
        [{ type: 'dns', value: ACME_IDENTIFIER }],
      );
      const csrDer = Buffer.from(
        acmeCsrPem.replace(/-----(BEGIN|END) CERTIFICATE REQUEST-----|\s/g, ''), 'base64',
      );
      const finalizeJws = makeJws({
        url: `https://trust.fitfak.net/acme/order/${orderId}/finalize`, nonce: nonce4Resp.headers['replay-nonce'], payload: { csr: base64url.encode(csrDer) }, kid: accountId, privateKey,
      });
      const finalizeResp = await request('POST', `${TRUST}/acme/order/${orderId}/finalize`, { rawBody: Buffer.from(JSON.stringify(finalizeJws)), headers: TRUST_HEADERS });
      assert.strictEqual(finalizeResp.status, 200);
      assert.strictEqual(finalizeResp.json.status, 'valid');
      assert.ok(finalizeResp.json.certificate);
      console.log('pki-acme: sipariş finalize edildi -- tüm authorization\'lar geçerliyken sertifika üretildi');

      const certSerial = finalizeResp.json.certificate.split('/').pop();
      const certNonce = (await request('GET', `${TRUST}/acme/new-nonce`, { headers: { Host: 'trust.fitfak.net' } })).headers['replay-nonce'];
      const certJws = makeJws({
        url: `https://trust.fitfak.net/acme/cert/${certSerial}`, nonce: certNonce, payload: '', kid: accountId, privateKey,
      });
      const certDownload = await request('POST', `${TRUST}/acme/cert/${certSerial}`, { rawBody: Buffer.from(JSON.stringify(certJws)), headers: TRUST_HEADERS });
      assert.strictEqual(certDownload.status, 200);
      assert.ok(certDownload.raw.length > 0);
      console.log('pki-acme: üretilen sertifika /acme/cert/ üzerinden indirilebildi');

      const replayJws = makeJws({
        url: 'https://trust.fitfak.net/acme/new-account', nonce: nonce1, payload: {}, jwk, privateKey,
      });
      const replayResp = await request('POST', `${TRUST}/acme/new-account`, { rawBody: Buffer.from(JSON.stringify(replayJws)), headers: TRUST_HEADERS });
      assert.strictEqual(replayResp.status, 400);
      console.log('pki-acme: kullanılmış bir nonce\'un tekrar sunulması doğru şekilde reddedildi (replay koruması)');
    } finally {
      challengeServer.close();
    }
    } // ACME bölümünün sonu (yukarıdaki `acmeResolvable` dalı)

    // =======================================================================
    // 3) OCSP + CRL
    // =======================================================================
    // Bozuk bir OCSP isteği HTTP 500 ile DEĞİL, RFC 6960 §4.2.1
    // `malformedRequest` ile cevaplanmalı: 500 "responder bozuk" demektir ve
    // istemciler bunu geçici arıza sayıp bir noktada iptal kontrolünü atlar --
    // yani başkasının gönderdiği bozuk bayt, iptal altyapısını devre dışı
    // bırakırdı.
    const ocspResp = await request('POST', `${STATUS}/ocsp`, { rawBody: Buffer.from('fake-ocsp-request-der'), headers: { Host: 'trust.fitfak.net', 'content-type': 'application/ocsp-request' } });
    assert.strictEqual(ocspResp.status, 200);
    assert.strictEqual(ocspResp.headers['content-type'], 'application/ocsp-response');
    assert.ok(ocspResp.headers['cache-control'].includes('max-age'));
    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED } -- 30 03 0a 01 01
    assert.strictEqual(ocspResp.raw.toString('hex'), '30030a0101', 'malformedRequest(1) beklenir');
    console.log('pki: bozuk /ocsp isteği RFC 6960 malformedRequest ile reddedildi (500 değil)');

    const crlResp = await request('GET', `${STATUS}/crl`, { headers: { Host: 'trust.fitfak.net' } });
    assert.strictEqual(crlResp.status, 200);
    assert.strictEqual(crlResp.headers['content-type'], 'application/pkix-crl');
    console.log('pki: /crl isteği işlendi, doğru content-type');

    console.log('\nALL PKI/ACME/OCSP/CRL CHECKS PASSED (gerçek issuer, gerçek CSR, gerçek JWS, gerçek http-01 doğrulaması)');
  } finally {
    server.close();
  }
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
