'use strict';

const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');

const { createMockDb } = require('./mock-db');
const srpAuth = require('../services/srp-auth-service');
const authService = require('../services/auth-service');

// public/oauth-client.js içindeki SRP yapıştırıcısı.
//
// Kripto ve uç noktalar ayrıca test ediliyor; burada test edilen, tarayıcı
// sayfasının çağırdığı katman: doğrulayıcısı olan hesap SRP'den geçiyor mu,
// olmayan hesap eski yola düşüp ARDINDAN taşınıyor mu, ve her iki durumda da
// parola gerçekten ağda görünmüyor mu.
//
// Ağa çıkan HER gövde kaydediliyor ve sonunda parolanın hiçbirinde geçmediği
// doğrulanıyor -- niyet beyanı değil, gözlem.

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

const sentBodies = [];

async function main() {
  const db = createMockDb(['users']);
  const store = makeStore();
  const ephemeral = makeStore();
  authService.configureEphemeralStore(ephemeral);
  const config = { db: { rootSecret: crypto.randomBytes(32) } };

  // Sayfanın konuştuğu üç ucu taşıyan asgari sunucu.
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
    sentBodies.push({ url: req.url, body });

    const reply = (status, obj) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(obj));
    };

    try {
      if (req.url === '/auth/srp/begin') {
        return reply(200, await srpAuth.beginSrpLogin({ db, store, config, identity: body.identity }));
      }
      if (req.url === '/auth/srp/finish') {
        const r = await srpAuth.finishSrpLogin({ db, store, stateId: body.stateId, A: body.A, M1: body.M1 });
        const mfa = await authService.issueMfaChallengeForUser({ db, userId: r.userId });
        return reply(200, Object.assign({ M2: r.M2 }, mfa));
      }
      if (req.url === '/auth/login/password') {
        const users = db.collection('users');
        const row = await users.findOne('email', String(body.username).toLowerCase())
          || await users.findOne('username', body.username);
        if (!row || row.passwordHash !== `legacy$${body.password}`) return reply(401, { error: 'invalid_credentials' });
        return reply(200, await authService.issueMfaChallengeForUser({ db, userId: String(row._id) }));
      }
      if (req.url === '/auth/srp/upgrade') {
        return reply(200, await srpAuth.upgradeLegacyAccountToSrp({
          db, authService, mfaChallengeToken: body.mfaChallengeToken, setupToken: body.setupToken,
          saltB64: body.saltB64, verifierB64: body.verifierB64,
        }));
      }
      if (req.url === '/auth/register') {
        return reply(200, await authService.register({
          db, username: body.username, email: body.email, mailer: null,
          srpSaltB64: body.srpSaltB64, srpVerifierB64: body.srpVerifierB64,
        }));
      }
      reply(404, { error: 'not_found' });
    } catch (e) {
      reply(e.httpStatus || 500, { error: e.code || 'internal_error', error_description: e.message });
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;

  // Tarayıcı ortamını kur ve sayfanın yüklediği İKİ dosyayı olduğu gibi yükle.
  global.window = global;
  global.location = { origin: base };
  const realFetch = global.fetch;
  global.fetch = (url, opts) => realFetch(url.startsWith('http') ? url : base + url, opts);

  require(path.join(__dirname, '..', 'public', 'srp-client.js'));
  require(path.join(__dirname, '..', 'public', 'oauth-client.js'));
  const api = global.FitfakOAuth;

  console.log('\n[1] Sayfanın yüklediği dosyalar birlikte çalışıyor');
  check('FitfakSrp yüklendi', !!global.FitfakSrp);
  check('FitfakOAuth yüklendi', !!api);
  check('loginWithSrp mevcut', typeof api.loginWithSrp === 'function');
  check('registerWithSrp mevcut', typeof api.registerWithSrp === 'function');

  console.log('\n[2] SRP ile kayıt: parola gövdede yok');
  const regPassword = 'YeniHesap123!';
  const reg = await api.registerWithSrp({ username: 'yeni', email: 'yeni@fitfak.net', password: regPassword });
  check('kayıt tamamlandı', !!reg.userId);
  const regBody = sentBodies.find((b) => b.url === '/auth/register').body;
  check('gövdede parola alanı yok', regBody.password === undefined);
  check('gövdede doğrulayıcı var', !!regBody.srpVerifierB64);

  console.log('\n[3] Doğrulayıcısı olan hesap SRP yolundan giriyor');
  await db.collection('users').update(reg.userId, { status: 'active', emailVerified: true, mfaMethods: JSON.stringify(['totp']) });
  const login = await api.loginWithSrp({ identity: 'yeni@fitfak.net', password: regPassword });
  check('SRP yolu kullanıldı', login.srp === true);
  check('ikinci faktör isteniyor', login.requiresSecondFactor === true);
  check('eski uca hiç gidilmedi', !sentBodies.some((b) => b.url === '/auth/login/password'));

  console.log('\n[4] Yanlış parola: eski yola düşer, o da reddeder');
  let failed = false;
  try { await api.loginWithSrp({ identity: 'yeni@fitfak.net', password: 'Yanlis123!' }); }
  catch (_) { failed = true; }
  check('giriş başarısız', failed);

  console.log('\n[5] Taşınmamış eski hesap: eski yol + otomatik taşıma');
  const legacyPassword = 'EskiParolam123!';
  const legacyId = await db.collection('users').insert({
    username: 'eski', email: 'eski@fitfak.net', status: 'active', emailVerified: true,
    mfaMethods: JSON.stringify(['totp']), createdAt: BigInt(Date.now()),
    passwordHash: `legacy$${legacyPassword}`, srpSalt: '', srpVerifier: '',
  });
  const legacyLogin = await api.loginWithSrp({ identity: 'eski@fitfak.net', password: legacyPassword });
  check('eski yola düşüldü', legacyLogin.srp === false);
  check('giriş başarılı', legacyLogin.requiresSecondFactor === true);
  check('taşıma yapıldı olarak işaretlendi', legacyLogin.migrated === true);

  const upgraded = await db.collection('users').get(legacyId);
  check('doğrulayıcı yazıldı', !!upgraded.srpVerifier);
  check('eski parola hash\'i silindi', upgraded.passwordHash === '');

  console.log('\n[6] Taşındıktan sonra artık SRP yolundan giriyor');
  const beforeCount = sentBodies.filter((b) => b.url === '/auth/login/password').length;
  const second = await api.loginWithSrp({ identity: 'eski@fitfak.net', password: legacyPassword });
  check('bu kez SRP kullanıldı', second.srp === true);
  const afterCount = sentBodies.filter((b) => b.url === '/auth/login/password').length;
  check('eski uca bir daha gidilmedi', afterCount === beforeCount);

  console.log('\n[7] Ağa çıkan HİÇBİR gövdede parola yok (taşıma isteği hariç değil -- o da yok)');
  const allBodies = JSON.stringify(sentBodies);
  check('SRP hesabının parolası hiç görünmedi', !allBodies.includes(regPassword));
  // Eski hesabın parolası SADECE taşıma öncesi tek bir /auth/login/password
  // gövdesinde geçer -- geçişin kaçınılmaz bedeli, ve tam olarak bir kez.
  const legacyOccurrences = sentBodies.filter((b) => JSON.stringify(b.body).includes(legacyPassword));
  check('eski hesabın parolası tam olarak bir kez gitti', legacyOccurrences.length === 1);
  check('o da yalnızca eski uca gitti', legacyOccurrences[0].url === '/auth/login/password');

  server.close();
  console.log(`\nOK - SRP istemci yapıştırıcısı: ${checks} kontrol geçti.`);
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
