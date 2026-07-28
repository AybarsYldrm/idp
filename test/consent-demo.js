'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

// OAuth onay ekranı ve kapsam sınırları -- canlı sunucuya karşı.
//
// Bu testten önce iki şey doğruydu ve ikisi de sessizdi:
//
//  1. /oauth/authorize, KAYITLI HERHANGİ bir client için, kullanıcı hiçbir şey
//     görmeden yetkilendirme kodu üretiyordu. SSO "tekrar parola sorma"
//     demektir; "hiç sorma" değil.
//  2. İstenen `scope`, client'ın kayıtlı `allowedScopes` listesiyle HİÇ
//     karşılaştırılmıyordu. Kayıt sırasında verilen liste, uygulanmadığı sürece
//     yorum satırıdır.
//
// Ayrıca burada CSRF kapısı da kontrol ediliyor: onay kararı, başka bir siteden
// tetiklenebiliyorsa onay değildir.

process.env.FITFAK_IDP_DEV_DB = '1';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
process.env.FITFAK_IDP_BIND_IDP = '127.0.0.1';
process.env.FITFAK_IDP_BIND_TRUST = '127.0.0.2';
process.env.FITFAK_IDP_BIND_ADMIN = '127.0.0.3';
process.env.FITFAK_IDP_BIND_STATUS = '127.0.0.4';
process.env.FITFAK_IDP_DB_SECRET = crypto.randomBytes(32).toString('base64');

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

function request(port, pathname, { method = 'GET', headers = {}, body, cookies } = {}) {
  return new Promise((resolve, reject) => {
    const h = { ...headers };
    if (cookies) h.cookie = cookies;
    if (body !== undefined) {
      h['content-type'] = h['content-type'] || 'application/json';
      h['content-length'] = Buffer.byteLength(body);
    }
    const req = http.request({ host: '127.0.0.1', port, path: pathname, method, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (_) { /* HTML ya da boş */ }
        resolve({
          status: res.statusCode, location: res.headers.location,
          headers: res.headers, body: text, json,
        });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

// Tarayıcıdan geliyormuş gibi: aynı köken. Kapı bu başlığa bakıyor.
const SAME_ORIGIN = { 'sec-fetch-site': 'same-origin' };

function cookieJar(res, jar = {}) {
  for (const raw of res.headers['set-cookie'] || []) {
    const [pair] = raw.split(';');
    const idx = pair.indexOf('=');
    const name = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1);
    if (value === '') delete jar[name];
    else jar[name] = value;
  }
  return jar;
}
const jarHeader = (jar) => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

async function main() {
  const { main: startServer } = require('../oauth-server');
  const server = await startServer();
  const port = server._httpServers[0].address().port;
  const db = server._db;

  // ── Hazırlık: iki client ve bir kullanıcı ────────────────────────────
  console.log('\n[1] Hazırlık');
  await db.collection('oauth_clients').insert({
    clientId: 'ucuncu-taraf', clientSecret: 'x', name: 'Üçüncü Taraf Uygulama',
    redirectUris: JSON.stringify(['https://app.example.com/cb']),
    allowedScopes: JSON.stringify(['openid', 'profile', 'dns:read']),
    firstParty: false, clientUri: 'https://app.example.com',
    createdAt: BigInt(Date.now()),
  });
  await db.collection('oauth_clients').insert({
    clientId: 'kendi-uygulamamiz', clientSecret: 'y', name: 'FITFAK Portal',
    redirectUris: JSON.stringify(['https://dns.fitfak.net/cb']),
    allowedScopes: JSON.stringify(['openid', 'profile']),
    firstParty: true, clientUri: '',
    createdAt: BigInt(Date.now()),
  });
  check('client kayıtları hazır', true);

  // Oturum doğrudan üretiliyor. Giriş zincirinin tamamı (PoW -> e-posta
  // doğrulama -> TOTP kaydı -> parola -> TOTP) başka testlerin konusu; burada
  // sınanan şey onay akışı, ona ulaşmak için gereken zincir değil.
  const { completeLogin } = require('../services/login-completion');
  const sessionManager = server._sessionManager;
  const userId = await db.collection('users').insert({
    username: 'onaytest', email: 'onay@fitfak.net', status: 'active', emailVerified: true,
    mfaMethods: '[]', createdAt: BigInt(Date.now()),
  });
  const loggedIn = await completeLogin({
    db, sessionManager, userId, ip: '127.0.0.1',
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120', fingerprintId: 'fp',
  });
  const tokens = await sessionManager.issueTokensForClient({
    sessionId: loggedIn.sessionId, clientId: 'self', scope: 'openid profile',
  });
  const jar = cookieJar({
    headers: {
      'set-cookie': [
        ...sessionManager.buildSsoCookies(tokens),
        sessionManager.buildAccountsListCookie([loggedIn.sessionId]),
      ],
    },
  });
  check('oturum çerezi hazır', !!jar['__Secure-fitfak_at']);

  // ── Onay ekranı ──────────────────────────────────────────────────────
  console.log('\n[2] Üçüncü taraf client onay ekranına gidiyor');
  const { challenge } = pkce();
  const authorizeQuery = new URLSearchParams({
    client_id: 'ucuncu-taraf', redirect_uri: 'https://app.example.com/cb',
    response_type: 'code', scope: 'openid profile dns:read',
    code_challenge: challenge, code_challenge_method: 'S256', state: 'durum-1',
  });
  const authorize = await request(port, `/oauth/authorize?${authorizeQuery}`, { cookies: jarHeader(jar) });
  check('302 dönüyor', authorize.status === 302);
  check('doğrudan client\'a KOD verilmiyor', !/[?&]code=/.test(authorize.location));
  check('/consent\'e gidiyor', authorize.location.startsWith('/consent?request='));

  const requestId = new URL(authorize.location, 'http://x').searchParams.get('request');

  console.log('\n[3] Onay ekranı ne istendiğini söylüyor');
  const info = await request(port, `/consent/info?request=${encodeURIComponent(requestId)}`, { cookies: jarHeader(jar) });
  check('bilgi alınabiliyor', info.status === 200);
  check('uygulama adı geliyor', info.json.client.name === 'Üçüncü Taraf Uygulama');
  check('nereye yönlendirileceği geliyor', info.json.client.redirectHost === 'app.example.com');
  check('üç kapsam listeleniyor', info.json.scopes.length === 3);
  check('her kapsamın açıklaması var', info.json.scopes.every((s) => s.detail && s.title));
  check('hepsi yeni', info.json.scopes.every((s) => s.isNew === true));
  check('hesabın kim olduğu geliyor', info.json.account.email === 'onay@fitfak.net');

  console.log('\n[4] Onay kararı başka bir siteden verilemiyor');
  const crossSite = await request(port, '/consent/decide', {
    method: 'POST', headers: { 'sec-fetch-site': 'cross-site' }, cookies: jarHeader(jar),
    body: JSON.stringify({ request: requestId, approve: true }),
  });
  check('siteler arası istek reddedildi', crossSite.status === 403);
  check('istek hâlâ bekliyor (tüketilmedi)',
    (await request(port, `/consent/info?request=${encodeURIComponent(requestId)}`, { cookies: jarHeader(jar) })).status === 200);

  console.log('\n[5] Reddetme client\'a iletiliyor');
  const denyAuth = await request(port, `/oauth/authorize?${authorizeQuery}`, { cookies: jarHeader(jar) });
  const denyId = new URL(denyAuth.location, 'http://x').searchParams.get('request');
  const denied = await request(port, '/consent/decide', {
    method: 'POST', headers: SAME_ORIGIN, cookies: jarHeader(jar),
    body: JSON.stringify({ request: denyId, approve: false }),
  });
  check('karar kabul edildi', denied.status === 200);
  const denyUrl = new URL(denied.json.redirectTo);
  check('client\'a dönülüyor', denyUrl.origin + denyUrl.pathname === 'https://app.example.com/cb');
  check('error=access_denied', denyUrl.searchParams.get('error') === 'access_denied');
  check('state korunuyor', denyUrl.searchParams.get('state') === 'durum-1');

  console.log('\n[6] Onay verilince kod üretiliyor ve izin saklanıyor');
  const approved = await request(port, '/consent/decide', {
    method: 'POST', headers: SAME_ORIGIN, cookies: jarHeader(jar),
    body: JSON.stringify({ request: requestId, approve: true }),
  });
  check('karar kabul edildi', approved.status === 200);
  const okUrl = new URL(approved.json.redirectTo);
  check('kod üretildi', !!okUrl.searchParams.get('code'));
  check('state korunuyor', okUrl.searchParams.get('state') === 'durum-1');

  const reused = await request(port, '/consent/decide', {
    method: 'POST', headers: SAME_ORIGIN, cookies: jarHeader(jar),
    body: JSON.stringify({ request: requestId, approve: true }),
  });
  check('aynı onay isteği ikinci kez kullanılamıyor', reused.status === 404);

  console.log('\n[7] İkinci kez sorulmuyor -- ama YENİ bir kapsam sorulur');
  const again = await request(port, `/oauth/authorize?${authorizeQuery}`, { cookies: jarHeader(jar) });
  check('onay ekranı atlanıyor', /[?&]code=/.test(again.location));
  check('doğrudan client\'a dönülüyor', again.location.startsWith('https://app.example.com/cb'));

  // Bu client'ın dns:read izni vardı. Şimdi yalnızca openid istiyor: kapsanıyor.
  const narrower = new URLSearchParams({
    client_id: 'ucuncu-taraf', redirect_uri: 'https://app.example.com/cb',
    response_type: 'code', scope: 'openid',
    code_challenge: challenge, code_challenge_method: 'S256',
  });
  const narrow = await request(port, `/oauth/authorize?${narrower}`, { cookies: jarHeader(jar) });
  check('dar kapsam da sorulmadan geçiyor', /[?&]code=/.test(narrow.location));

  console.log('\n[8] Client\'ın yetkisi dışındaki kapsam reddediliyor');
  const overreach = new URLSearchParams({
    client_id: 'ucuncu-taraf', redirect_uri: 'https://app.example.com/cb',
    response_type: 'code', scope: 'openid dns:write',
    code_challenge: challenge, code_challenge_method: 'S256', state: 'durum-2',
  });
  const rejected = await request(port, `/oauth/authorize?${overreach}`, { cookies: jarHeader(jar) });
  check('302 ile client\'a dönülüyor', rejected.status === 302);
  const rejectedUrl = new URL(rejected.location);
  check('error=invalid_scope', rejectedUrl.searchParams.get('error') === 'invalid_scope');
  check('kod ÜRETİLMEDİ', !rejectedUrl.searchParams.get('code'));
  check('state korunuyor', rejectedUrl.searchParams.get('state') === 'durum-2');

  console.log('\n[9] Kendi uygulamamıza onay ekranı çıkmıyor');
  const firstParty = new URLSearchParams({
    client_id: 'kendi-uygulamamiz', redirect_uri: 'https://dns.fitfak.net/cb',
    response_type: 'code', scope: 'openid profile',
    code_challenge: challenge, code_challenge_method: 'S256',
  });
  const fp = await request(port, `/oauth/authorize?${firstParty}`, { cookies: jarHeader(jar) });
  check('doğrudan kod üretiliyor', /[?&]code=/.test(fp.location));
  check('client\'a dönülüyor', fp.location.startsWith('https://dns.fitfak.net/cb'));

  console.log('\n[10] prompt=none hiçbir ekran göstermiyor');
  const silentOk = await request(port, `/oauth/authorize?${authorizeQuery}&prompt=none`, { cookies: jarHeader(jar) });
  check('izin varken sessizce kod veriyor', /[?&]code=/.test(silentOk.location));

  // İzni geri alıp aynı isteği sessiz modda tekrar deniyoruz.
  const revoke = await request(port, '/account/grants/revoke', {
    method: 'POST', headers: SAME_ORIGIN, cookies: jarHeader(jar),
    body: JSON.stringify({ clientId: 'ucuncu-taraf' }),
  });
  check('izin geri alındı', revoke.status === 200 && revoke.json.revoked === true);

  const silentFail = await request(port, `/oauth/authorize?${authorizeQuery}&prompt=none`, { cookies: jarHeader(jar) });
  const silentUrl = new URL(silentFail.location);
  check('izin yokken consent_required', silentUrl.searchParams.get('error') === 'consent_required');
  check('sessiz modda onay ekranı GÖSTERİLMİYOR', !silentFail.location.startsWith('/consent'));

  const noSession = await request(port, `/oauth/authorize?${authorizeQuery}&prompt=none`);
  check('oturumsuz sessiz istek login_required',
    new URL(noSession.location).searchParams.get('error') === 'login_required');

  console.log('\n[11] İzin geri alınınca yeniden soruluyor');
  const askedAgain = await request(port, `/oauth/authorize?${authorizeQuery}`, { cookies: jarHeader(jar) });
  check('onay ekranına dönüldü', askedAgain.location.startsWith('/consent?request='));

  console.log('\n[12] Onay isteği onu başlatan hesaba bağlı');
  const otherId = new URL(askedAgain.location, 'http://x').searchParams.get('request');
  const anonymous = await request(port, `/consent/info?request=${encodeURIComponent(otherId)}`);
  check('oturumsuz görüntülenemiyor', anonymous.status === 401);

  console.log('\n[13] /consent sayfası oturumsuz girişe yönlendiriyor');
  const page = await request(port, `/consent?request=${encodeURIComponent(otherId)}`);
  check('302 -> /login', page.status === 302 && page.location.startsWith('/login'));
  check('sorgu dizesi korunuyor', decodeURIComponent(page.location).includes(`/consent?request=${otherId}`));

  await new Promise((r) => server.close(r));
  console.log(`\nOK - OAuth onayı: ${checks} kontrol geçti.`);
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
