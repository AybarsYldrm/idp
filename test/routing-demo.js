'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

// Temiz URL'ler, yönlendirmeler ve kimlik kapıları -- canlı sunucuya karşı.
//
// Burada test edilen üç şey, üçü de ilk mesajdan beri açıktı:
//
//  1. Adres çubuğunda '.html' görünmemeli.
//  2. Oturumsuz bir kullanıcı /portal'a girdiğinde girişe YÖNLENDİRİLMELİ, ve
//     girişten SONRA portala GERİ DÖNMELİ. Önceden ikisi de olmuyordu.
//  3. /static/portal.html gibi bir yol, /portal'a konan kimlik kapısını
//     ATLATMAMALI -- statik dosya sunucusu HTML sunduğu sürece atlatıyordu.

process.env.FITFAK_IDP_DEV_DB = '1';
process.env.NODE_ENV = 'test';
process.env.PORT = '0';
// Üretimdeki gibi her mantıksal host AYRI bir adrese bağlanır. Hepsini aynı
// adrese koymak rota çakışmasına yol açar -- status.trust.fitfak.net kök yolu
// ('/') kendi servis tanıtımı için kullanıyor ve session.fitfak.net'in kökünü
// gölgeler. Ayrım soket seviyesinde yapıldığı için ayrı adres şart.
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

function request(port, pathname, { method = 'GET', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: pathname, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        location: res.headers.location,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function main() {
  const { main: startServer } = require('../oauth-server');
  const server = await startServer();
  const port = server._httpServers[0].address().port;

  console.log('\n[1] Temiz URL\'ler çalışıyor');
  const login = await request(port, '/login');
  check('/login sayfayı sunuyor', login.status === 200 && /<html/i.test(login.body));
  check('önbelleğe alınmıyor', /no-store/.test(login.headers['cache-control'] || ''));
  check('çerçeveleme engelli', login.headers['x-frame-options'] === 'DENY');
  check('MIME sniffing engelli', login.headers['x-content-type-options'] === 'nosniff');

  console.log('\n[2] Oturumsuz /portal girişe yönlendiriyor -- ve geri dönüş taşınıyor');
  const portal = await request(port, '/portal');
  check('302 dönüyor', portal.status === 302);
  check('/login\'e gidiyor', portal.location.startsWith('/login'));
  check('return_to=/portal taşınıyor',
    decodeURIComponent(portal.location).includes('return_to=/portal'));

  console.log('\n[3] Kök yol oturum durumuna göre yönleniyor');
  const root = await request(port, '/');
  check('oturumsuz kök -> /login', root.status === 302 && root.location === '/login');

  console.log('\n[4] /static altından HTML SUNULMUYOR (kimlik kapısı atlatılamaz)');
  // Bu, en önemli kontrol: statik sunucu HTML servis ettiği sürece
  // /static/portal.html, /portal'daki oturum kontrolünü tamamen atlatıyordu.
  const sneaky = await request(port, '/static/portal.html');
  check('/static/portal.html sayfayı VERMİYOR', sneaky.status !== 200 || !/<html/i.test(sneaky.body));
  check('bunun yerine temiz URL\'e yönlendiriyor',
    sneaky.status === 301 && sneaky.location === '/portal');

  const sneakyLogin = await request(port, '/static/demo-login.html?return_to=/x');
  check('eski giriş bağlantısı da 301',
    sneakyLogin.status === 301 && sneakyLogin.location === '/login?return_to=/x');

  console.log('\n[5] Statik varlıklar hâlâ erişilebilir');
  const asset = await request(port, '/static/srp-client.js');
  check('script sunuluyor', asset.status === 200 && /FitfakSrp/.test(asset.body));
  check('doğru content-type',
    (asset.headers['content-type'] || '').startsWith('text/javascript'));

  console.log('\n[6] Dizin dışına çıkma denemeleri');
  for (const p of ['/static/../oauth-server.js', '/static/..%2foauth-server.js', '/static/../../etc/passwd']) {
    const r = await request(port, p);
    check(`engellendi: ${p}`, r.status === 404 || r.status === 301 || !/require\(/.test(r.body));
  }

  console.log('\n[7] Bilinmeyen uzantılar sunulmuyor');
  const denied = await request(port, '/static/../package.json');
  check('package.json sunulmuyor', !/"name"/.test(denied.body));

  await new Promise((r) => server.close(r));
  console.log(`\nOK - yönlendirme ve rotalar: ${checks} kontrol geçti.`);
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
