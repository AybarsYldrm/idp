'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

// Yönetim yüzeyinin giriş yüzeyinden AYRI bir adreste olması.
//
// Bu bir düzen tercihi değil. session.fitfak.net herkese açık olmak zorunda --
// giriş sayfası orada. one.fitfak.net ise olmak zorunda değil: ayrı bir adrese
// bağlandığında güvenlik duvarı, VPN ya da yalnızca yerel arayüz kısıtıyla
// dışarıya tamamen kapatılabilir.
//
// Aynı porttaki bir yol olsaydı, tüm koruma uygulama içindeki tek bir
// kontrole (requireAdmin) bağlı kalırdı: o kontrolün bir rotada unutulması ya
// da bir hata yolunda atlanması, yönetim API'sini internete açardı. Ağ
// seviyesindeki ayrım, o tek kontrolün ARKASINA ikinci bir kat koyar.

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

function request(host, port, pathname, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request({ host, port, path: pathname, method }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode, location: res.headers.location,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    req.end();
  });
}

const ADMIN_ROUTES = [
  ['GET', '/admin'],
  ['GET', '/admin/users'],
  ['POST', '/admin/users/role'],
  ['GET', '/admin/sessions'],
  ['POST', '/admin/sessions/revoke'],
  ['GET', '/admin/oauth-clients'],
  ['POST', '/admin/oauth-clients'],
  ['POST', '/admin/oauth-clients/update'],
  ['POST', '/admin/oauth-clients/delete'],
  ['GET', '/admin/certificates'],
  ['POST', '/admin/certificates/revoke'],
  ['GET', '/admin/acme-orders'],
  ['POST', '/admin/users/cert-profiles'],
];

async function main() {
  const { main: startServer } = require('../oauth-server');
  const server = await startServer();

  // PORT=0 ile her bind AYRI bir efemer port alır; üretimde hepsi 80'de,
  // farklı adreslerde dinler. Testin doğru portu bulması için adrese göre
  // eşleştiriyoruz -- ilk sunucuyu varsaymak yanlış yüzeyi sorgulamak olurdu.
  const portOf = (host) => {
    const found = server._httpServers.find((h) => h.address() && h.address().address === host);
    if (!found) throw new Error(`${host} için dinleyici bulunamadı`);
    return found.address().port;
  };
  const port = portOf('127.0.0.1');

  console.log('\n[1] Yönetim rotalarının HİÇBİRİ giriş yüzeyinde yok');
  for (const [method, route] of ADMIN_ROUTES) {
    const res = await request('127.0.0.1', port, route, method);
    // 404 bekleniyor: rota o adreste kayıtlı değil. 401/403 gelseydi rota
    // ORADA olurdu ve yalnızca uygulama kontrolüyle korunuyor olurdu.
    check(`${method} ${route} -> 404 (session.fitfak.net)`, res.status === 404);
  }

  console.log('\n[2] Aynı rotalar yönetim adresinde MEVCUT');
  for (const [method, route] of ADMIN_ROUTES) {
    const res = await request('127.0.0.3', portOf('127.0.0.3'), route, method);
    // Kimlik yok, dolayısıyla 401/403 ya da girişe yönlendirme bekleniyor --
    // ama 404 DEĞİL: rota orada var.
    const reachable = res.status === 401 || res.status === 403 || res.status === 302;
    check(`${method} ${route} -> ${res.status} (one.fitfak.net)`, reachable);
  }

  console.log('\n[3] Yönetim paneli oturumsuz kullanıcıyı girişe yolluyor');
  const panel = await request('127.0.0.3', portOf('127.0.0.3'), '/admin');
  check('302 dönüyor', panel.status === 302);
  check('/login\'e, dönüş adresiyle', panel.location === `/login?return_to=${encodeURIComponent('/admin')}`);

  console.log('\n[4] Giriş yüzeyi hâlâ çalışıyor');
  const login = await request('127.0.0.1', port, '/login');
  check('/login sunuluyor', login.status === 200);
  const portal = await request('127.0.0.1', port, '/portal');
  check('/portal girişe yönlendiriyor', portal.status === 302);

  console.log('\n[5] Yüzeyler birbirine sızmıyor');
  // PKI ve durum uçları da kendi adreslerinde kalmalı.
  check('OCSP giriş yüzeyinde yok', (await request('127.0.0.1', port, '/ocsp', 'POST')).status === 404);
  check('CT log giriş yüzeyinde yok', (await request('127.0.0.1', port, '/ct/v1/get-sth')).status === 404);
  check('/policy giriş yüzeyinde yok', (await request('127.0.0.1', port, '/policy')).status === 404);
  check('/policy trust yüzeyinde VAR', (await request('127.0.0.2', portOf('127.0.0.2'), '/policy')).status === 200);
  check('CT log trust yüzeyinde VAR', (await request('127.0.0.2', portOf('127.0.0.2'), '/ct/v1/get-sth')).status === 200);
  check('CRL status yüzeyinde VAR', (await request('127.0.0.4', portOf('127.0.0.4'), '/crl')).status === 200);

  await new Promise((r) => server.close(r));
  console.log(`\nOK - yüzey ayrımı: ${checks} kontrol geçti.`);
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
