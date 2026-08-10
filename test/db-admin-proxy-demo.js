'use strict';

const http = require('node:http');

const { createDatabaseAdminProxy, PROXY_ROUTES } = require('../core/database-admin-proxy');

// Veritabanı yönetiminin one.fitfak.net'ten yapılabilmesi.
//
// Veritabanının paneli 127.0.2.1'de duruyor ve orada kalması doğru: düz HTTP konuşuyor ve tek
// taşıma seviyesi koruması ağdan erişilemez olmak. Ama sonuç şuydu -- veritabanına bakmanın tek
// yolu o makinede bir kabuk açmaktı, üstelik yönetim yüzeyi başka bir yerdeyken.
//
// Vekil ikisini birleştiriyor. Buradaki kontrollerin çoğu, birleştirmenin YANLIŞ yapılabilecek
// yollarına bakıyor:
//
//   * Yolu olduğu gibi iletmek. O zaman `/admin/database/` altına yazılan her şey veritabanının
//     API'sine giderdi -- bugün olmayan ama yarın eklenecek uçlar dahil, yani yetkilendirme
//     kararı hiç verilmemiş uçlar.
//   * Kimlik bilgisini istemciden almak. O zaman operatörün veritabanının anahtarını bilmesi
//     gerekirdi; yani tarayıcıya yapıştırılan, sohbete düşen, ekran görüntüsünde kalan bir değer.
//   * Veritabanı kapalıyken hata vermek. Bu mimaride veritabanının IdP'den SONRA açılması normal
//     bir sıralama, bir arıza değil -- ve mesajın bunu söylemesi gerekiyor.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

/**
 * Veritabanının yönetim API'si yerine, NE İSTENDİĞİNİ kaydeden bir sahte.
 *
 * İstenen başlıkların kaydedilmesi asıl mesele: doğru yanıtın dönmesi yetmez, isteğin doğru
 * kimlik bilgisiyle gitmiş olması gerekir.
 */
function fakeDatabaseApi({ expectToken = 'db-api-token' } = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      seen.push({
        method: req.method,
        path: req.url,
        token: req.headers['x-admin-token'],
        origin: req.headers.origin,
        body: raw ? JSON.parse(raw) : null,
      });
      const reply = (status, payload) => {
        const out = JSON.stringify(payload);
        res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(out) });
        res.end(out);
      };
      if (req.headers['x-admin-token'] !== expectToken) return reply(401, { error: 'unauthorized' });
      if (req.url === '/api/overview') return reply(200, { summary: { totalMegabytes: 4 }, services: [] });
      if (req.url === '/api/services' && req.method === 'POST') return reply(200, { secret: 'once-only' });
      if (req.url === '/api/not-json') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<html>'); }
      return reply(200, { ok: true, path: req.url });
    });
  });
  return { server, seen };
}

const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));

async function main() {
  const api = fakeDatabaseApi();
  const port = await listen(api.server);
  const adminApiUrl = `http://127.0.0.1:${port}`;

  console.log('\n1. Yalnızca listelenen uçlar iletiliyor');

  {
    const proxy = createDatabaseAdminProxy({
      readPairing: async () => ({ adminApiUrl, adminApiToken: 'db-api-token' }),
    });

    const ok = await proxy.forward('GET', '/overview');
    check('listedeki uç iletildi', ok.status === 200 && ok.payload.summary.totalMegabytes === 4);

    // Asıl kontrol. Yolu olduğu gibi ileten bir vekil bunların hepsini geçirirdi -- ve
    // geçirdiği şeylerin yetkilendirme kararı hiçbir yerde verilmemiş olurdu.
    for (const [method, route] of [
      ['GET', '/api/overview'],
      ['GET', '/../api/overview'],
      ['DELETE', '/services'],
      ['GET', '/database/dump'],
      ['POST', '/api/services'],
      ['GET', '/'],
    ]) {
      const refused = await proxy.forward(method, route);
      check(`iletilmiyor: ${method} ${route}`, refused.status === 404 && refused.payload.error === 'not_proxied');
    }

    // Ve reddedilen istek veritabanına HİÇ ULAŞMAMALI: 404'ü karşı taraf üretiyorsa, beyaz
    // listenin bir anlamı yoktur.
    const before = api.seen.length;
    await proxy.forward('GET', '/database/dump');
    check('reddedilen istek veritabanına gitmiyor', api.seen.length === before);
  }

  console.log('\n2. Kimlik bilgisi eşleştirme dizininden, istemciden DEĞİL');

  {
    const proxy = createDatabaseAdminProxy({
      readPairing: async () => ({ adminApiUrl, adminApiToken: 'db-api-token' }),
    });
    await proxy.forward('GET', '/overview');
    const last = api.seen.at(-1);

    check('istek makine kimlik bilgisiyle gitti', last.token === 'db-api-token');
    // Karşı tarafın aynı-kaynak kontrolü POST'larda `Origin` bakıyor; vekilin kendi kaynağını
    // bildirmesi, o kontrolün bir tarayıcı isteğini ayırt etmesini sağlar.
    check('kaynak bildirildi', last.origin === adminApiUrl);

    const created = await proxy.forward('POST', '/services', { name: 'dns-resolver', roles: ['reader'] });
    check('gövde iletiliyor', api.seen.at(-1).body.name === 'dns-resolver');
    check('yanıt geri dönüyor', created.payload.secret === 'once-only');
  }

  console.log('\n3. Veritabanı henüz açılmamışsa: durum, hata değil');

  {
    const proxy = createDatabaseAdminProxy({ readPairing: async () => null });
    const result = await proxy.forward('GET', '/overview');
    check('503 dönüyor', result.status === 503);
    check('sebebi adlandırılıyor', result.payload.error === 'database_unavailable');
    // Bu mimaride veritabanının IdP'den sonra açılması normal bir sıralama. Mesaj bunu
    // söylemezse operatör hatayı yanlış yerde arar.
    check('ne yapılacağını söylüyor', /eşleştirme dizini|FITFAK_PAIRING_DIR/.test(result.payload.error_description));
    check('durum "yapılandırılmamış" diyor', (await proxy.status()).configured === false);
  }

  console.log('\n4. Veritabanı yokluğu ÖNBELLEKLENMİYOR');

  {
    // Önbelleklenseydi, IdP'den sonra açılan bir veritabanı için vekil kalıcı olarak
    // çalışmazdı -- ve bu, bu mimarinin en yaygın açılış sırası.
    let available = false;
    const proxy = createDatabaseAdminProxy({
      readPairing: async () => (available ? { adminApiUrl, adminApiToken: 'db-api-token' } : null),
    });

    check('önce erişilemiyor', (await proxy.forward('GET', '/overview')).status === 503);
    available = true;
    check('veritabanı açılınca kendiliğinden çalışıyor', (await proxy.forward('GET', '/overview')).status === 200);
  }

  console.log('\n5. Kimlik bilgisi reddedilirse yeniden okunuyor');

  {
    // ASCII: HTTP başlık DEĞERLERİ latin-1 ile sınırlı ve Node, ASCII olmayan bir değerle
    // isteği hiç göndermez -- yani 401 yerine bir bağlantı hatası alınır. Buradaki sınama 401
    // yolunu ölçüyor, o yüzden değer gerçekçi olmalı (kimlik bilgileri base64url).
    let token = 'wrong-token-aaaa';
    const proxy = createDatabaseAdminProxy({
      readPairing: async () => ({ adminApiUrl, adminApiToken: token }),
    });

    const refused = await proxy.forward('GET', '/overview');
    check('yanlış anahtar 401', refused.status === 401);

    // Veritabanı yeniden başlamış ve yeni bir anahtar yayınlamış olabilir. Önbelleği tutmak,
    // vekilin kalıcı olarak bozuk kalması demek olurdu.
    token = 'db-api-token';
    check('bir sonraki istek dizini yeniden okuyor', (await proxy.forward('GET', '/overview')).status === 200);
  }

  console.log('\n6. Ulaşılamayan veritabanı anlaşılır bir cevap veriyor');

  {
    const proxy = createDatabaseAdminProxy({
      readPairing: async () => ({ adminApiUrl: 'http://127.0.0.1:1', adminApiToken: 'x' }),
      timeoutMs: 500,
    });
    const result = await proxy.forward('GET', '/overview');
    check('502 dönüyor', result.status === 502);
    check('sebebi taşınıyor', result.payload.error === 'database_unreachable' && !!result.payload.error_description);
  }

  console.log('\n7. Durum ucu SIR DÖNDÜRMÜYOR');

  {
    const proxy = createDatabaseAdminProxy({
      readPairing: async () => ({ adminApiUrl, adminApiToken: 'db-api-token' }),
    });
    const status = await proxy.status();
    check('adres bildiriliyor', status.target === adminApiUrl);
    // Bir durum ucunun sır döndürmesi, o sırrın panelin ağ sekmesine ve oradan bir ekran
    // görüntüsüne düşmesi demektir.
    check('anahtar HİÇBİR yerde yok', !JSON.stringify(status).includes('db-api-token'));
    check('iletilen uçlar listeleniyor', status.routes.length === Object.keys(PROXY_ROUTES).length);
  }

  console.log('\n8. Mühürleme bilerek listede');

  {
    // Ele geçirilmiş bir veritabanını kapatmak, yönetim yüzeyinden yapılabilmesi gereken ilk
    // şeydir; o an makineye kabuk açmak için zaman yoktur.
    check('mühürleme iletiliyor', !!PROXY_ROUTES['POST /admission/seal']);
    const proxy = createDatabaseAdminProxy({
      readPairing: async () => ({ adminApiUrl, adminApiToken: 'db-api-token' }),
    });
    const sealed = await proxy.forward('POST', '/admission/seal', { reason: 'test' });
    check('ve çalışıyor', sealed.status === 200);
  }

  await new Promise((r) => api.server.close(r));
  console.log(`\nOK - veritabanı yönetim vekili: ${checks} kontrol geçti.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message, err.stack); process.exit(1); },
);
