'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const cookieConsent = require('../core/cookie-consent');

// Çerez kategorileri -- canlı sunucuya karşı.
//
// Sınanan asıl şey, oturum çerezi ile istatistik çerezinin AYRI olduğu:
//
//  - istatistik çerezi rıza olmadan YAZILMAZ,
//  - rıza geri alındığında SİLİNİR ("bir daha yazmayız" demek yetmez; yazılmış
//    olan tarayıcıda durur ve her istekte gönderilir),
//  - "hepsini reddet" oturumu KAPATMAZ.

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
      h['content-type'] = 'application/json';
      h['content-length'] = Buffer.byteLength(body);
    }
    const req = http.request({ host: '127.0.0.1', port, path: pathname, method, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (_) { /* HTML */ }
        resolve({ status: res.statusCode, headers: res.headers, body: text, json });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const SAME_ORIGIN = { 'sec-fetch-site': 'same-origin' };

// Set-Cookie'den bir çerezin YAZILDIĞINI mı yoksa SİLİNDİĞİNİ mi anlamak için:
// silme, boş değer + Max-Age=0 ile yapılır.
function findCookie(res, name) {
  for (const raw of res.headers['set-cookie'] || []) {
    if (!raw.startsWith(`${name}=`)) continue;
    const value = raw.slice(name.length + 1).split(';')[0];
    return { raw, value, deleted: value === '' && /max-age=0/i.test(raw) };
  }
  return null;
}

async function main() {
  const { main: startServer } = require('../oauth-server');
  const server = await startServer();
  const port = server._httpServers[0].address().port;

  console.log('\n[1] Katalog her çerezi anlatıyor');
  const catalog = await request(port, '/api/cookies');
  check('katalog dönüyor', catalog.status === 200);
  check('karar bekleniyor', catalog.json.needsDecision === true);
  check('tercih henüz yok', catalog.json.preferences === null);
  check('iki kategori var', catalog.json.categories.length === 2);
  check('zorunlu kategori kapatılamaz',
    catalog.json.categories.find((c) => c.key === 'zorunlu').required === true);
  check('istatistik kategorisi kapatılabilir',
    catalog.json.categories.find((c) => c.key === 'istatistik').required === false);
  check('her çerezin açıklaması ve süresi var',
    catalog.json.cookies.every((c) => c.purpose && c.lifetime && c.category));
  // Reklam/izleme kategorisi YOK, çünkü öyle bir çerez yazmıyoruz. Yazmadığımız
  // bir kategoriyi listelemek, ileride sessizce doldurulabilecek bir kutu
  // bırakmak olurdu.
  check('reklam kategorisi yok', !catalog.json.categories.some((c) => /reklam|pazarlama/i.test(c.title)));

  console.log('\n[2] Oturum çerezleri katalogda ve ZORUNLU kategoride');
  const byName = Object.fromEntries(catalog.json.cookies.map((c) => [c.name, c]));
  for (const name of ['__Secure-fitfak_at', '__Secure-fitfak_rt', '__Secure-fitfak_accounts', '__Secure-fitfak_did']) {
    check(`${name} zorunlu`, byName[name] && byName[name].category === 'zorunlu');
  }
  check('istatistik çerezi ayrı kategoride', byName[cookieConsent.STATS_COOKIE].category === 'istatistik');

  console.log('\n[3] Rıza olmadan istatistik çerezi YAZILMIYOR');
  const anonymous = await request(port, '/login');
  check('giriş sayfası çalışıyor', anonymous.status === 200);
  check('istatistik çerezi yazılmadı', !findCookie(anonymous, cookieConsent.STATS_COOKIE));

  console.log('\n[4] Reddetmek kaydediliyor -- ve istatistik çerezi yine yok');
  const rejected = await request(port, '/api/cookies', {
    method: 'POST', headers: SAME_ORIGIN, body: JSON.stringify({ istatistik: false }),
  });
  check('kayıt kabul edildi', rejected.status === 200 && rejected.json.istatistik === false);
  const rejectedPrefs = findCookie(rejected, cookieConsent.PREFS_COOKIE);
  check('tercih çerezi yazıldı', !!rejectedPrefs && !rejectedPrefs.deleted);
  const statsAfterReject = findCookie(rejected, cookieConsent.STATS_COOKIE);
  check('istatistik çerezi yazılmadı (silme yönergesi olabilir)',
    !statsAfterReject || statsAfterReject.deleted);

  // Tercih çerezi tarayıcıdan OKUNABİLİR olmalı: bant, sunucuya sormadan
  // gösterilip gösterilmeyeceğine karar verebilmeli.
  check('tercih çerezi HttpOnly DEĞİL', !/httponly/i.test(rejectedPrefs.raw));
  check('tercih çerezi Secure', /secure/i.test(rejectedPrefs.raw));

  const prefsCookie = `${cookieConsent.PREFS_COOKIE}=${rejectedPrefs.value}`;
  const afterReject = await request(port, '/api/cookies', { cookies: prefsCookie });
  check('artık karar beklenmiyor', afterReject.json.needsDecision === false);
  check('tercih hatırlanıyor', afterReject.json.preferences.istatistik === false);

  console.log('\n[5] Kabul edilince istatistik çerezi yazılıyor');
  const accepted = await request(port, '/api/cookies', {
    method: 'POST', headers: SAME_ORIGIN, cookies: prefsCookie,
    body: JSON.stringify({ istatistik: true }),
  });
  const statsCookie = findCookie(accepted, cookieConsent.STATS_COOKIE);
  check('istatistik çerezi yazıldı', !!statsCookie && !statsCookie.deleted);
  check('istatistik çerezi HttpOnly', /httponly/i.test(statsCookie.raw));
  check('rastgele, hesaba bağlı değil', statsCookie.value.length >= 20);

  const acceptedPrefs = findCookie(accepted, cookieConsent.PREFS_COOKIE);
  const acceptedJar = `${cookieConsent.PREFS_COOKIE}=${acceptedPrefs.value}; ${cookieConsent.STATS_COOKIE}=${statsCookie.value}`;

  console.log('\n[6] Aynı rıza tekrar verilince YENİ tanıtıcı üretilmiyor');
  const again = await request(port, '/api/cookies', {
    method: 'POST', headers: SAME_ORIGIN, cookies: acceptedJar,
    body: JSON.stringify({ istatistik: true }),
  });
  check('istatistik çerezi yeniden yazılmadı', !findCookie(again, cookieConsent.STATS_COOKIE));

  console.log('\n[7] Rıza geri alınınca çerez SİLİNİYOR');
  const withdrawn = await request(port, '/api/cookies', {
    method: 'POST', headers: SAME_ORIGIN, cookies: acceptedJar,
    body: JSON.stringify({ istatistik: false }),
  });
  const removal = findCookie(withdrawn, cookieConsent.STATS_COOKIE);
  check('silme yönergesi gönderildi', !!removal && removal.deleted === true);

  console.log('\n[8] Tercih başka bir siteden değiştirilemiyor');
  const crossSite = await request(port, '/api/cookies', {
    method: 'POST', headers: { 'sec-fetch-site': 'cross-site' },
    body: JSON.stringify({ istatistik: true }),
  });
  check('siteler arası istek reddedildi', crossSite.status === 403);

  console.log('\n[9] Kategori listesi değişirse rıza yeniden soruluyor');
  // Kullanıcı GÖRMEDİĞİ bir kategoriye rıza vermiş sayılamaz; sürüm alanı
  // eski rızayı otomatik olarak geçersiz kılar.
  const stale = encodeURIComponent(JSON.stringify({ v: 0, istatistik: true, t: Date.now() }));
  const staleResp = await request(port, '/api/cookies', {
    cookies: `${cookieConsent.PREFS_COOKIE}=${stale}`,
  });
  check('eski sürümlü rıza geçersiz', staleResp.json.needsDecision === true);
  check('eski rıza istatistiği açmıyor',
    cookieConsent.hasStatisticsConsent(`${cookieConsent.PREFS_COOKIE}=${stale}`) === false);

  console.log('\n[10] Bozuk tercih çerezi hata vermiyor, karar sorulur');
  const broken = await request(port, '/api/cookies', {
    cookies: `${cookieConsent.PREFS_COOKIE}=bu-json-degil`,
  });
  check('istek başarılı', broken.status === 200);
  check('karar yeniden soruluyor', broken.json.needsDecision === true);

  console.log('\n[11] /cookies sayfası oturumsuz da açılıyor');
  const page = await request(port, '/cookies');
  check('sayfa sunuluyor', page.status === 200 && /<html/i.test(page.body));
  const tr = await request(port, '/cerezler');
  check('Türkçe takma ad da çalışıyor', tr.status === 200 && /<html/i.test(tr.body));

  await new Promise((r) => server.close(r));
  console.log(`\nOK - çerez kategorileri: ${checks} kontrol geçti.`);
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
