'use strict';

const { assertSameOrigin } = require('../core/same-origin');
const { UserQuota } = require('../core/user-quota');

// Köken kapısı ve kullanıcı kotası -- iki savunmanın da birim düzeyinde
// sınanması. Uçtan uca hâli test/consent-demo.js'te (siteler arası onay
// denemesi 403 alıyor).

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

const ORIGINS = ['https://session.fitfak.net'];
const req = (headers) => ({ headers });

function allowed(headers, opts = {}) {
  try { assertSameOrigin(req(headers), { allowedOrigins: ORIGINS, ...opts }); return true; }
  catch { return false; }
}

function main() {
  console.log('\n[1] Sec-Fetch-Site: en güvenilir sinyal (sayfa kodu bu başlığı DEĞİŞTİREMEZ)');
  check('same-origin geçiyor', allowed({ 'sec-fetch-site': 'same-origin' }));
  // Kullanıcının adres çubuğuna yazdığı ya da yer iminden açtığı istek. Bir
  // sayfanın tetikleyemeyeceği tek durum bu.
  check('none geçiyor', allowed({ 'sec-fetch-site': 'none' }));
  check('cross-site reddediliyor', !allowed({ 'sec-fetch-site': 'cross-site' }));
  check('same-site VARSAYILAN OLARAK reddediliyor', !allowed({ 'sec-fetch-site': 'same-site' }));

  console.log('\n[2] Sec-Fetch-Site, Origin\'i EZER');
  // Origin sayfa tarafından yazılamaz ama proxy/istemci tarafından
  // yazılabilir; Sec-Fetch-Site varsa karar onundur.
  check('cross-site + doğru Origin yine reddediliyor',
    !allowed({ 'sec-fetch-site': 'cross-site', origin: 'https://session.fitfak.net' }));

  console.log('\n[3] same-site gevşetmesi Origin\'i AYRICA doğruluyor');
  // 'same-site' yalnızca eTLD+1 eşleşmesi demek: kotarilmis.fitfak.net de
  // same-site'tır. O yüzden gevşetme açıkken bile tam köken karşılaştırılıyor.
  check('bizim alt alan adımız geçiyor',
    allowed({ 'sec-fetch-site': 'same-site', origin: 'https://session.fitfak.net' }, { allowSameSite: true }));
  check('tanınmayan alt alan adı reddediliyor',
    !allowed({ 'sec-fetch-site': 'same-site', origin: 'https://saldiri.fitfak.net' }, { allowSameSite: true }));
  check('Origin hiç yoksa reddediliyor',
    !allowed({ 'sec-fetch-site': 'same-site' }, { allowSameSite: true }));

  console.log('\n[4] Sec-Fetch-Site yoksa Origin\'e düşülüyor');
  check('doğru Origin geçiyor', allowed({ origin: 'https://session.fitfak.net' }));
  check('yanlış Origin reddediliyor', !allowed({ origin: 'https://kotu.example.com' }));
  check('null Origin reddediliyor', !allowed({ origin: 'null' }));
  // Ön ek eşleşmesiyle kandırma denemesi: bu BAŞKA bir alan adıdır.
  check('benzeyen alan adı reddediliyor', !allowed({ origin: 'https://session.fitfak.net.kotu.com' }));

  console.log('\n[5] Son çare Referer -- yalnızca KÖKEN kısmına bakılıyor');
  check('doğru köken geçiyor', allowed({ referer: 'https://session.fitfak.net/portal?x=1' }));
  check('yanlış köken reddediliyor', !allowed({ referer: 'https://kotu.example.com/sayfa' }));

  console.log('\n[6] Hiçbir başlık yoksa REDDEDİLİYOR');
  // Bir tarayıcının durum değiştiren isteği bu üç başlığın hiçbiri olmadan
  // yapması beklenmez. Betikten gelen istek de cookie taşımaz.
  check('başlıksız istek reddediliyor', !allowed({}));

  console.log('\n[7] Kullanıcı kotası: pencere içinde sayıyor');
  const quota = new UserQuota({ limits: { test: { windowMs: 60_000, max: 3 } } });
  check('1. istek geçiyor', quota.check('kullanici-1', 'test').limited === false);
  check('2. istek geçiyor', quota.check('kullanici-1', 'test').limited === false);
  check('3. istek geçiyor', quota.check('kullanici-1', 'test').limited === false);
  check('4. istek engelleniyor', quota.check('kullanici-1', 'test').limited === true);

  console.log('\n[8] Kota KULLANICI başına -- bir kullanıcı diğerini kilitleyemez');
  check('başka kullanıcı etkilenmiyor', quota.check('kullanici-2', 'test').limited === false);

  console.log('\n[9] Kota İŞLEM başına -- bir işlemin kotası diğerini tüketmiyor');
  check('farklı işlem ayrı sayılıyor', quota.check('kullanici-1', 'avatar').limited === false);

  console.log('\n[10] Aşımda AppError, Retry-After ile');
  let err = null;
  try { quota.enforce('kullanici-1', 'test'); } catch (e) { err = e; }
  check('hata fırlatıldı', !!err);
  check('kod rate_limited', err.code === 'rate_limited');
  check('HTTP 429', err.httpStatus === 429);
  // "Çok sık denediniz" deyip ne zaman denenebileceğini söylememek, istemciyi
  // daha sık denemeye iter.
  check('ne zaman denenebileceği söyleniyor', err.retryAfterSeconds === 60);

  console.log('\n[11] Tanımsız işlem varsayılan kotaya düşüyor');
  const fresh = new UserQuota();
  check('bilinmeyen işlem çalışıyor', fresh.check('u', 'bilinmeyen-islem').max === 60);
  check('hesap silme kotası dar', fresh.check('u', 'account-delete').max === 3);

  console.log(`\nOK - köken kapısı ve kullanıcı kotası: ${checks} kontrol geçti.`);
}

try { main(); process.exit(0); }
catch (err) { console.error('\nFAILED:', err.message); process.exit(1); }
