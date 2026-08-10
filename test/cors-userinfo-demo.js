'use strict';

const { createCorsOriginSet, originOf } = require('../core/cors-origins');
const { Server } = require('../core/http-transport');

// Bir uygulamanın tarayıcıdan kimlik bilgisi çekebilmesi.
//
// İki ayrı hata bunu imkânsız kılıyordu ve ikisi de aynı belirtiyi veriyordu -- "veri
// çekemiyorum" -- ama sebepleri farklıydı ve biri düzeltilse diğeri hâlâ engelliyordu:
//
//   1. CORS LİSTESİ SABİTTİ. `session.fitfak.net` ve `trust.fitfak.net` yazıyordu; portal
//      (fitfak.net) ve yönetim yüzeyi (one.fitfak.net) hiç eklenmemişti. Tarayıcı isteği
//      yanıta hiç bakmadan reddediyordu.
//
//   2. USERINFO YALNIZCA ÇEREZE BAKIYORDU. Çerez `__Secure-` önekli ve SameSite kısıtlı, yani
//      tarayıcı onu çapraz siteye GÖNDERMEZ -- `credentials: 'include'` yazılsa bile. Yani
//      CORS düzelse bile belirteç hiç ulaşmayacaktı, ve dönen hata "Cookie içinde token eksik"
//      olduğu için teşhis CORS'a değil çereze giderdi.
//
// Buradaki kontroller ikisini de kapsıyor, ve asıl ağırlık NEGATİF olanlarda: bilinmeyen bir
// kaynağa izin veren bir uygulama da tüm pozitif kontrolleri geçerdi -- ve o uygulama,
// herhangi bir sayfanın kullanıcının çerezleriyle bu API'yi okuyabilmesi demek olurdu.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

/** Sunucunun CORS başlıklarını, gerçek bir istek olmadan gözlemlemek için. */
function applyCors(server, origin, requestHeaders = null) {
  const headers = {};
  const res = {
    setHeader(name, value) { headers[name.toLowerCase()] = String(value); },
  };
  const req = {
    headers: {
      ...(origin ? { origin } : {}),
      ...(requestHeaders ? { 'access-control-request-headers': requestHeaders } : {}),
    },
  };
  server._applyCors(req, res);
  return headers;
}

async function main() {
  console.log('\n1. Kaynak, kayıtlı yönlendirme adresinden türetiliyor');

  {
    check('https adres kaynağını verir', originOf('https://fitfak.net/oauth/callback') === 'https://fitfak.net');
    check('port korunur', originOf('https://app.fitfak.net:8443/cb') === 'https://app.fitfak.net:8443');
    // Sayısal geri döngüde http, RFC 8252 §8.3'ün kabul ettiği durum: makineden çıkmayan bir
    // bağlantıda okunacak trafik yok.
    check('sayısal geri döngü http kabul edilir', originOf('http://127.0.2.1/auth/callback') === 'http://127.0.2.1');

    // Bir alan adında düz http'ye izin vermek, ağdaki herkesin yanıtı okuyabilmesi demek.
    check('alan adında düz http reddedilir', originOf('http://uygulama.example/cb') === null);
    // Özel şema bir kaynak değildir ve tarayıcıdan gelmez.
    check('özel şema reddedilir', originOf('myapp://callback') === null);
    check('bozuk adres reddedilir', originOf('bu bir adres değil') === null);
    check('boş reddedilir', originOf('') === null && originOf(null) === null);
  }

  console.log('\n2. Küme kayıtlı istemcilerden kuruluyor');

  {
    let clients = [
      { redirects: [{ redirectUri: 'https://fitfak.net/oauth/callback' }] },
      { redirects: [{ redirectUri: 'https://dns.fitfak.net/cb' }, { redirectUri: 'https://dns.fitfak.net/cb2' }] },
      { redirects: [{ redirectUri: 'myapp://callback' }] },
    ];
    const set = createCorsOriginSet({
      listClients: async () => clients,
      always: ['https://session.fitfak.net'],
      ttlMs: 50,
    });
    await set.refresh();

    check('sabit kaynak izinli', set.allows('https://session.fitfak.net'));
    check('kayıtlı uygulamanın kaynağı izinli', set.allows('https://fitfak.net'));
    check('aynı kaynağın iki adresi tek girdi', set.snapshot().fromClients.filter((o) => o === 'https://dns.fitfak.net').length === 1);
    check('tarayıcıdan gelmeyen şema listede yok', !set.snapshot().fromClients.some((o) => o.startsWith('myapp')));

    // Asıl kontrol: kayıtlı OLMAYAN bir kaynak. Bunu geçiren bir uygulama, herhangi bir
    // sayfanın kullanıcının çerezleriyle bu API'yi okuyabilmesi demektir.
    check('kayıtsız kaynak REDDEDİLİR', !set.allows('https://saldirgan.example'));
    check('boş kaynak reddedilir', !set.allows(''));
    check('alt alan adı otomatik izinli DEĞİL', !set.allows('https://baska.fitfak.net'));

    // Yeni bir uygulama kaydedildiğinde bekleme olmadan geçerli olmalı: ilk isteğin reddedilmesi,
    // kaydın çalışmadığı izlenimi verir.
    clients = [...clients, { redirects: [{ redirectUri: 'https://yeni.fitfak.net/cb' }] }];
    check('yenilemeden önce henüz yok', !set.allows('https://yeni.fitfak.net'));
    await set.refresh();
    check('yenilemeden sonra izinli', set.allows('https://yeni.fitfak.net'));
  }

  console.log('\n3. Yenileme başarısızlığı çalışan listeyi bozmuyor');

  {
    let fail = false;
    const set = createCorsOriginSet({
      listClients: async () => {
        if (fail) throw new Error('veritabanı yok');
        return [{ redirects: [{ redirectUri: 'https://fitfak.net/cb' }] }];
      },
      always: [],
      ttlMs: 10_000,
    });
    await set.refresh();
    check('kaynak izinli', set.allows('https://fitfak.net'));

    fail = true;
    await set.refresh();
    // Listeyi boşaltmak, veritabanı bir an erişilemez olduğunda çalışan HER uygulamayı kırardı.
    check('yenileme düşse de eldeki liste duruyor', set.allows('https://fitfak.net'));
  }

  console.log('\n4. Sunucu başlıkları yalnızca izinli kaynağa koyuyor');

  {
    const server = new Server();
    server.setCorsOriginResolver((origin) => origin === 'https://fitfak.net');

    const allowed = applyCors(server, 'https://fitfak.net');
    check('izinli kaynak yansıtılıyor', allowed['access-control-allow-origin'] === 'https://fitfak.net');
    // `*` ile `Allow-Credentials: true` birlikte kullanılamaz; tarayıcı reddeder. Kimlik
    // doğrulamalı bir API'de kaynak YANSITILMAK zorunda -- ve yansıtma, ancak önce doğrulandıysa
    // güvenlidir.
    check('joker değil, tam kaynak', allowed['access-control-allow-origin'] !== '*');
    check('kimlik bilgisi izni veriliyor', allowed['access-control-allow-credentials'] === 'true');
    check('Authorization başlığına izin var', /Authorization/i.test(allowed['access-control-allow-headers']));
    // Vary olmadan bir ara önbellek, bir kaynağa verilen yanıtı başka bir kaynağa servis edebilir.
    check('Vary: Origin var', allowed.vary === 'Origin');
    check('ön kontrol önbellekleniyor', Number(allowed['access-control-max-age']) > 0);

    const refused = applyCors(server, 'https://saldirgan.example');
    check('izinsiz kaynağa HİÇBİR başlık konmuyor', Object.keys(refused).length === 0);

    // Kaynağı olmayan istek tarayıcıdan gelmiyor demektir (curl, sunucudan sunucuya).
    // Ona CORS başlığı koymak anlamsız olurdu.
    const noOrigin = applyCors(server, null);
    check('kaynaksız istekte başlık yok', Object.keys(noOrigin).length === 0);

    // Sabit liste hâlâ çalışıyor: çözücü yokken bile kendi yüzeylerimiz izinli olmalı.
    const bare = new Server();
    check('varsayılan listede kendi yüzeylerimiz var',
      Object.keys(applyCors(bare, 'https://session.fitfak.net')).length > 0);
    check('ve yönetim yüzeyi de',
      Object.keys(applyCors(bare, 'https://one.fitfak.net')).length > 0);
    check('çözücü yokken kayıtsız kaynak reddedilir',
      Object.keys(applyCors(bare, 'https://saldirgan.example')).length === 0);
  }

  console.log('\n5. Çözücüdeki bir hata isteği düşürmüyor');

  {
    const server = new Server();
    server.setCorsOriginResolver(() => { throw new Error('çözücü patladı'); });
    // Başlık konmaz -- ama istek de düşmez. CORS başlığı koyamamak bir yanıt hatası değildir;
    // orada bir istisna fırlatmak, tarayıcıdan gelen her isteği 500'e çevirirdi.
    const headers = applyCors(server, 'https://fitfak.net');
    check('hata yutuluyor, başlık konmuyor', Object.keys(headers).length === 0);
  }

  console.log('\n6. Bearer belirteci Authorization başlığından okunuyor');

  {
    // Fonksiyon oauth-server.js içinde ve o dosya @fitfak/qr'a bağlı; burada davranışı
    // kaynaktan çıkarıp sınıyoruz. Sınanan şey ayrıştırma kuralı ve o kural, ucun çapraz
    // kaynaktan çağrılabilir olup olmamasını belirliyor.
    const source = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'oauth-server.js'), 'utf8');
    const match = /function bearerToken\(req\)\s*\{[\s\S]*?\n\}/.exec(source);
    check('bearerToken tanımlı', !!match);
    // eslint-disable-next-line no-new-func
    const bearerToken = new Function(`return ${match[0]}`)();

    check('Bearer okunuyor', bearerToken({ headers: { authorization: 'Bearer abc.def.ghi' } }) === 'abc.def.ghi');
    // RFC 7235 §2.1: şema adı büyük/küçük harfe duyarsız. Reddetmek, standardın izin verdiği
    // bir şeyi reddetmek olurdu ve bazı istemciler gerçekten küçük harf gönderir.
    check('küçük harfli şema da', bearerToken({ headers: { authorization: 'bearer abc' } }) === 'abc');
    check('fazladan boşluk sorun değil', bearerToken({ headers: { authorization: '  Bearer   abc  ' } }) === 'abc');
    check('başka şema reddedilir', bearerToken({ headers: { authorization: 'Basic abc' } }) === null);
    check('başlık yoksa null', bearerToken({ headers: {} }) === null);
    check('boş Bearer null', bearerToken({ headers: { authorization: 'Bearer' } }) === null);
  }

  console.log(`\nOK - CORS ve userinfo: ${checks} kontrol geçti.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message, err.stack); process.exit(1); },
);
