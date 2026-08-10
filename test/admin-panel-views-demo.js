'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { PROXY_ROUTES } = require('../core/database-admin-proxy');

// Yönetim panelinin yeni ekranları: Uygulamalar ve Veritabanı.
//
// Bu iki ekran API'si olan ama yüzü olmayan uçları görünür kılıyor. Sınanması gereken şey
// "düğme var mı" değil; panelin SÖYLEDİĞİ ŞEYİN doğru olması:
//
//   * Panelin çağırdığı her uç GERÇEKTEN VAR MI. Bir sayfa, olmayan bir uca istek atarsa
//     boş bir tablo gösterir -- ve boş bir tablo ile yetkisiz bir tablo dışarıdan aynı görünür.
//   * Tek taraflı kalmış bir uygulama ÖYLE görünüyor mu. Çalışmayacak bir uygulamayı
//     çalışıyormuş gibi listelemek, bu birleştirmenin bütün amacını ortadan kaldırır.
//   * Sırlar bir kez gösterilip bir daha okunamıyorsa, panel bunu SÖYLÜYOR mu.
//   * Veritabanı kapalıyken panel ne yapıyor. Bu mimaride veritabanının IdP'den sonra açılması
//     normal bir sıralama; ekranın bunu bir arıza gibi göstermemesi gerekiyor.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

const PANEL = fs.readFileSync(path.join(__dirname, '..', 'public', 'admin-panel.html'), 'utf8');
const SERVER = fs.readFileSync(path.join(__dirname, '..', 'oauth-server.js'), 'utf8');

/** Panelin betiği: söz dizimi bozuksa hiçbir ekran açılmaz. */
function panelScript() {
  const blocks = [...PANEL.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  return blocks.join('\n');
}

function main() {
  console.log('\n1. Panelin betiği çalışabilir durumda');

  {
    const script = panelScript();
    let error = null;
    // eslint-disable-next-line no-new-func
    try { new Function(script); } catch (err) { error = err; }
    check('söz dizimi geçerli', error === null);

    // Panelin başvurduğu her öğe gerçekten işaretlemede olmalı: olmayan bir id'ye yazmaya
    // çalışan satır TypeError atar ve o noktadan sonraki HİÇBİR ekran kurulmaz.
    const ids = new Set([...PANEL.matchAll(/id="([^"]+)"/g)].map((m) => m[1]));
    const used = new Set([...script.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]));
    const missing = [...used].filter((id) => !ids.has(id));
    check(`başvurulan tüm id'ler var (${used.size} tanesi)`, missing.length === 0);
  }

  console.log('\n2. Panelin çağırdığı her uç sunucuda var');

  {
    const script = panelScript();
    // Sorgu dizesi atılıyor: yollar sunucuda sorgusuz tanımlı ve `?userId=` gibi bir ek,
    // aynı ucun farklı bir uç sanılmasına yol açardı.
    const called = new Set([...script.matchAll(/(?:get|post)\('(\/admin\/[^'?]+)/g)].map((m) => m[1]));
    check('yeni uçlar çağrılıyor', called.size > 0);

    for (const endpoint of called) {
      // Olmayan bir uca istek atan sayfa boş bir tablo gösterir; boş tablo ile yetkisiz tablo
      // dışarıdan aynı görünür ve teşhis yanlış yerden başlar.
      const declared = SERVER.includes(`path: '${endpoint}'`)
        // Döngüyle kurulan yollar (`/admin/database${route}`) düz metin olarak geçmiyor.
        || (endpoint.startsWith('/admin/database/')
          && new RegExp(`'${endpoint.replace('/admin/database', '')}'`).test(SERVER));
      check(`sunucuda tanımlı: ${endpoint}`, declared);
    }
  }

  console.log('\n3. Veritabanı çağrıları vekilin ilettiği uçlara denk geliyor');

  {
    const script = panelScript();
    const dbCalls = [...script.matchAll(/(get|post)\('\/admin\/database(\/[^']*)'/g)]
      .map((m) => ({ method: m[1] === 'get' ? 'GET' : 'POST', route: m[2] }));
    check('veritabanı uçları çağrılıyor', dbCalls.length >= 3);

    for (const call of dbCalls) {
      if (call.route === '/status') continue; // vekilin kendi durumu, iletilen bir uç değil
      // Vekil yolu OLDUĞU GİBİ iletmiyor; listede olmayan bir yol 404 döner. Panelin listede
      // olmayan bir yolu çağırması, sessizce boş bir ekran demek.
      check(`vekil iletiyor: ${call.method} ${call.route}`, !!PROXY_ROUTES[`${call.method} ${call.route}`]);
    }
  }

  console.log('\n4. Tek taraflı kalmış uygulama ÖYLE görünüyor');

  {
    const script = panelScript();
    const render = /function renderApplications\(\)\s*\{[\s\S]*?\n  \}/.exec(script);
    check('renderApplications tanımlı', !!render);
    const body = render[0];

    // Birleştirmenin asıl değeri bu: iki ayrı panele bakan biri eksik yarıyı göremez.
    check('veritabanı yarısı eksikse söyleniyor', /missing === 'database'/.test(body));
    check('OAuth yarısı eksikse söyleniyor', /missing === 'oauth'/.test(body));
    check('eksik kayıt olumsuz işaretleniyor', /badge-bad/.test(body));
    // Ne olacağını da söylemesi gerekiyor: "eksik" demek, operatöre ne bozulacağını anlatmaz.
    check('sonucu açıklanıyor', /bağlanamaz|giriş alamaz/.test(body));
    check('tam kayıt olumlu işaretleniyor', /badge-ok/.test(body));
  }

  console.log('\n5. Sırlar bir kez gösteriliyor ve bu söyleniyor');

  {
    const script = panelScript();
    const fn = /function showCreatedApplication\(created\)\s*\{[\s\S]*?\n  \}/.exec(script);
    check('showCreatedApplication tanımlı', !!fn);
    const body = fn[0];

    // İkisi BİRLİKTE gösteriliyor: ayrı ekranlarda olsalardı operatör birini kaydedip
    // diğerini kaçırırdı, ve kaçırılan kayıt sırrı uygulamanın hiç bağlanamaması demek.
    check('OAuth sırrı gösteriliyor', /clientSecret/.test(body));
    check('kayıt sırrı da gösteriliyor', /enrolmentSecret/.test(body));
    check('SPIFFE kimliği gösteriliyor', /spiffeId/.test(body));
    check('bir daha gösterilmeyeceği söyleniyor', /bir daha gösterilmeyecek/.test(body));
    check('ortam bloğu veriliyor', /created\.environment/.test(body));

    // Modal'a kaydetme işleyicisi verilmiyor: bu ekran bir form değil, bir kez okunacak bir
    // çıktı. "Kaydet" düğmesi göstermek, kaydedilmemiş bir şey varmış izlenimi verirdi.
    check('yalnızca okunacak bir ekran', /openModal\([^)]*body, null\)/.test(body));
  }

  console.log('\n6. Veritabanı kapalıyken ekran arıza göstermiyor');

  {
    const script = panelScript();
    const fn = /async function loadDatabase\(\)\s*\{[\s\S]*?\n  \}/.exec(script);
    check('loadDatabase tanımlı', !!fn);
    const body = fn[0];

    // Bu mimaride veritabanının IdP'den SONRA açılması normal bir sıralama.
    check('hata yakalanıyor', /catch \(e\)/.test(body));
    check('durum kullanıcıya söyleniyor', /database-offline/.test(body));
    check('tablolar temizleniyor', /database-services-body/.test(body) && /database-conn-body/.test(body));

    // Ve kayıt düğmesi kapatılıyor: veritabanı kapalıyken kayıt reddedilir (vekil ilk sırada
    // denenir) ve tıklanabilir bırakmak, denendiğinde reddedilecek bir işi teklif etmek olurdu.
    const renderApps = /function renderApplications\(\)\s*\{[\s\S]*?\n  \}/.exec(script)[0];
    check('veritabanı yokken kayıt düğmesi kapalı',
      /btn-new-application'\)\.disabled = !data\.databaseReachable/.test(renderApps));
    check('ve sebebi yazılıyor', /application-db-warning/.test(renderApps));
  }

  console.log('\n7. Sistem servisi uygulama gibi gösterilmiyor');

  {
    const script = panelScript();
    const fn = /function renderDatabase\(\)\s*\{[\s\S]*?\n  \}/.exec(script);
    check('renderDatabase tanımlı', !!fn);
    const body = fn[0];

    // Kimlik sağlayıcısı kabul kapısından geçiyor, kayıt defterinden değil: üzerinde işlem
    // yapılabilirmiş gibi göstermek, hiçbir işe yaramayan düğmelere basmaya davet etmek olur.
    check('sistem servisi ayırt ediliyor', /svc\.system/.test(body));
    check('sistem servisinde sayaç sıfırlama yok', /svc\.usage && !svc\.system/.test(body));
    check('servis sayımı sistemi dışarıda bırakıyor', /filter\(function \(x\) \{ return !x\.system; \}\)/.test(body));
  }

  console.log('\n8. Mühürleme ne yaptığını söylüyor');

  {
    const script = panelScript();
    check('mühürleme düğmesi bağlı', /btn-seal-database'\)\.addEventListener/.test(script));
    // Geri dönüşü kimlik sağlayıcısına bağlı olan bir işlemi, sonucunu söylemeden yaptırmak
    // yanlış olurdu.
    check('sonucu anlatılıyor', /her uygulamayı anında dışarıda bırakır/.test(script));
    check('planlı bakım için olmadığı söyleniyor', /planlı bakım için değildir/.test(script));
    check('gerekçe isteniyor', /seal-reason/.test(script));
  }

  console.log('\n9. Ekranlar gezinmeye bağlı ve açılışta yükleniyor');

  {
    check('Uygulamalar menüde', /data-view="applications"/.test(PANEL));
    check('Veritabanı menüde', /data-view="database"/.test(PANEL));
    check('Uygulamalar görünümü var', /id="view-applications"/.test(PANEL));
    check('Veritabanı görünümü var', /id="view-database"/.test(PANEL));
    // Yüklenmezlerse ekran açıldığında boş görünür ve operatör "hiç uygulama yok" sanır.
    check('ikisi de açılışta yükleniyor',
      /loadApplications\(\), loadDatabase\(\)/.test(panelScript()));
  }

  console.log(`\nOK - yönetim paneli ekranları: ${checks} kontrol geçti.`);
}

main();
process.exit(0);
