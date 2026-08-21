'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { createInternalRedirects, DEFAULT_DESTINATION } = require('../core/internal-redirects');

// IdP'nin kendi sayfaları arasındaki dönüş adresleri.
//
// Eskiden `?return_to=%2Fadmin` idi. Doğrulanıyordu -- hem sunucuda hem sayfada `safeRedirect`
// çağrılıyordu -- yani açık yönlendirme AÇIK DEĞİLDİ. Ama yüzey oradaydı: her yeni çağrı
// yerinde doğrulamanın tekrar yapılması gerekiyordu, ve o çağrı yerlerinden biri unutulduğunda
// bunu hiçbir şey söylemezdi. Üstelik hedef yol adres çubuğunda, tarayıcı geçmişinde ve ekran
// görüntüsünde görünür kalıyordu.
//
// Şimdi URL'de yol değil, kayıtlı bir listeye karşılık gelen opak bir TUTAMAK var. Farkın özü
// şu: uydurulmuş bir tutamak hiçbir yere çözülmez. Açık yönlendirme, engellenmesi gereken bir
// şey olmaktan çıkıp İFADE EDİLEMEZ bir şey haline geliyor -- ve ifade edilemeyen bir şeyin
// yanlışlıkla ifade edildiği bir çağrı yeri de olamaz.
//
// Aşağıdaki kontrollerin ağırlığı burada: kayıtlı olmayan HİÇBİR şeyin tutamağa çevrilememesi
// ve hiçbir tutamağın kayıtlı olmayan bir yere çözülmemesi.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

const SECRET = Buffer.alloc(32, 0x5a);
const make = (secret = SECRET) => createInternalRedirects({ secret });

function main() {
  console.log('\n1. Kayıtlı sayfalar tutamağa çevriliyor ve geri çözülüyor');

  {
    const r = make();
    for (const target of ['/portal', '/profile', '/admin', '/consent']) {
      const handle = r.handleFor(target);
      check(`${target} bir tutamak alıyor`, typeof handle === 'string' && handle.startsWith('fru.'));
      check(`${target} geri çözülüyor`, r.resolve(handle) === target);
    }
    // İki sayfanın aynı tutamağa düşmesi, birine gitmek isteyen kullanıcıyı diğerine götürürdü.
    const handles = new Set(r.list().map((e) => e.handle));
    check('her sayfanın tutamağı farklı', handles.size === r.list().length);
    // Tutamak yolu AÇIKÇA taşımamalı: taşısaydı, gizlemeye çalıştığımız şey URL'de kalırdı.
    check('tutamak yolu metin olarak içermiyor', !r.handleFor('/admin').includes('admin'));
  }

  console.log('\n2. Kayıtlı OLMAYAN hiçbir şey tutamağa çevrilemiyor');

  {
    const r = make();
    // Asıl mesele bu. Bunlardan herhangi birine tutamak veren bir uygulama, açık yönlendirmeyi
    // geri getirmiş olurdu.
    for (const bad of [
      'https://saldirgan.example/',
      '//saldirgan.example/',
      '/admin/../../etc/passwd',
      '/gizli-sayfa',
      'javascript:alert(1)',
      '',
      null,
      undefined,
    ]) {
      check(`tutamak verilmiyor: ${JSON.stringify(bad)}`, r.handleFor(bad) === null);
    }
  }

  console.log('\n3. Uydurulmuş bir tutamak hiçbir yere çözülmüyor');

  {
    const r = make();
    for (const bad of ['fru.aaaaaaaaaaaaaaaaaaaaaaaa', 'fru.', 'not-a-handle', '/admin', '', null]) {
      check(`çözülmüyor: ${JSON.stringify(bad)}`, r.resolve(bad) === null);
      // Ve çağıran her zaman bir yere gidebilmeli: hata göstermek yerine varsayılana düşmek,
      // "bağlantı eskimiş" ile "bir hata var" arasında fark görmeyen kullanıcı için doğru olan.
      check(`varsayılana düşüyor: ${JSON.stringify(bad)}`, r.destinationFor(bad) === DEFAULT_DESTINATION);
    }

    // BAŞKA bir sırla üretilmiş bir tutamak da kabul edilmemeli: kabul edilseydi, sırrın
    // doğrulamada hiçbir rolü olmazdı.
    const other = make(Buffer.alloc(32, 0x11));
    check('başka sırla üretilmiş tutamak reddediliyor', r.resolve(other.handleFor('/admin')) === null);
  }

  console.log('\n4. Tutamaklar yeniden başlatmalar arasında AYNI kalıyor');

  {
    // Rastgele üretilip saklansaydı, bir yeniden başlatma dışarıda paylaşılmış her bağlantıyı
    // kırardı. HMAC ile türetmek, durum tutmadan aynı cevabı vermeyi sağlıyor.
    const a = make();
    const b = make();
    check('aynı sır aynı tutamağı veriyor', a.handleFor('/admin') === b.handleFor('/admin'));
    check('farklı sır farklı tutamak', make(Buffer.alloc(32, 1)).handleFor('/admin') !== a.handleFor('/admin'));
  }

  console.log('\n5. Sorgu dizesi tutamağı değiştirmiyor');

  {
    const r = make();
    const base = r.handleFor('/admin');
    // Aksi halde her sorgu dizesi ayrı bir tutamak olurdu ve liste kapalı olmazdı -- yani
    // saldırgan kendi sorgusunu ekleyerek yeni bir "kayıtlı" hedef üretebilirdi.
    check('sorgu atılıyor', r.handleFor('/admin?next=https://saldirgan.example') === base);
    check('parça atılıyor', r.handleFor('/admin#x') === base);
  }

  console.log('\n6. Giriş bağlantısı tutamakla kuruluyor');

  {
    const r = make();
    const url = r.loginUrl('/admin');
    check('ru parametresi var', url.includes('ru=fru.'));
    // Hedefin URL'de metin olarak görünmemesi bu değişikliğin ikinci sebebiydi.
    check('yol URL\'de görünmüyor', !url.includes('admin'));
    check('return_to yok', !url.includes('return_to'));

    const withExtra = r.loginUrl('/portal', { choose_account: '1' });
    check('ek parametreler korunuyor', withExtra.includes('choose_account=1') && withExtra.includes('ru='));

    // Kayıtsız bir hedef için tutamak yok: bağlantı yine de çalışmalı, sadece dönüş adresi
    // olmadan. Uydurmak, listeyi kapalı tutmanın anlamını ortadan kaldırırdı.
    check('kayıtsız hedef için düz /login', r.loginUrl('https://saldirgan.example') === '/login');
  }

  console.log('\n7. Sunucu tarafında return_to kalmadı');

  {
    const source = fs.readFileSync(path.join(__dirname, '..', 'oauth-server.js'), 'utf8');
    // Yorumlar dışında hiçbir yerde üretilmemeli: tek bir kalıntı çağrı yeri, kapatılan yüzeyi
    // geri açardı.
    const lines = source.split('\n').filter((line) => line.includes('return_to') && !line.trim().startsWith('//'));
    check('hiçbir yönlendirme return_to üretmiyor', lines.length === 0);
    check('tutamak üreten yol kullanılıyor', /internalRedirects\.loginUrl\(/.test(source));

    // Tutamak sayfada değil sunucuda çözülüyor: sayfada çözmek, listenin tarayıcıya gömülmesi
    // ve sistemin iç yapısının giriş yapmamış herkese açılması demek olurdu.
    check('çözüm ucu var', /path: '\/auth\/resolve-ru'/.test(source));
    check('tutamak haritası sunucudan geliyor', /redirect-handles\.js/.test(source));
  }

  console.log('\n8. Sayfalar tutamak haritasını kullanıyor');

  {
    for (const page of ['portal.html', 'profile.html']) {
      const html = fs.readFileSync(path.join(__dirname, '..', 'public', page), 'utf8');
      check(`${page}: harita yükleniyor`, html.includes('/static/redirect-handles.js'));
      check(`${page}: ru ile yönlendiriyor`, /ru=' \+ encodeURIComponent\(FITFAK_RU\./.test(html));
      check(`${page}: return_to kalmadı`, !html.includes('return_to'));
    }

    const login = fs.readFileSync(path.join(__dirname, '..', 'public', 'demo-login.html'), 'utf8');
    check('giriş sayfası ru okuyor', /params\.get\('ru'\)/.test(login));
    // Eski bağlantılar dışarıda paylaşılmış olabilir; bugün kırmanın faydası yok. Ama
    // safeRedirect'ten geçmeye devam ediyor, yani yüzey kapalı.
    check('eski return_to hâlâ kabul ediliyor', /params\.get\('return_to'\)/.test(login));
    check('ve hâlâ doğrulanıyor', /safeRedirect\(\s*\n?\s*params\.get\('return_to'\)/.test(login));
  }

  console.log('\n9. Yüzeyler arası yönlendirme MUTLAK adres kullanıyor');

  {
    // `/admin` one.fitfak.net'te, giriş sayfası session.fitfak.net'te. Göreli bir adres
    // tarayıcı tarafından BULUNULAN kökene göre çözülür, yani yönetici one.fitfak.net/login'e
    // gidiyordu -- orada giriş sayfası yok. Ters yönde de aynısı: giriş sayfası tutamağı
    // çözüp `/admin` alıyor ve session.fitfak.net/admin'e gidiyordu; orada da /admin yok.
    // İki yönde de 404, ve iki adres de tek başına doğru göründüğü için hiçbir şey söylemiyor.
    const redirects = createInternalRedirects({
      secret: Buffer.alloc(32, 7),
      origins: { idp: 'https://session.fitfak.net', admin: 'https://one.fitfak.net' },
    });

    const adminLogin = redirects.loginUrl('/admin');
    check('one.fitfak.net/admin -> mutlak giriş adresi',
      adminLogin.startsWith('https://session.fitfak.net/login?'));
    check('ve dönüş tutamağını taşıyor', /[?&]ru=fru\./.test(adminLogin));

    const adminBack = redirects.destinationFor(redirects.handleForName('admin'));
    check('giriş sonrası dönüş de mutlak', adminBack === 'https://one.fitfak.net/admin');

    // Aynı yüzey içindekiler GÖRELİ kalmalı: mutlak adres koymak, yerel bir kurulumu
    // yapılandırmadaki dış hostname'e göndermek olurdu.
    check('aynı yüzeydeki giriş göreli', redirects.loginUrl('/portal').startsWith('/login?'));
    check('aynı yüzeydeki dönüş göreli',
      redirects.destinationFor(redirects.handleForName('portal')) === '/portal');

    // Köken verilmediğinde göreli kalıyor: yapılandırılmamış bir hostname uydurmak, bir
    // kurulumu var olmayan bir adrese göndermek demek.
    const noOrigins = createInternalRedirects({ secret: Buffer.alloc(32, 7) });
    check('köken yoksa göreli kalıyor', noOrigins.loginUrl('/admin').startsWith('/login?'));

    // Tutamaklar kökenden BAĞIMSIZ türetiliyor: bir host değişikliği dışarıda paylaşılmış
    // her bağlantıyı kırmamalı.
    check('tutamak kökene bağlı değil',
      noOrigins.handleForName('admin') === redirects.handleForName('admin'));
  }

  console.log(`\nOK - iç dönüş adresleri: ${checks} kontrol geçti.`);
}

main();
process.exit(0);
