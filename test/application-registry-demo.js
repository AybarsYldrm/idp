'use strict';

const { createApplicationRegistry } = require('../core/application-registry');

// Bir uygulamayı sisteme TEK bir işlemle almak.
//
// Tünel, SMTP, DNS gibi uygulamalar için üç ayrı iş vardı: IdP'de OAuth istemcisi,
// veritabanında servis, ve ikisinin adlarının ELLE tutturulması. Üçüncüsü sessizce yanlış
// yapılabiliyordu -- iki ayrı ad, uygulamanın belirteç alıp veritabanına bağlanamaması demek,
// ve bu ancak ilk yazma denemesinde, iki sistemin günlüklerinde ayrı ayrı görünüyor.
//
// Buradaki kontrollerin ağırlığı YARIM KALMIŞ DURUMLARDA. İki ayrı süreç var, aralarında
// dağıtık bir işlem yok, ve bir taraf düştüğünde diğerinde ne kaldığı sistemi ya çalışır ya
// da sessizce bozuk bırakır:
//
//   * Sıralama düşme ihtimaline göre: önce veritabanı (kapalı olabilir), sonra OAuth (yerel).
//     Tersi sırada, veritabanı düştüğünde geriye sahibi olmayan bir OAuth istemcisi kalırdı
//     ve onu kimse fark etmezdi.
//   * OAuth düşerse veritabanı kaydı GERİ ALINIYOR -- yoksa aynı adla ikinci deneme "bu servis
//     zaten var" ile reddedilir ve operatör neyin yarım kaldığını anlamadan sıkışır.
//   * Geri alma da düşerse AÇIKÇA söyleniyor. Sessizce başarılı görünmek en kötüsü olurdu.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

async function rejects(label, fn, matcher = null) {
  let message = null;
  try { await fn(); } catch (err) { message = err.message; }
  check(label, message !== null && (!matcher || matcher.test(message)));
  return message;
}

/** IdP'nin istemci deposu yerine, ne yapıldığını kaydeden bir sahte. */
function fakeClientStore({ failCreate = false } = {}) {
  const clients = new Map();
  return {
    clients,
    async createClient({ clientId, clientSecret, name, redirectUris, allowedScopes }) {
      if (failCreate) throw new Error('istemci oluşturulamadı');
      if (clients.has(clientId)) throw new Error('client_exists');
      const record = {
        clientId, clientSecret, name, allowedScopes,
        redirects: (redirectUris || []).map((redirectUri) => ({ redirectUri, handle: `h-${redirectUri}` })),
      };
      clients.set(clientId, record);
      return record;
    },
    async deleteClient(clientId) {
      if (!clients.has(clientId)) throw new Error('not_found');
      clients.delete(clientId);
      return { deleted: true };
    },
    async listClients() { return [...clients.values()]; },
  };
}

/** Veritabanı vekili yerine: hangi çağrıların yapıldığını kaydeder ve düşürülebilir. */
function fakeDatabaseProxy({ services = new Map(), failCreate = false, failRemove = false, unreachable = false } = {}) {
  const calls = [];
  return {
    services,
    calls,
    async forward(method, route, body) {
      calls.push({ method, route, body });
      if (unreachable) {
        return { status: 503, payload: { error: 'database_unavailable', error_description: 'kapalı' } };
      }
      if (route === '/services' && method === 'POST') {
        if (failCreate) return { status: 500, payload: { error: 'boom', error_description: 'olmadı' } };
        if (services.has(body.name)) return { status: 409, payload: { error: 'exists' } };
        services.set(body.name, { ...body, spiffeId: `spiffe://fitfak.net/service/${body.name}` });
        return { status: 200, payload: { secret: `enrol-${body.name}` } };
      }
      if (route === '/services/remove') {
        if (failRemove) return { status: 500, payload: { error: 'remove_failed', error_description: 'silinemedi' } };
        services.delete(body.name);
        return { status: 200, payload: { removed: true } };
      }
      if (route === '/services' && method === 'GET') {
        return {
          status: 200,
          payload: {
            services: [...services.values()].map((s) => ({
              name: s.name, roles: s.roles, spiffeId: s.spiffeId,
              description: s.description, enrolledAt: 0, usage: null,
            })),
          },
        };
      }
      return { status: 404, payload: { error: 'not_proxied' } };
    },
  };
}

const secret = () => 'generated-secret-value';

function make(overrides = {}) {
  const clientStore = overrides.clientStore || fakeClientStore();
  const databaseProxy = overrides.databaseProxy || fakeDatabaseProxy();
  let changed = 0;
  const registry = createApplicationRegistry({
    clientStore,
    databaseProxy,
    trustDomain: 'fitfak.net',
    onChanged: async () => { changed += 1; },
  });
  return { registry, clientStore, databaseProxy, changes: () => changed };
}

async function main() {
  console.log('\n1. Tek ad, üç yerde birden');

  {
    const { registry, clientStore, databaseProxy } = make();
    const app = await registry.register({
      name: 'dns-resolver',
      description: 'DNS çözücü',
      redirectUris: ['https://dns.fitfak.net/oauth/callback'],
      roles: ['reader', 'writer'],
      generateSecret: secret,
    });

    // Elle eşleştirilecek bir şey kalmaması bu değişikliğin bütün noktası.
    check('OAuth istemci kimliği ad ile aynı', app.oauth.clientId === 'dns-resolver');
    check('veritabanı servis adı da', app.database.serviceName === 'dns-resolver');
    check('SPIFFE kimliği de addan türüyor', app.spiffeId === 'spiffe://fitfak.net/service/dns-resolver');
    check('istemci gerçekten oluşturuldu', clientStore.clients.has('dns-resolver'));
    check('servis gerçekten oluşturuldu', databaseProxy.services.has('dns-resolver'));

    // Sırlar BİR KEZ ve BİRLİKTE dönüyor: ayrı ayrı dönselerdi operatör birini kaydedip
    // diğerini kaçırırdı.
    check('OAuth sırrı dönüyor', app.oauth.clientSecret === 'generated-secret-value');
    check('kayıt sırrı dönüyor', app.database.enrolmentSecret === 'enrol-dns-resolver');

    // Değerleri iki panelden tek tek toplamak, bu işi zorlaştıran şeyin kendisiydi.
    check('ortam bloğu üretiliyor', app.environment.includes("FITFAK_SERVICE_NAME='dns-resolver'"));
    check('ortamda OAuth kimliği var', app.environment.includes('FITFAK_OAUTH_CLIENT_ID'));
    check('ortamda kayıt sırrı var', app.environment.includes('FITFAK_ENROLMENT_SECRET'));
    // Adres ve güven çıpası eşleştirme dizininden bulunuyor; buraya yazmak onları elle
    // girilen değerler hâline geri getirirdi.
    check('ortamda adres YOK', !app.environment.includes('FITFAK_DB_TARGET'));
  }

  console.log('\n2. Veritabanı ÖNCE deneniyor');

  {
    // Düşme ihtimali yüksek olan taraf o. Sonraya bırakılsaydı, düştüğünde geriye sahibi
    // olmayan bir OAuth istemcisi kalırdı.
    const { registry, clientStore, databaseProxy } = make({ databaseProxy: fakeDatabaseProxy({ unreachable: true }) });
    await rejects('veritabanı kapalıyken kayıt reddediliyor',
      () => registry.register({
        name: 'tunnel', redirectUris: ['https://tunnel.fitfak.net/cb'], generateSecret: secret,
      }), /Veritabanında servis oluşturulamadı/);

    check('geriye OAuth istemcisi KALMIYOR', clientStore.clients.size === 0);
    check('veritabanı önce denendi', databaseProxy.calls[0].route === '/services');
  }

  console.log('\n3. OAuth düşerse veritabanı kaydı geri alınıyor');

  {
    const databaseProxy = fakeDatabaseProxy();
    const { registry } = make({
      clientStore: fakeClientStore({ failCreate: true }),
      databaseProxy,
    });

    await rejects('kayıt reddediliyor',
      () => registry.register({
        name: 'smtp-relay', redirectUris: ['https://mail.fitfak.net/cb'], generateSecret: secret,
      }), /istemci oluşturulamadı/);

    // Geri alınmasaydı, aynı adla ikinci deneme "bu servis zaten var" ile reddedilir ve
    // operatör neyin yarım kaldığını anlamadan sıkışırdı.
    check('veritabanı servisi geri alındı', !databaseProxy.services.has('smtp-relay'));
    check('geri alma çağrısı yapıldı', databaseProxy.calls.some((c) => c.route === '/services/remove'));
  }

  console.log('\n4. Geri alma da düşerse SESSİZ KALINMIYOR');

  {
    const databaseProxy = fakeDatabaseProxy({ failRemove: true });
    const { registry } = make({
      clientStore: fakeClientStore({ failCreate: true }),
      databaseProxy,
    });

    const message = await rejects('hata bildiriliyor',
      () => registry.register({
        name: 'job-runner', redirectUris: ['https://jobs.fitfak.net/cb'], generateSecret: secret,
      }));
    // İki sistem birbirinden habersiz kaldı; operatörün bunu bilmesi ve nereye bakacağını
    // öğrenmesi gerekiyor.
    check('yarım kalan durum adlandırılıyor', /geri alınamadı/.test(message));
    check('ne yapılacağı söyleniyor', /elle silin/.test(message));
  }

  console.log('\n5. Kabul edilmeyen girdiler');

  {
    const { registry } = make();
    // Ad üç yerde kullanılıyor; üçünün de kabul ettiği biçimde olmak zorunda.
    for (const bad of ['Büyük-Harf', 'boşluklu ad', 'a', '-baslangic', 'nokta.li', '']) {
      await rejects(`ad reddediliyor: ${JSON.stringify(bad)}`,
        () => registry.register({ name: bad, redirectUris: ['https://x.fitfak.net/cb'], generateSecret: secret }));
    }

    // Yönlendirme adresi olmayan bir istemci yetkilendirme kodu alamaz; kaydı yine de
    // oluşturmak, çalışmayacağı ilk kullanıldığında anlaşılan bir uygulama bırakırdı.
    await rejects('OAuth isteyip adres vermeyen reddediliyor',
      () => registry.register({ name: 'no-redirect', redirectUris: [], generateSecret: secret }),
      /yönlendirme adresi gerekli/);

    await rejects('ikisini de istemeyen reddediliyor',
      () => registry.register({ name: 'nothing', needsOauth: false, needsDatabase: false, generateSecret: secret }),
      /kaydedilecek bir şey yok/);
  }

  console.log('\n6. Yalnızca bir tarafa ihtiyaç duyan uygulamalar');

  {
    const { registry, clientStore, databaseProxy } = make();

    // Arka planda çalışan bir işçi: veritabanına yazar ama tarayıcıdan giriş almaz.
    const worker = await registry.register({
      name: 'log-shipper', needsOauth: false, roles: ['writer'], generateSecret: secret,
    });
    check('yalnızca veritabanı kaydı', worker.database !== null && worker.oauth === null);
    check('OAuth istemcisi oluşturulmadı', !clientStore.clients.has('log-shipper'));
    check('SPIFFE kimliği yine de var', worker.spiffeId.endsWith('/service/log-shipper'));

    // Yalnızca giriş alan bir web uygulaması: veritabanına hiç dokunmaz.
    const web = await registry.register({
      name: 'status-page', needsDatabase: false,
      redirectUris: ['https://status.fitfak.net/cb'], generateSecret: secret,
    });
    check('yalnızca OAuth kaydı', web.oauth !== null && web.database === null);
    check('veritabanı servisi oluşturulmadı', !databaseProxy.services.has('status-page'));
  }

  console.log('\n7. Listeleme iki sistemin görüşünü birleştiriyor');

  {
    const { registry, clientStore, databaseProxy } = make();
    await registry.register({
      name: 'dns-resolver', redirectUris: ['https://dns.fitfak.net/cb'], generateSecret: secret,
    });
    // Yalnızca bir tarafta duran kayıtlar: iki ayrı panele bakan biri bunları göremez.
    await clientStore.createClient({
      clientId: 'yalniz-oauth', clientSecret: 'x', name: 'Yalnız OAuth',
      redirectUris: ['https://a.fitfak.net/cb'], allowedScopes: ['openid'],
    });
    databaseProxy.services.set('yalniz-db', {
      name: 'yalniz-db', roles: ['reader'], spiffeId: 'spiffe://fitfak.net/service/yalniz-db',
    });

    const { applications, databaseReachable } = await registry.list();
    check('veritabanına ulaşılabildi', databaseReachable === true);

    const byName = Object.fromEntries(applications.map((a) => [a.name, a]));
    check('tam kayıt iki tarafı da gösteriyor',
      !!byName['dns-resolver'].oauth && !!byName['dns-resolver'].database);
    check('tam kayıt eksiksiz işaretli', byName['dns-resolver'].missing === null);

    // Asıl değer bu: tek taraflı bir kayıt ÇALIŞMAZ ve panelde öyle görünmeli.
    check('yalnız OAuth kaydının eksiği bildiriliyor', byName['yalniz-oauth'].missing === 'database');
    check('yalnız veritabanı kaydının eksiği bildiriliyor', byName['yalniz-db'].missing === 'oauth');
  }

  console.log('\n8. Veritabanı kapalıyken listeleme yine de çalışıyor');

  {
    const { registry, clientStore } = make({ databaseProxy: fakeDatabaseProxy({ unreachable: true }) });
    await clientStore.createClient({
      clientId: 'web-app', clientSecret: 'x', name: 'Web',
      redirectUris: ['https://web.fitfak.net/cb'], allowedScopes: ['openid'],
    });

    const result = await registry.list();
    // Boş bir liste göstermek, uygulamaların silindiği izlenimi verirdi. Bilinen yarısını
    // gösterip diğerinin bilinmediğini söylemek doğru olan.
    check('bilinen taraf yine de listeleniyor', result.applications.length === 1);
    check('ve veritabanının bilinmediği söyleniyor', result.databaseReachable === false);
  }

  console.log('\n9. Kaldırma iki sistemden birden');

  {
    const { registry, clientStore, databaseProxy } = make();
    await registry.register({
      name: 'dns-resolver', redirectUris: ['https://dns.fitfak.net/cb'], generateSecret: secret,
    });

    const removed = await registry.remove('dns-resolver');
    check('OAuth istemcisi silindi', removed.oauth === true && !clientStore.clients.has('dns-resolver'));
    check('veritabanı servisi silindi', removed.database === true && !databaseProxy.services.has('dns-resolver'));
    check('hata yok', removed.errors.length === 0);
  }

  console.log('\n10. Kısmi kaldırma AÇIKÇA bildiriliyor');

  {
    const databaseProxy = fakeDatabaseProxy({ failRemove: true });
    const { registry } = make({ databaseProxy });
    await registry.register({
      name: 'dns-resolver', redirectUris: ['https://dns.fitfak.net/cb'], generateSecret: secret,
    });

    const removed = await registry.remove('dns-resolver');
    // "Silindi" deyip yarısını bırakmak, aynı adla ikinci bir kaydın anlaşılmaz bir çakışmayla
    // reddedilmesi demek.
    check('OAuth tarafı silindi', removed.oauth === true);
    check('veritabanı tarafı silinemedi', removed.database === false);
    check('ve bu söyleniyor', removed.errors.some((e) => /Veritabanı/.test(e)));
  }

  console.log('\n11. Değişiklikler haber veriliyor');

  {
    const { registry, changes } = make();
    await registry.register({
      name: 'dns-resolver', redirectUris: ['https://dns.fitfak.net/cb'], generateSecret: secret,
    });
    // Yeni bir uygulamanın kaynağı hemen izinli olmalı: ilk tarayıcı isteğinin CORS'ta
    // reddedilmesi, kaydın çalışmadığı izlenimi verir.
    check('kayıtta haber veriliyor', changes() === 1);
    await registry.remove('dns-resolver');
    check('kaldırmada da', changes() === 2);
  }

  console.log(`\nOK - uygulama kaydı: ${checks} kontrol geçti.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message, err.stack); process.exit(1); },
);
