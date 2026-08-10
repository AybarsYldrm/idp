'use strict';

const { StagingStore, StagingFull } = require('../core/staging-store');
const { createMockDb } = require('./mock-db');

// Veritabanı yokken yazılanların, geldiğinde kaybolmaması.
//
// Bu tamponun var olma sebebi bir kilitlenme: veritabanı mühürlü açılır ve IdP ona bir sunucu
// sertifikası verene kadar kimseye hizmet etmez, yani IdP yazamadığı bir pencerede ayakta
// olmak zorundadır. O pencerede yönetici giriş yapıp ilk yapılandırmayı yapabilmeli.
//
// Kritik olan kısım KİMLİK YENİDEN YAZIMI. Tamponda üretilen kimlikler gerçek veritabanınınkiler
// değil; boşaltmada motor kendi kimliğini üretir. Yeniden yazılmazsa şu olur ve hiçbir yerde
// hata vermez: bir oturumun `userId`'si var olmayan bir kullanıcıyı gösterir, bir
// `userId:deviceId` bileşik anahtarı hiçbir zaman eşleşmez, ve kullanıcı "giriş yaptım ama
// hesabım yok" durumunda kalır.
//
// Bileşik anahtarlar bu yüzden ayrıca sınanıyor: tam eşitlikle yeniden yazan bir uygulama
// doğrudan referansları düzeltir ve bileşikleri sessizce bozuk bırakır -- yani testlerin
// yarısı geçer.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

async function rejects(label, fn) {
  let threw = false;
  try { await fn(); } catch (_) { threw = true; }
  check(label, threw);
}

function realDb() {
  return createMockDb(['users', 'sessions', 'user_devices', 'oauth_clients']);
}

async function main() {
  console.log('\n1. Tampon: yazmalar tutuluyor, okumalar görüyor');

  {
    const staging = new StagingStore();
    const users = staging.collection('users');

    const id = await users.insert({ username: 'aybars', email: 'a@fitfak.net' });
    check('bir kimlik döndü', typeof id === 'string');
    // Aranabilir bir desen: boşaltmada alt dize olarak bulunup değiştirilebilmesi buna bağlı.
    check('tampon kimliği aranabilir bir desen', /^stg_[0-9a-f]{32}$/.test(id));

    check('kayıt geri okunabiliyor', (await users.get(id)).username === 'aybars');
    check('alan üzerinden bulunabiliyor', (await users.findOne('email', 'a@fitfak.net')).username === 'aybars');
    check('işlem günlüğe alındı', staging.size === 1);
  }

  console.log('\n2. Boşaltma: sıra korunuyor, kimlikler yeniden yazılıyor');

  {
    const staging = new StagingStore();
    const users = staging.collection('users');
    const sessions = staging.collection('sessions');
    const devices = staging.collection('user_devices');

    const userId = await users.insert({ username: 'aybars', email: 'a@fitfak.net' });
    await sessions.insert({ sessionId: 's1', userId, ip: '10.0.0.1' });
    // Bileşik anahtar: tam eşitlikle yeniden yazan bir uygulama bunu KAÇIRIR.
    await devices.insert({ userDeviceKey: `${userId}:dev-1`, userId, deviceId: 'dev-1' });

    const db = realDb();
    const summary = await staging.flushTo(db);
    check('üç ekleme oynatıldı', summary.inserts === 3);
    check('tampon boşaldı', staging.size === 0);

    const realUser = (await db.collection('users').find('username', 'aybars'))[0];
    check('kullanıcı gerçek veritabanında', !!realUser);
    check('gerçek kimlik tampon kimliğinden farklı', realUser._id !== userId);

    const realSession = (await db.collection('sessions').find('sessionId', 's1'))[0];
    check('oturumun userId\'si GERÇEK kimliği gösteriyor', realSession.userId === realUser._id);

    const realDevice = (await db.collection('user_devices').find('deviceId', 'dev-1'))[0];
    check('bileşik anahtar da yeniden yazıldı', realDevice.userDeviceKey === `${realUser._id}:dev-1`);
    check('ve içindeki tampon kimliği kalmadı', !realDevice.userDeviceKey.includes('stg_'));
  }

  console.log('\n3. İç içe yapılarda da yeniden yazılıyor');

  {
    const staging = new StagingStore();
    const users = staging.collection('users');
    const clients = staging.collection('oauth_clients');

    const userId = await users.insert({ username: 'admin' });
    await clients.insert({
      clientId: 'panel',
      // Dizi ve iç içe nesne: bir JSON alanına gömülmüş referans da düzeltilmeli.
      owners: [userId],
      meta: { createdBy: userId, note: `sahibi ${userId}` },
    });

    const db = realDb();
    await staging.flushTo(db);
    const realUser = (await db.collection('users').find('username', 'admin'))[0];
    const client = (await db.collection('oauth_clients').find('clientId', 'panel'))[0];

    check('dizi içindeki referans yeniden yazıldı', client.owners[0] === realUser._id);
    check('iç içe nesnedeki referans yeniden yazıldı', client.meta.createdBy === realUser._id);
    check('metin içine gömülü referans yeniden yazıldı', client.meta.note === `sahibi ${realUser._id}`);
  }

  console.log('\n4. Güncelleme ve silme de oynatılıyor');

  {
    const staging = new StagingStore();
    const users = staging.collection('users');

    const keep = await users.insert({ username: 'kalan', status: 'pending' });
    const drop = await users.insert({ username: 'silinen' });
    await users.update(keep, { status: 'active' });
    await users.delete(drop);

    const db = realDb();
    const summary = await staging.flushTo(db);
    check('iki ekleme, bir güncelleme, bir silme', summary.inserts === 2 && summary.updates === 1 && summary.deletes === 1);

    const rows = db.collection('users')._debugAll();
    check('yalnızca bir kayıt kaldı', rows.length === 1);
    check('kalan kaydın güncellemesi uygulandı', rows[0].status === 'active');
  }

  console.log('\n5. Boşaltmada tekillik çakışması bir BİRLEŞMEDİR, bir hata değil');

  {
    const staging = new StagingStore();
    // Aynı e-posta veritabanında ZATEN var: tamponun göremediği bir durum.
    const db = realDb();
    await db.collection('users').insert({ username: 'aybars', email: 'a@fitfak.net' });

    await staging.collection('users').insertUnique({ username: 'aybars', email: 'a@fitfak.net' }, { unique: ['email'] });
    await staging.collection('users').insert({ username: 'yeni', email: 'y@fitfak.net' });

    const summary = await staging.flushTo(db);
    check('çakışan kayıt atlandı', summary.conflicts === 1);
    // Asıl mesele: boşaltma durmadı. Durursa çakışmadan SONRAKİ her şey de kaybolurdu.
    check('çakışmadan sonraki kayıt yine de yazıldı', summary.inserts === 1);
    check('veritabanında iki kullanıcı var', db.collection('users')._debugAll().length === 2);
  }

  console.log('\n6. Tampon içinde tekillik anında yakalanıyor');

  {
    const staging = new StagingStore();
    await staging.collection('users').insertUnique({ email: 'a@fitfak.net' }, { unique: ['email'] });
    await rejects('aynı değerle ikinci ekleme reddedilir',
      () => staging.collection('users').insertUnique({ email: 'a@fitfak.net' }, { unique: ['email'] }));
  }

  console.log('\n7. Tampon sınırsız büyümüyor');

  {
    const staging = new StagingStore({ maxOperations: 5 });
    for (let i = 0; i < 5; i++) await staging.collection('users').insert({ n: i });
    // Sessizce düşürmek, yöneticiye kaydedildiğini söyleyip kaydetmemek olurdu.
    await rejects('sınır dolunca yazma REDDEDİLİR', () => staging.collection('users').insert({ n: 6 }));
    check('sınırdaki kayıtlar duruyor', staging.size === 5);
  }

  console.log('\n8. Şema veriden ÖNCE uygulanıyor');

  {
    const staging = new StagingStore();
    const order = [];
    await staging.applySchemaRegistry({ users: { fields: [] }, sessions: { fields: [] } });
    await staging.collection('users').insert({ username: 'x' });

    const db = realDb();
    const originalApply = db.applySchemaRegistry.bind(db);
    db.applySchemaRegistry = async (r) => { order.push('schema'); return originalApply(r); };
    const usersCollection = db.collection('users');
    const originalInsert = usersCollection.insert.bind(usersCollection);
    usersCollection.insert = async (r) => { order.push('insert'); return originalInsert(r); };

    await staging.flushTo(db);
    // Alanları tanımlanmamış bir koleksiyona yazmak, motorun kaydı reddetmesi ya da
    // indeksleri hiç kurmaması demek olurdu.
    check('önce şema, sonra veri', order[0] === 'schema' && order[1] === 'insert');
  }

  console.log('\n9. Boşaltmadan sonra tampon temiz');

  {
    const staging = new StagingStore();
    await staging.collection('users').insert({ username: 'a' });
    const db = realDb();
    await staging.flushTo(db);

    check('işlem günlüğü boş', staging.size === 0);
    // İkinci bir boşaltma aynı kayıtları TEKRAR yazmamalı.
    const second = await staging.flushTo(db);
    check('ikinci boşaltma bir şey yazmıyor', second.inserts === 0);
    check('veritabanında tek kayıt var', db.collection('users')._debugAll().length === 1);
  }

  console.log('\n10. Durum raporu');

  {
    const staging = new StagingStore({ maxOperations: 100 });
    await staging.collection('users').insert({ username: 'a' });
    await staging.collection('sessions').insert({ sessionId: 's' });
    const status = staging.status();
    check('işlem sayısı doğru', status.operations === 2);
    check('koleksiyonlar listeleniyor', status.collections.includes('users') && status.collections.includes('sessions'));
    check('kayıt sayısı doğru', status.records === 2);
    check('sınır bildiriliyor', status.maxOperations === 100);
  }

  console.log(`\nOK - açılış tamponu: ${checks} kontrol geçti.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message, err.stack); process.exit(1); },
);
