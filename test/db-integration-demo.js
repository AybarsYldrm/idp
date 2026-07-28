'use strict';

const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const crypto = require('node:crypto');

// IdP <-> veritabanı: gerçek gRPC sunucusuna karşı uçtan uca.
//
// core/db-bootstrap.js'in yaptığı işin gerçekten çalıştığının kanıtı. Şimdiye
// kadarki testler bootstrap akışını VERİTABANI tarafından doğruluyordu; bu test
// IdP tarafını, yani ürünün gerçekten çalıştıracağı kod yolunu koşturuyor:
//
//   1. veritabanı sunucusu bir CA'dan TLS kimliği alır ve dinlemeye başlar
//   2. IdP'nin hiçbir şeyi yoktur -- yalnızca tek kullanımlık bir enrolment sırrı
//   3. connectToDatabase(): bootstrap TLS -> güven çıpaları -> enrolment -> mTLS
//   4. IdP şemasını uygular ve koleksiyonlarını kullanır
//   5. süreç yeniden başlar: diskteki sertifikadan devam, sır KULLANILMAZ

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

let db;
try {
  db = require('@fitfak/database');
  require('@fitfak/grpc');
} catch (_) {
  console.log('SKIP - db entegrasyonu: @fitfak/database veya @fitfak/grpc kurulu degil');
  process.exit(0);
}

const {
  createDatabaseServer, createSharedSecretAttestor, createRenewalAttestor,
  createCompositeAttestor, generateEnrolmentSecret,
} = db;

const testPki = require(path.join(
  path.dirname(require.resolve('@fitfak/database/package.json')), 'test', 'helpers', 'test-pki',
));

async function main() {
  const baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'idp-db-'));
  const identityDir = path.join(baseDir, 'identity');
  const dataDir = path.join(baseDir, 'data');

  console.log('\n[1] Veritabanı sunucusu ayakta, kayıt otoritesi olarak');
  const authority = testPki.createTestCaBackend();
  const serverTls = testPki.createServerIdentity(authority, { commonName: 'localhost' });
  const enrolmentSecret = generateEnrolmentSecret();

  let consumed = 0;
  const server = createDatabaseServer({
    baseDir: path.join(baseDir, 'fitdb'),
    principals: { 'idp-service': { roles: ['admin'] } },
    enrollment: {
      caBackend: authority,
      attestor: createCompositeAttestor([
        createSharedSecretAttestor({
          enrolments: {
            'idp-service': {
              secret: enrolmentSecret,
              subject: { CN: 'idp-service' },
              altNames: ['idp-service'],
              roles: ['admin'],
              maxUses: 1,
            },
          },
          onConsumed: () => { consumed += 1; },
        }),
        createRenewalAttestor({ roleResolver: () => ['admin'] }),
      ]),
    },
  });
  server.listen(0, { host: '127.0.0.1', tls: serverTls.tlsOptions });
  await new Promise((resolve) => server.app.server.server.once('listening', resolve));
  const target = `https://localhost:${server.address().port}`;
  check('sunucu dinliyor', !!server.address().port);

  console.log('\n[2] IdP ilk kez bağlanıyor: TLS -> enrolment -> mTLS');
  const { connectToDatabase } = require('../core/db-bootstrap');
  const schema = require('../db/schema');

  const config = {
    dataDir,
    db: {
      remoteTarget: target,
      dbId: null,
      ownerId: 'fitfak-idp-service',
      serviceName: 'idp-service',
      enrolmentSecret: enrolmentSecret.toString('base64'),
      caFingerprint: authority.ca.fingerprint256,
      identityDir,
      rootSecret: crypto.randomBytes(32),
    },
  };

  const first = await connectToDatabase({ config, logger: { info: () => {}, warn: () => {} } });
  check('mTLS ile bağlanıldı', first.mode === 'mtls');
  check('kimlik alındı', first.identity.principal === 'idp-service');
  check('kanal karşılıklı doğrulamalı', first.identity.client.channelInfo().mutual === true);
  check('enrolment sırrı tüketildi', consumed === 1);
  check('kimlik diske yazıldı', fs.existsSync(path.join(identityDir, 'identity.json')));

  const stored = JSON.parse(await fsp.readFile(path.join(identityDir, 'identity.json'), 'utf8'));
  check('sertifika saklandı', !!stored.certPem);
  check('özel anahtar saklandı', !!stored.privateKeyPem);
  const mode = (await fsp.stat(path.join(identityDir, 'identity.json'))).mode & 0o777;
  check('kimlik dosyası 0600', mode === 0o600);

  console.log('\n[3] IdP şemasını uyguluyor ve koleksiyonlarını kullanıyor');
  // ÜRÜNÜN yaptığı gibi: bootstrap'ın açtığı veritabanı kullanılıyor
  // (oauth-server.js#bootstrapDatabase şemayı tam olarak buna uygular).
  // Test eskiden AYRI bir veritabanı oluşturup şemayı ona uyguluyordu; o
  // yüzden bootstrap'ın kendi veritabanını yeniden açabildiği hiç sınanmadı.
  const database = first.db;
  await database.applySchemaRegistry(schema);
  // Uzak istemcide listCollections() ayrıntı nesneleri döner (yerelde dizi);
  // isim alanına indirgiyoruz.
  const raw = await database.listCollections();
  const collections = raw.map((c) => (typeof c === 'string' ? c : c.name));
  for (const name of ['users', 'sessions', 'user_devices', 'user_profiles', 'ct_log_entries']) {
    check(`koleksiyon tanımlı: ${name}`, collections.includes(name));
  }

  console.log('\n[4] IdP servisleri uzak veritabanıyla çalışıyor');
  const authService = require('../services/auth-service');
  const { SessionManager } = require('../core/session-manager');
  const { loadOrCreateSigningKeyPair } = require('../core/keys');
  const { completeLogin } = require('../services/login-completion');

  const keyDir = path.join(baseDir, 'keys');
  const sessionManager = new SessionManager({
    store: authService.createSessionStoreAdapter(database),
    signingKeyPair: loadOrCreateSigningKeyPair(keyDir),
    issuer: 'https://session.fitfak.net', cookieDomain: '.fitfak.net',
  });

  const userId = await database.collection('users').insert({
    username: 'aybars', email: 'a@fitfak.net', status: 'active', emailVerified: true,
    mfaMethods: '[]', createdAt: BigInt(Date.now()),
  });
  check('kullanıcı uzak veritabanına yazıldı', !!userId);

  const found = await database.collection('users').findOne('email', 'a@fitfak.net');
  check('kör indeksle okundu', found && found.username === 'aybars');

  // Oturum akışı: cihaz bağlama, tazeleme, hepsi uzak veritabanı üzerinden.
  const deviceId = require('../core/device-binding').newDeviceId();
  const login1 = await completeLogin({
    db: database, sessionManager, userId, ip: '203.0.113.7',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/120', fingerprintId: 'fp', deviceId,
  });
  check('oturum açıldı', !!login1.sessionId);

  for (let i = 0; i < 4; i++) {
    await completeLogin({
      db: database, sessionManager, userId, ip: '203.0.113.7',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/120', fingerprintId: 'fp', deviceId,
    });
  }
  const sessions = (await sessionManager.listSessions(String(userId))).filter((s) => !s.revoked);
  check('5 giriş -> tek oturum (uzak veritabanında da)', sessions.length === 1);

  // Profil ve avatar da uzak veritabanı üzerinden.
  const profileService = require('../services/profile-service');
  await profileService.updateProfile({ db: database, userId, displayName: 'Aybars' });
  const profile = await profileService.getProfile({ db: database, userId });
  check('profil uzak veritabanında', profile.displayName === 'Aybars');

  console.log('\n[5] Yeniden başlatma: sertifikadan devam, sır KULLANILMIYOR');
  first.identity.close();
  first.handle.close();

  const second = await connectToDatabase({ config, logger: { info: () => {}, warn: () => {} } });
  check('yeniden bağlanıldı', second.mode === 'mtls');
  check('aynı principal', second.identity.principal === 'idp-service');
  check('enrolment sırrı TEKRAR kullanılmadı', consumed === 1);
  check('kanal yine mTLS', second.identity.client.channelInfo().mutual === true);

  // Veritabanının kendisi de yeniden AÇILABİLMELİ. Bu kontrol bir hata
  // yakaladı: bootstrap ilk açılışta veritabanını oluşturup dönen istemci
  // sırrını KULLANIP ATIYOR, sonraki açılışta ise kök sırla açmayı deniyordu.
  // O iki değer aynı değil ve sunucu istemci sırrını saklamıyor -- yani sistem
  // BİR KEZ çalışıp sonra kendi veritabanını bir daha açamıyordu. Test bunu
  // göremiyordu çünkü sırrı bellekte taşıyıp elle geri veriyordu.
  check('veritabanı tutamağı diske yazıldı', fs.existsSync(path.join(identityDir, 'database.json')));
  const handleMode = (await fsp.stat(path.join(identityDir, 'database.json'))).mode & 0o777;
  check('tutamak dosyası 0600', handleMode === 0o600);

  check('bootstrap veritabanını KENDİSİ açtı', !!second.db);
  const reopenedByBootstrap = await second.db.collection('users').findOne('email', 'a@fitfak.net');
  check('bootstrap\'ın açtığı veritabanında veriler yerinde',
    reopenedByBootstrap && reopenedByBootstrap.username === 'aybars');
  const storedHandle = JSON.parse(await fsp.readFile(path.join(identityDir, 'database.json'), 'utf8'));
  check('tutamakta dbId var', !!storedHandle.dbId);
  check('tutamakta istemci sırrı var', !!storedHandle.clientSecret);
  // Sır KÖK SIRRIN kendisi değil: sunucu oluşturma anında kendi sırrını üretir
  // ve bir daha vermez. Eskiden bootstrap kök sırla açmayı deniyordu.
  check('sır kök sırdan FARKLI',
    storedHandle.clientSecret !== config.db.rootSecret.toString('base64'));

  console.log('\n[6] Sırsız ve sertifikasız bağlanma denemesi reddediliyor');
  await fsp.rm(identityDir, { recursive: true, force: true });
  let refused = false;
  try {
    await connectToDatabase({
      config: { ...config, db: { ...config.db, enrolmentSecret: null } },
      logger: { info: () => {}, warn: () => {} },
    });
  } catch (e) { refused = /enrolment/i.test(e.message) || /kimlik/i.test(e.message); }
  check('kimlik ve sır yokken bağlanılamıyor', refused);

  let noTrust = false;
  try {
    await connectToDatabase({
      config: { ...config, db: { ...config.db, caFingerprint: null, caPath: null } },
      logger: { info: () => {}, warn: () => {} },
    });
  } catch (e) { noTrust = /güven çıpası/i.test(e.message); }
  check('güven çıpası olmadan bağlanılamıyor', noTrust);

  second.identity.close();
  second.handle.close();
  await server.close();
  await fsp.rm(baseDir, { recursive: true, force: true });
  console.log(`\nOK - IdP <-> veritabanı entegrasyonu: ${checks} kontrol geçti.`);
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
