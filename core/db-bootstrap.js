'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

// IdP ile veritabanı arasındaki yumurta-tavuk sorununun çözümü.
//
// Bağımlılık gerçekten çift yönlüdür:
//
//   IdP  -> veritabanı   : oturumları, kullanıcıları, sertifika kayıtlarını orada tutar
//   veritabanı -> IdP    : "bu bağlanan kim ve ne yapmaya yetkili" sorusunu ona sorar
//
// Bu döngü kendiliğinden kırılmaz. Kırılması için zincirin bir ucunun, karşı
// tarafa hiç soru sormadan doğrulanabilir olması gerekir -- ilk çalıştırmada
// bunu yapan şey sunucunun TLS sertifikasıdır (server.crt/key) ve IdP'ye elden
// verilmiş tek kullanımlık bir enrolment sırrıdır.
//
// Sıra şudur ve her adım bir öncekinin kanıtına dayanır:
//
//   0. soğuk açılış     veritabanı sunucusunun bir TLS kimliği vardır (kendi
//                       CA'sından ya da elle sağlanmış server.crt/key). IdP'nin
//                       hiçbir şeyi yoktur.
//   1. bootstrap TLS    SADECE sunucu kimliğini kanıtlar. IdP sunucuyu pinlenmiş
//                       CA parmak iziyle doğrular. Bu kanal üzerinde yalnızca
//                       EnrollmentService erişilebilir.
//   2. güven çıpaları   IdP CA bundle'ını çeker. Bunlar açık veridir; istek
//                       hiçbir sır taşımaz.
//   3. enrolment        IdP, paylaşılan sırla HMAC üretir (TLS oturumuna ve CSR'ye
//                       bağlı), CSR'sini yollar, sertifikasını alır.
//   4. mTLS'e yükselme  aynı hedefe, artık karşılıklı kimlik doğrulamalı.
//   5. kararlı durum    veri düzlemi yalnızca mTLS. Paylaşılan sır TÜKENMİŞTİR.
//   6. yenileme         mTLS üzerinden, süre dolmadan. Sır bir daha kullanılmaz.
//
// Adım 5'ten sonra döngü artık yoktur: IdP ayaktadır, dolayısıyla veritabanı
// SONRAKİ her servis için kimlik sorusunu IdP'ye sorabilir (bkz.
// createIdpTokenAttestor). Paylaşılan sır yalnızca ilk halkayı kurmak içindir
// ve bu yüzden tek kullanımlıktır -- kalıcı olsaydı kimlik sisteminin yanında
// duran kalıcı bir arka kapı olurdu.

const IDENTITY_FILE = 'identity.json';
// Veritabanı tutamağı: dbId + istemci sırrı. Sır sunucuda SAKLANMAZ (yalnızca
// oluşturma anında bir kez döner), yani bu dosya kaybolursa veritabanı bir daha
// açılamaz. Kimlik dosyasıyla aynı muamele: 0600, temp+rename.
const DB_HANDLE_FILE = 'database.json';

function log(logger, level, message) {
  if (logger && typeof logger[level] === 'function') logger[level](message);
  else if (level === 'warn') console.warn(message);
  else console.log(message);
}

/**
 * Diskte saklanan mTLS kimliği. Yeniden başlatmada tekrar enrolment yapmamak
 * için tutulur -- her açılışta enrolment yapmak, tek kullanımlık sırrın tek
 * kullanımlık olmamasını gerektirirdi.
 */
async function loadStoredIdentity(dir) {
  try {
    const raw = await fsp.readFile(path.join(dir, IDENTITY_FILE), 'utf8');
    const stored = JSON.parse(raw);
    if (!stored.certPem || !stored.privateKeyPem) return null;

    // Süresi dolmuş ya da dolmak üzere olan bir sertifikayla bağlanmayı denemek,
    // anlaşılması zor bir TLS hatasıyla sonuçlanır. Burada erken fark edip
    // yeniden enrolment yoluna gitmek daha okunur.
    const cert = new crypto.X509Certificate(stored.certPem);
    const notAfter = new Date(cert.validTo).getTime();
    if (Number.isFinite(notAfter) && notAfter < Date.now() + 60_000) return null;

    return stored;
  } catch (_) {
    return null;
  }
}

async function writeSecretFile(dir, name, payload) {
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, name);
  const tmp = `${file}.tmp`;
  // 0600 ile ve önce geçici dosyaya, sonra rename. Doğrudan yazmak, süreç
  // yazarken ölürse yarım bir dosya bırakır ve sonraki açılış onu "var ama
  // bozuk" olarak bulur.
  await fsp.writeFile(tmp, JSON.stringify(payload, null, 2), { mode: 0o600 });
  await fsp.rename(tmp, file);
}

async function storeIdentity(dir, identity) {
  return writeSecretFile(dir, IDENTITY_FILE, identity);
}

async function storeDbHandle(dir, handleInfo) {
  return writeSecretFile(dir, DB_HANDLE_FILE, handleInfo);
}

async function loadStoredDbHandle(dir) {
  try {
    const stored = JSON.parse(await fsp.readFile(path.join(dir, DB_HANDLE_FILE), 'utf8'));
    if (!stored.dbId || !stored.clientSecret) return null;
    return stored;
  } catch (_) {
    return null;
  }
}

/**
 * Veritabanına bağlanır; gerekiyorsa önce enrolment yaparak mTLS kimliği edinir.
 *
 * @returns {{ handle, identity, db, mode }} `mode`: 'embedded' | 'mtls'
 */
async function connectToDatabase({ config, logger = null }) {
  const dbCfg = config.db;

  // ---- gömülü motor: ağ yok, enrolment yok --------------------------------------------
  if (!dbCfg.remoteTarget) {
    log(logger, 'info', '[bootstrap] Gömülü veritabanı motoru kullanılıyor (ağ yok).');
    const {
      DatabaseManager, ClientSecretKeyProvider, SnowflakeGenerator,
    } = require('@fitfak/database');

    const snowflake = new SnowflakeGenerator({
      workerId: Number(process.env.FITFAK_IDP_SNOWFLAKE_WORKER_ID || 1),
    });
    const manager = new DatabaseManager({ baseDir: config.dataDir, snowflake });
    const keyProvider = new ClientSecretKeyProvider(dbCfg.rootSecret);

    const dbIdFile = path.join(config.dataDir, 'fitfak_idp_db_id.txt');
    const dbId = dbCfg.dbId
      || (fs.existsSync(dbIdFile) ? fs.readFileSync(dbIdFile, 'utf8').trim() : null);

    if (dbId) {
      const db = await manager.openDatabase({
        ownerId: dbCfg.ownerId, dbId, requesterId: dbCfg.ownerId, keyProvider,
      });
      return { handle: null, identity: null, db, manager, mode: 'embedded' };
    }

    const created = await manager.createDatabase({
      ownerId: dbCfg.ownerId, name: 'main', keyProvider,
    });
    await fsp.mkdir(config.dataDir, { recursive: true });
    await fsp.writeFile(dbIdFile, created.dbId);
    log(logger, 'warn', `[bootstrap] Yeni veritabanı oluşturuldu: dbId=${created.dbId}`);
    return { handle: null, identity: null, db: created.db, manager, mode: 'embedded', created: true };
  }

  // ---- uzak veritabanı: TLS -> enrolment -> mTLS ---------------------------------------
  const {
    enroll, resume, connectDatabase, createFitfakSslCsrProvider,
  } = require('@fitfak/database');
  const csrProvider = createFitfakSslCsrProvider();

  const trust = {};
  if (dbCfg.caPath) trust.caPem = await fsp.readFile(dbCfg.caPath, 'utf8');
  else if (dbCfg.caFingerprint) trust.pinnedFingerprints = [dbCfg.caFingerprint];
  else {
    // Buraya düşmek, sunucuyu doğrulamadan enrolment yapmak demektir. config.js
    // üretimde bunu zaten reddediyor; burada da reddediyoruz, çünkü bu modül
    // başka bir yapılandırmayla da çağrılabilir.
    throw new Error(
      '[bootstrap] Veritabanı sunucusunu doğrulayacak bir güven çıpası yok '
      + '(FITFAK_IDP_DB_CA_FINGERPRINT ya da FITFAK_IDP_DB_CA_PATH gerekli).',
    );
  }

  const stored = await loadStoredIdentity(dbCfg.identityDir);

  let identity;
  if (stored) {
    // Zaten bir sertifikamız var: enrolment adımı tamamen atlanır. Yenileme
    // mTLS üzerinden yapılır ve paylaşılan sırra hiç dokunmaz.
    log(logger, 'info', '[bootstrap] Kayıtlı mTLS kimliği bulundu, enrolment atlanıyor.');
    identity = await resume({
      target: dbCfg.remoteTarget,
      certPem: stored.certPem,
      privateKeyPem: stored.privateKeyPem,
      chainPem: stored.chainPem,
      principal: stored.principal,
      roles: stored.roles,
      notAfter: stored.notAfter,
      renewAfter: stored.renewAfter,
      csrProvider,
      logger: { info: (m) => log(logger, 'info', `[bootstrap] ${m}`) },
    });
  } else {
    if (!dbCfg.enrolmentSecret) {
      throw new Error(
        '[bootstrap] mTLS kimliği yok ve FITFAK_IDP_DB_ENROLMENT_SECRET verilmemiş.\n'
        + '  İlk çalıştırmada IdP kendini veritabanına tanıtacak tek kullanımlık bir sırra ihtiyaç duyar.\n'
        + '  Veritabanı tarafında üretin (generateEnrolmentSecret) ve bu değişkende verin.',
      );
    }
    log(logger, 'info', '[bootstrap] mTLS kimliği yok -- enrolment yapılıyor (TLS -> enrol -> mTLS).');

    identity = await enroll({
      target: dbCfg.remoteTarget,
      serviceName: dbCfg.serviceName,
      csrProvider,
      trust,
      bootstrap: { secret: Buffer.from(dbCfg.enrolmentSecret, 'base64') },
      altNames: [dbCfg.serviceName],
      logger: {
        info: (m) => log(logger, 'info', `[bootstrap] ${m}`),
        warn: (m) => log(logger, 'warn', `[bootstrap] ${m}`),
      },
    });

    await storeIdentity(dbCfg.identityDir, {
      certPem: identity.certPem,
      privateKeyPem: identity.privateKeyPem,
      chainPem: identity.chainPem,
      principal: identity.principal,
      roles: identity.roles,
      notAfter: identity.notAfter,
      renewAfter: identity.renewAfter,
    });
    log(logger, 'info', `[bootstrap] Enrolment tamamlandı: principal=${identity.principal}`);
    log(logger, 'warn',
      '[bootstrap] Paylaşılan enrolment sırrı TÜKENDİ. Ortam değişkeninden kaldırabilirsiniz; '
      + 'yenileme artık mTLS üzerinden yapılıyor.');
  }

  // Yenileme ömrün ~2/3'ünde başlar: başarısız olursa tekrar denemek için yer kalır.
  identity.startAutoRenewal();
  identity.on('renewed', async (e) => {
    await storeIdentity(dbCfg.identityDir, {
      certPem: identity.certPem, privateKeyPem: identity.privateKeyPem, chainPem: identity.chainPem,
      principal: identity.principal, roles: identity.roles,
      notAfter: e.notAfter, renewAfter: e.renewAfter,
    });
    log(logger, 'info', `[bootstrap] Sertifika yenilendi, geçerlilik: ${new Date(e.notAfter).toISOString()}`);
  });

  const handle = await connectDatabase({ target: dbCfg.remoteTarget, identity });

  // ---- veritabanı tutamağı -------------------------------------------------
  //
  // `createDatabase` istemci sırrını SUNUCUDA SAKLAMAZ; bir kez döner ve o
  // kadar (bkz. @fitfak/database grpc/client.js). Yani onu kaybeden taraf
  // veriyi de kaybeder.
  //
  // Önceki hâli tam olarak bunu yapıyordu: ilk açılışta oluşturuyor, dönen
  // sırrı kullanıp atıyor, sonraki açılışta `rootSecret` ile açmayı deniyordu.
  // O iki değer aynı değil. Sonuç: sistem BİR KEZ çalışıyor, sonra kendi
  // veritabanını bir daha açamıyordu -- ve bu, enrolment'ın yeniden
  // başlatmada çalıştığını doğrulayan testin bile göremediği bir yerdeydi
  // (test, sırrı bellekte taşıyordu).
  //
  // Sır artık kimlikle aynı muameleyi görüyor: 0600, temp+rename.
  const dbHandleFile = path.join(dbCfg.identityDir, DB_HANDLE_FILE);
  const storedHandle = await loadStoredDbHandle(dbCfg.identityDir);

  let db;
  if (storedHandle) {
    db = await handle.openDatabase({
      dbId: storedHandle.dbId, clientSecret: storedHandle.clientSecret,
    });
    log(logger, 'info', `[bootstrap] Veritabanı açıldı: dbId=${storedHandle.dbId}`);
  } else if (dbCfg.dbId) {
    // Elle taşınan yapılandırma: dbId ortamdan, sır kök sırdan. Sunucu
    // tarafındaki veritabanı bu sırla oluşturulmuşsa çalışır.
    db = await handle.openDatabase({
      dbId: dbCfg.dbId,
      clientSecret: dbCfg.rootSecret.toString('base64'),
    });
    await storeDbHandle(dbCfg.identityDir, {
      dbId: dbCfg.dbId, clientSecret: dbCfg.rootSecret.toString('base64'),
    });
  } else {
    const created = await handle.createDatabase('kimlik');
    // Sır ÖNCE saklanıyor, sonra kullanılıyor: aradaki bir çökme, açılamayan
    // bir veritabanı bırakırdı.
    await storeDbHandle(dbCfg.identityDir, {
      dbId: created.dbId, clientSecret: created.clientSecret,
    });
    log(logger, 'warn',
      `[bootstrap] Yeni veritabanı oluşturuldu: dbId=${created.dbId}\n`
      + `  Erişim sırrı ${dbHandleFile} dosyasında (0600). Bu dosya kaybolursa\n`
      + '  veritabanı bir daha AÇILAMAZ -- yedekleyin.');
    db = await handle.openDatabase({ dbId: created.dbId, clientSecret: created.clientSecret });
  }

  return { handle, identity, db, mode: 'mtls' };
}

module.exports = {
  connectToDatabase, loadStoredIdentity, storeIdentity,
  loadStoredDbHandle, storeDbHandle, DB_HANDLE_FILE,
};
