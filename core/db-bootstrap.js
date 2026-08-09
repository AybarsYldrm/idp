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
// tarafa hiç soru sormadan var olabilmesi gerekir. O uç IdP'nin SERTİFİKA
// OTORİTESİDİR ve bu yüzden YEREL bir depoda durur.
//
//
// NEDEN CA UZAK VERİTABANINDA DEĞİL
//
// Kök ve ara CA'lar `secrets` koleksiyonunda, diskte şifreli olarak duruyor --
// dosyada değil (gerekçe core/ca-vault.js'in başında). Ama o koleksiyon UZAK
// veritabanında olamaz, ve sebebi bir tercih değil bir kilitlenme:
//
//   veritabanı mühürlü açılır ve IdP ona bir sunucu sertifikası verene kadar
//   kimseye hizmet etmez  ->  IdP o sertifikayı üretmek için CA'sına ihtiyaç
//   duyar  ->  CA uzak veritabanındaysa IdP oraya bağlanmak zorundadır  ->
//   ama orası mühürlü.
//
// Her veritabanı yeniden başlatmasında bu kilit yeniden kurulurdu. O yüzden CA,
// IdP'nin YANINDA duran gömülü bir fitdb örneğindedir: aynı şifreleme, aynı
// sürümleme, aynı erişim yolu -- ama ağ yok, dolayısıyla bağımlılık yok.
// Uygulama verisi (kullanıcılar, oturumlar, sertifika kayıtları) uzak
// veritabanında kalır; orası zaten IdP ayağa kalktıktan sonra erişilir.
//
//
// SIRA
//
//   0. yerel CA deposu   IdP kök ve ara CA'larını açar. Ağ yok, kimseye soru yok.
//   1. sunucu kimliği    IdP, VERİTABANI İÇİN bir TLS sunucu sertifikası üretir.
//                        Kendi kimliği için de bir istemci sertifikası üretir --
//                        CA kendisi olduğu için enrolment'a gerek yok.
//   2. denetim düzlemi   Mühürlü veritabanına bağlanır. İki taraf da paylaşılan
//                        denetim sırrıyla kendini kanıtlar (ÇİFT YÖNLÜ: aksi
//                        halde araya giren biri, IdP'nin ürettiği ÖZEL ANAHTARI
//                        teslim alır). Sertifika + anahtar + güven çıpaları
//                        kurulur. Veritabanı artık PROVISIONED ama hâlâ kapalı.
//   3. mTLS              IdP kendi istemci sertifikasıyla geri bağlanır.
//                        Veritabanı bunu görünce AÇILIR.
//   4. kararlı durum     Diğer servisler enrolment ile girer; veritabanı onların
//                        sertifikalarını IdP'nin /pki/ra/issue ucundan ister.
//                        Kendisi hiçbir şey imzalamaz.
//
// Adım 2 ile 3 arasında bir SÜRE SINIRI vardır (veritabanı tarafında hold
// timer). IdP orada takılırsa veritabanı malzemeyi siler ve yeniden mühürlenir.

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
 * IdP'nin sertifika otoritesinin durduğu YEREL gömülü veritabanı.
 *
 * Ayrı bir örnek, uygulama verisinden ayrı bir dizin ve ayrı bir yaşam döngüsü.
 * Dosya başındaki nota bakın: uzak veritabanına koymak, veritabanının her
 * yeniden başlatmasında çözülemeyen bir kilit yaratır.
 *
 * Şifreleme uygulama veritabanıyla AYNI kök sırdan türetiliyor. Ayrı bir sır
 * daha iyi bir yalıtım sağlardı, ama işletme maliyeti de iki katına çıkardı --
 * ve ikisini de kaybetmek aynı sonucu verdiği için kazanç sanıldığı kadar
 * büyük değil.
 */
async function openCaStore({ config, logger = null }) {
  const {
    DatabaseManager, ClientSecretKeyProvider, SnowflakeGenerator,
  } = require('@fitfak/database');

  const baseDir = config.caStoreDir;
  await fsp.mkdir(baseDir, { recursive: true, mode: 0o700 });

  const manager = new DatabaseManager({
    baseDir,
    snowflake: new SnowflakeGenerator({
      workerId: Number(process.env.FITFAK_IDP_SNOWFLAKE_WORKER_ID || 1),
    }),
  });
  const keyProvider = new ClientSecretKeyProvider(config.db.rootSecret);

  const idFile = path.join(baseDir, 'ca-store-db-id.txt');
  const existingId = fs.existsSync(idFile) ? fs.readFileSync(idFile, 'utf8').trim() : null;

  if (existingId) {
    const db = await manager.openDatabase({
      ownerId: 'fitfak-idp-ca', dbId: existingId, requesterId: 'fitfak-idp-ca', keyProvider,
    });
    return { db, manager, created: false };
  }

  const created = await manager.createDatabase({ ownerId: 'fitfak-idp-ca', name: 'ca', keyProvider });
  // Kimlik ÖNCE yazılıyor: aradaki bir çökme, bir daha açılamayan bir CA deposu
  // bırakırdı ve o depoda kök anahtar var.
  await fsp.writeFile(idFile, created.dbId, { mode: 0o600 });
  log(logger, 'warn', `[bootstrap] Yeni CA deposu oluşturuldu: ${baseDir} (dbId=${created.dbId})`);
  return { db: created.db, manager, created: true };
}

/**
 * Mühürlü veritabanına sunucu kimliğini kurar ve IdP'nin kendi istemci
 * sertifikasını üretir.
 *
 * İkisi de IdP'nin KENDİ kökünden çıkar ve ikisi de her açılışta yeniden
 * üretilir. Veritabanının sunucu anahtarı hiçbir yerde diske yazılmaz -- ne
 * veritabanında, ne burada. Yeniden başlatma, bir dakikalık bir devirle
 * çözülür; bir dosyada duran anahtar ise kalıcı bir sorumluluktur.
 *
 * @returns {{ clientCertPem, clientKeyPem, chainPem, spiffeId }}
 */
async function provisionDatabase({ config, pkiIssuer, logger = null }) {
  const { provisionServerIdentity, createFitfakSslCsrProvider } = require('@fitfak/database');
  const spiffe = require('./spiffe');
  const dbCfg = config.db;

  const csrProvider = createFitfakSslCsrProvider();
  const anchors = await pkiIssuer.getTrustAnchorsPem();

  // ---- 1. veritabanının sunucu sertifikası --------------------------------------------
  const serverNames = dbCfg.serverNames;
  const serverKey = await csrProvider.generateKeyPair();
  const serverCsr = await csrProvider.createCsr({
    keyPair: serverKey,
    subject: { CN: serverNames[0] },
    altNames: serverNames,
  });
  const serverCert = await pkiIssuer.signCertificateFromCsr({
    csrPem: serverCsr,
    profile: 'server-auth',
    subjectOverride: { cn: serverNames[0], sans: serverNames.map((value) => ({ type: inferSanType(value), value })) },
  });

  // ---- 2. IdP'nin kendi istemci sertifikası --------------------------------------------
  //
  // Enrolment YOK. Enrolment, CA'ya erişimi olmayan bir servisin sertifika alma
  // yoludur; IdP'nin CA'ya erişimi var, çünkü CA odur. Kendine enrolment
  // yaptırmak, ürettiği sertifikayı kendisinden istemek olurdu.
  const idpSpiffeId = spiffe.identities.service('idp');
  const clientKey = await csrProvider.generateKeyPair();
  const clientCsr = await csrProvider.createCsr({
    keyPair: clientKey,
    subject: { CN: dbCfg.serviceName },
    altNames: [idpSpiffeId.uri, dbCfg.serviceName],
  });
  const clientCert = await pkiIssuer.signCertificateFromCsr({
    csrPem: clientCsr,
    profile: 'service-identity',
    subjectOverride: { cn: dbCfg.serviceName },
    spiffeId: idpSpiffeId.uri,
    // Servis kimliği saatlerle ölçülür, dakikalarla değil: IdP kendi
    // sertifikasını yenilerken bir hata olursa geri dönmek için zamana ihtiyacı
    // var, ve beş dakika tek bir yavaş adımı kesintiye çevirir.
    validitySeconds: dbCfg.identityValiditySeconds,
  });

  // ---- 3. devir ------------------------------------------------------------------------
  const result = await provisionServerIdentity({
    target: dbCfg.remoteTarget,
    bootstrapSecret: dbCfg.controlSecret,
    serverIdentity: {
      certPem: serverCert.leafPem,
      privateKeyPem: serverKey.privateKeyPem,
      chainPem: splitPemChain(serverCert.chainPem),
    },
    // Veritabanı bundan sonra İSTEMCİ sertifikalarını bunlarla doğrulayacak.
    // Yerel yapılandırmadan değil buradan gelmesi kasıtlı: "kimin
    // sertifikalarına inanıyorum" ile "kimlik sağlayıcım kim" aynı sorudur ve
    // tek bir cevabı olmalıdır.
    trustAnchorsPem: anchors,
    controlSpiffeId: idpSpiffeId.uri,
    pinnedFingerprints: dbCfg.bootstrapFingerprints,
    logger: { info: (m) => log(logger, 'info', `[bootstrap] ${m}`) },
  });

  if (result.alreadyOpen) {
    log(logger, 'info', '[bootstrap] Veritabanı zaten açık; sunucu kimliği yeniden kurulmadı.');
  } else {
    log(logger, 'info',
      `[bootstrap] Veritabanının sunucu kimliği kuruldu. Veritabanı ${new Date(result.holdExpiresAt).toISOString()} `
      + 'tarihine kadar bekliyor; mTLS bağlantısı tamamlanmazsa kendini yeniden mühürleyecek.');
  }

  return {
    clientCertPem: clientCert.leafPem,
    clientKeyPem: clientKey.privateKeyPem,
    chainPem: splitPemChain(clientCert.chainPem),
    spiffeId: idpSpiffeId.uri,
    notAfter: clientCert.notAfter.getTime(),
  };
}

function splitPemChain(pem) {
  const matches = String(pem || '').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return matches ? matches.map((m) => `${m}\n`) : [];
}

function inferSanType(value) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return 'ip';
  if (value.includes('://')) return 'uri';
  return 'dns';
}

/**
 * Veritabanına bağlanır; uzak modda önce onu sağlar (provision), sonra kendi
 * sertifikasıyla mTLS'e geçer.
 *
 * @returns {{ handle, identity, db, mode }} `mode`: 'embedded' | 'mtls'
 */
async function connectToDatabase({ config, pkiIssuer = null, logger = null }) {
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

  // ---- uzak veritabanı: sağla (provision) -> mTLS --------------------------------------
  //
  // Enrolment BURADA YOK ve olmaması doğru. Enrolment, CA'ya erişimi olmayan bir
  // servisin sertifika alma yoludur. IdP'nin CA'ya erişimi vardır -- CA odur --
  // ve kendine enrolment yaptırması, ürettiği sertifikayı kendisinden istemesi
  // olurdu. Diğer her servis enrolment kullanır; IdP kullanamaz.
  if (!pkiIssuer) {
    throw new Error(
      '[bootstrap] Uzak veritabanı modunda bir pkiIssuer gerekli.\n'
      + '  Veritabanı mühürlü açılır ve sunucu sertifikasını IdP\'den bekler; onu üretecek\n'
      + '  olan da IdP\'nin sertifika otoritesidir.',
    );
  }
  if (!dbCfg.controlSecret) {
    throw new Error(
      '[bootstrap] FITFAK_IDP_DB_CONTROL_SECRET verilmemiş.\n'
      + '  Veritabanının sunucu kimliğini kurmak için gereken denetim düzlemi sırrı bu;\n'
      + '  db-server.js açılışta yazdırır. Enrolment sırrından AYRIDIR: bu sır veritabanının\n'
      + '  sunucu anahtarını değiştirme yetkisidir, bir istemci sertifikası alma yetkisi değil.',
    );
  }

  const { resume, connectDatabase, createFitfakSslCsrProvider } = require('@fitfak/database');
  const csrProvider = createFitfakSslCsrProvider();

  const provisioned = await provisionDatabase({ config, pkiIssuer, logger });

  // Kendi sertifikamızla geri bağlan. Veritabanı için ASIL OLAY budur: mühürlü
  // durumdan çıkıp herkese açılması, bu bağlantının başarılı olmasına bağlı.
  const identity = await resume({
    target: dbCfg.remoteTarget,
    certPem: provisioned.clientCertPem,
    privateKeyPem: provisioned.clientKeyPem,
    chainPem: provisioned.chainPem,
    principal: dbCfg.serviceName,
    roles: ['admin'],
    notAfter: provisioned.notAfter,
    csrProvider,
    logger: { info: (m) => log(logger, 'info', `[bootstrap] ${m}`) },
  });

  log(logger, 'info',
    `[bootstrap] mTLS bağlantısı kuruldu (${provisioned.spiffeId}). Veritabanı artık açık.`);

  // Yenileme, sertifikayı YENİDEN ÜRETEREK yapılıyor -- enrolment ile değil.
  // Aynı sebeple: yenileme de bir sertifika talebidir ve talebin muhatabı biziz.
  //
  // Veritabanının sunucu sertifikası da aynı anda yenilenmeli, yoksa saatler
  // sonra IdP'nin sertifikası tazeyken veritabanınınki ölür ve bağlantı
  // anlaşılması zor bir TLS hatasıyla düşer.
  const renewEveryMs = Math.floor((dbCfg.identityValiditySeconds * 1000) / 2);
  const renewalTimer = setInterval(async () => {
    try {
      const renewed = await provisionDatabase({ config, pkiIssuer, logger });
      await identity.client.upgrade({
        key: renewed.clientKeyPem,
        cert: [renewed.clientCertPem, ...renewed.chainPem.slice(0, -1)].join(''),
        ca: renewed.chainPem.join(''),
        rejectUnauthorized: true,
      });
      log(logger, 'info', '[bootstrap] Kimlik yenilendi (veritabanı sunucu sertifikası dahil).');
    } catch (err) {
      // Yenileme başarısızlığı MEVCUT sertifikayı bozmaz: eldeki hâlâ geçerli
      // ve bir sonraki turda tekrar denenecek. Bu yüzden hata bir uyarıdır,
      // bir çökme değil.
      log(logger, 'warn', `[bootstrap] Kimlik yenilenemedi, mevcut sertifika ile devam ediliyor: ${err.message}`);
    }
  }, renewEveryMs);
  // Yenileme zamanlayıcısı sürecin ayakta kalma sebebi olmamalı.
  if (typeof renewalTimer.unref === 'function') renewalTimer.unref();
  identity.on('closed', () => clearInterval(renewalTimer));

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
  connectToDatabase, openCaStore, provisionDatabase,
  loadStoredIdentity, storeIdentity,
  loadStoredDbHandle, storeDbHandle, DB_HANDLE_FILE,
};
