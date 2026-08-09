'use strict';

const crypto = require('node:crypto');
const workload = require('../services/workload-identity-service');
const spiffe = require('../core/spiffe');
const { createMockDb } = require('./mock-db');

// Kısa ömürlü kimliğin gerçekten kısa ömürlü olmasını sağlayan şeyler.
//
// Kısa ömürlü sertifika üretmek kolay: notAfter'ı beş dakika sonrasına koy, bitti.
// Zor olan, o beş dakikanın bir ANLAM taşıması. Anlamı taşıyan üç şey var ve
// üçü de burada sınanıyor:
//
//   1. HER YENİLEMEDE YETKİ YENİDEN DOĞRULANIR. Yenilemeyi "aynı şeyi bir kez
//      daha imzala" olarak ele almak, sertifikayı kısa ömürlü ama ardındaki
//      kararı bir yıllık yapar. Oturum iptal edildiğinde, hesap kapatıldığında,
//      cihaz kaydı silindiğinde YENİLEME DURMALI -- iptal etmeye gerek
//      kalmadan, dakikalar içinde.
//
//   2. HER ÜRETİMDE YENİ ANAHTAR. Aynı anahtarı yeniden sertifikalandırmak, o
//      anahtar bir kez sızdıysa sızıntıyı bir ömür daha taşımaktır -- yani kısa
//      ömürlülüğün tek faydasını ortadan kaldırır.
//
//   3. KAYIT TABLOSU SINIRSIZ BÜYÜMEZ. İki buçuk dakikada bir yenilenen bir
//      filoda, her üretimi süresiz saklamak tabloyu günde binlerce satır
//      büyütür. Tekillik kontrolünün anlamlı olduğu pencere, sertifikanın CANLI
//      olduğu penceredir.
//
// @fitfak/ssl kurulu olmadığı için imzalayıcı yerine bir sahte kullanılıyor:
// burada sınanan şey imza değil, imzalamanın ETRAFINDAKİ karar.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

async function rejectsWith(label, code, fn) {
  let got = null;
  try { await fn(); } catch (err) { got = err.code || err.message; }
  check(`${label} (${got})`, got === code);
}

const CSR = '-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----';

/** Her çağrıda farklı bir SKID üreten sahte imzalayıcı. */
function makeIssuer({ fixedSkid = null } = {}) {
  const issued = [];
  return {
    issued,
    async signCertificateFromCsr({ profile, spiffeId, validitySeconds }) {
      const seconds = validitySeconds || 300;
      const notBefore = new Date(Date.now() - 60_000);
      const notAfter = new Date(Date.now() + seconds * 1000);
      const record = {
        certPem: '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n',
        leafPem: '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n',
        chainPem: '-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n',
        serialNumberHex: crypto.randomBytes(8).toString('hex'),
        skidHex: fixedSkid || crypto.randomBytes(20).toString('hex'),
        spiffeId,
        profile,
        shortLived: true,
        notBefore,
        notAfter,
      };
      issued.push(record);
      return record;
    },
  };
}

function makeWorld({ sessionRevoked = false, userStatus = 'active', deviceEnrolled = true } = {}) {
  const db = createMockDb(['users', 'user_devices', 'workload_certificates']);
  const world = { db, userStatus, deviceEnrolled, userId: null };
  world.sessionManager = {
    store: {
      async getSessionById(sessionId) {
        if (sessionId !== 'sess-1') return null;
        // `userId` seed() tarafından dolduruluyor: koleksiyon kendi kimliğini
        // üretiyor ve oturumun ona işaret etmesi gerekiyor.
        return { sessionId: 'sess-1', userId: world.userId, revoked: sessionRevoked };
      },
    },
  };
  return world;
}

async function seed(world) {
  // `_id` GEÇİLMİYOR: koleksiyon onu kendisi üretir ve dışarıdan verilen bir
  // değer, kaydın anahtarıyla içeriğinin ayrışmasına yol açar.
  const userId = await world.db.collection('users').insert({
    username: 'aybars', status: world.userStatus,
  });
  world.userId = userId;
  if (world.deviceEnrolled) {
    await world.db.collection('user_devices').insert({
      userDeviceKey: `${userId}:dev-1`, userId, deviceId: 'dev-1',
    });
  }
  return userId;
}

async function main() {
  console.log('\n1. Üretim: kısa ömür, SPIFFE kimliği, yenileme zamanı');

  {
    const world = makeWorld();
    const userId = await seed(world);
    const pkiIssuer = makeIssuer();

    const result = await workload.issueShortLivedCertificate({
      db: world.db,
      pkiIssuer,
      sessionManager: world.sessionManager,
      profile: 'session',
      csrPem: CSR,
      spiffeId: spiffe.identities.session('sess-1').uri,
      binding: { userId, sessionId: 'sess-1', deviceId: 'dev-1' },
      issuedVia: 'session',
    });

    check('kimlik SPIFFE URI olarak dönüyor', result.spiffeId === `spiffe://${spiffe.TRUST_DOMAIN}/session/sess-1`);
    const lifetimeMs = new Date(result.notAfter) - new Date(result.notBefore);
    check('ömür beş dakika + geri tarihleme', lifetimeMs === (300 + 60) * 1000);

    // Ömrün YARISI, üçte ikisi değil: beş dakikalık bir sertifikada üçte iki,
    // yeniden denemek için 100 saniye bırakır ve o pencereye sığan tek bir
    // yavaş CA turu bir kesintidir.
    const renewOffset = new Date(result.renewAfter) - new Date(result.notBefore);
    check('yenileme ömrün yarısında', renewOffset === Math.floor(lifetimeMs / 2));

    check('üretim kaydedildi', (await world.db.collection('workload_certificates').find('spiffeId', result.spiffeId)).length === 1);
  }

  console.log('\n2. Sürekli doğrulama: yetki düşünce yenileme durur');

  {
    // Oturum iptal edildi. Sertifikayı İPTAL ETMEYE gerek yok -- yenilenmemesi
    // yeterli ve dakikalar içinde etkili.
    const world = makeWorld({ sessionRevoked: true });
    const userId = await seed(world);
    await rejectsWith('iptal edilmiş oturum için üretim reddedilir', 'session_revoked',
      () => workload.issueShortLivedCertificate({
        db: world.db, pkiIssuer: makeIssuer(), sessionManager: world.sessionManager,
        profile: 'session', csrPem: CSR,
        spiffeId: spiffe.identities.session('sess-1').uri,
        binding: { userId, sessionId: 'sess-1' },
      }));
  }

  {
    const world = makeWorld({ userStatus: 'suspended' });
    const userId = await seed(world);
    await rejectsWith('askıya alınmış hesap için üretim reddedilir', 'account_not_active',
      () => workload.issueShortLivedCertificate({
        db: world.db, pkiIssuer: makeIssuer(), sessionManager: world.sessionManager,
        profile: 'session', csrPem: CSR,
        spiffeId: spiffe.identities.session('sess-1').uri,
        binding: { userId, sessionId: 'sess-1' },
      }));
  }

  {
    // Kullanıcı profilinden "bu cihazı çıkar" dedi.
    const world = makeWorld({ deviceEnrolled: false });
    const userId = await seed(world);
    await rejectsWith('kaydı silinmiş cihaz için üretim reddedilir', 'device_unenrolled',
      () => workload.issueShortLivedCertificate({
        db: world.db, pkiIssuer: makeIssuer(), sessionManager: world.sessionManager,
        profile: 'device', csrPem: CSR,
        spiffeId: spiffe.identities.device('dev-1').uri,
        binding: { userId, sessionId: 'sess-1', deviceId: 'dev-1' },
      }));
  }

  console.log('\n3. Anahtar yeniden kullanımı reddediliyor');

  {
    const world = makeWorld();
    const userId = await seed(world);
    // Aynı SKID: istemci yeni anahtar üretmeyi atlamış.
    const pkiIssuer = makeIssuer({ fixedSkid: 'a'.repeat(40) });
    const args = {
      db: world.db, pkiIssuer, sessionManager: world.sessionManager,
      profile: 'session', csrPem: CSR,
      spiffeId: spiffe.identities.session('sess-1').uri,
      binding: { userId, sessionId: 'sess-1' },
    };

    await workload.issueShortLivedCertificate(args);
    check('ilk üretim geçiyor', true);
    await rejectsWith('AYNI anahtarla ikinci üretim reddedilir', 'key_reuse',
      () => workload.issueShortLivedCertificate(args));

    // Farklı anahtar sorunsuz.
    await workload.issueShortLivedCertificate({ ...args, pkiIssuer: makeIssuer() });
    check('farklı anahtarla üretim geçiyor', true);
  }

  console.log('\n4. Geçersiz profiller');

  {
    const world = makeWorld();
    await rejectsWith('uzun ömürlü bir profil bu yoldan üretilemez', 'not_short_lived',
      () => workload.issueShortLivedCertificate({
        db: world.db, pkiIssuer: makeIssuer(), sessionManager: world.sessionManager,
        profile: 'smime', csrPem: CSR, spiffeId: spiffe.identities.session('s').uri,
      }));

    await rejectsWith('bozuk CSR reddedilir', 'invalid_csr',
      () => workload.issueShortLivedCertificate({
        db: world.db, pkiIssuer: makeIssuer(), sessionManager: world.sessionManager,
        profile: 'session', csrPem: 'bu bir CSR değil',
        spiffeId: spiffe.identities.session('s').uri,
      }));
  }

  console.log('\n5. Kayıt tablosu sınırsız büyümüyor');

  {
    const world = makeWorld();
    const certs = world.db.collection('workload_certificates');
    const now = Date.now();

    // Biri dün süresi dolmuş, biri hâlâ canlı.
    await certs.insert({
      skidHex: 'old', spiffeId: 'spiffe://fitfak.net/session/old', sessionId: 'sess-1',
      notAfter: BigInt(now - 2 * 24 * 60 * 60 * 1000), status: 'valid',
    });
    await certs.insert({
      skidHex: 'live', spiffeId: 'spiffe://fitfak.net/session/live', sessionId: 'sess-1',
      notAfter: BigInt(now + 300_000), status: 'valid',
    });

    const swept = await workload.sweepExpired(world.db, { force: true });
    check('süresi dolmuş kayıt süpürüldü', swept.swept === 1);
    check('canlı kayıt duruyor', certs._debugAll().length === 1);
    check('duran kayıt canlı olan', certs._debugAll()[0].skidHex === 'live');

    const live = await workload.listForSession({ db: world.db, sessionId: 'sess-1' });
    check('oturumun canlı kimlikleri listelenebiliyor', live.length === 1);
  }

  console.log('\n6. İş yükü kimliği: isim jetondan DEĞİL yapılandırmadan gelir');

  {
    const world = makeWorld();
    await seed(world);
    const registry = { 'dns-resolver': { requiredScope: 'identity:workload', profile: 'workload' } };

    await rejectsWith('geçersiz jeton reddedilir', 'invalid_token',
      () => workload.issueForWorkload({
        db: world.db, pkiIssuer: makeIssuer(), sessionManager: world.sessionManager,
        introspection: { active: false }, workloadName: 'dns-resolver',
        csrPem: CSR, workloadRegistry: registry,
      }));

    // Geçerli bir jeton, ama gerekli kapsam yok. Her giriş yapmış kullanıcı
    // geçerli bir jeton taşır; yalnızca kapsamı olan bir jeton iş yükü kimliği
    // alabilir.
    await rejectsWith('kapsamı olmayan jeton reddedilir', 'workload_not_authorised',
      () => workload.issueForWorkload({
        db: world.db, pkiIssuer: makeIssuer(), sessionManager: world.sessionManager,
        introspection: { active: true, scope: 'openid profile' }, workloadName: 'dns-resolver',
        csrPem: CSR, workloadRegistry: registry,
      }));

    // Kayıtlı olmayan bir isim: jeton mükemmel olsa da olmaz. Aksi halde keyfi
    // bir `sub` üretebilen herkes sistemdeki herhangi bir kimliğe bürünürdü.
    await rejectsWith('kayıtlı olmayan iş yükü adı reddedilir', 'workload_not_authorised',
      () => workload.issueForWorkload({
        db: world.db, pkiIssuer: makeIssuer(), sessionManager: world.sessionManager,
        introspection: { active: true, scope: 'identity:workload' }, workloadName: 'idp-service',
        csrPem: CSR, workloadRegistry: registry,
      }));

    const ok = await workload.issueForWorkload({
      db: world.db, pkiIssuer: makeIssuer(), sessionManager: world.sessionManager,
      introspection: { active: true, scope: 'identity:workload', sub: 'svc' },
      workloadName: 'dns-resolver', csrPem: CSR, workloadRegistry: registry,
    });
    check('yetkili jeton iş yükü kimliği alıyor',
      ok.spiffeId === `spiffe://${spiffe.TRUST_DOMAIN}/workload/dns-resolver`);
  }

  console.log(`\nOK - kısa ömürlü kimlikler: ${checks} kontrol geçti.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message, err.stack); process.exit(1); },
);
