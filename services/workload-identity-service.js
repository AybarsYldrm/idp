'use strict';

const { AppError } = require('../core/errors');
const spiffe = require('../core/spiffe');
// Profil tablosundan geliyor, imzalayıcıdan değil: bu servisin PKI
// kütüphanesine ihtiyacı yok, yalnızca "bu profil kısa ömürlü mü" sorusunun
// cevabına var. core/pki-issuer.js açılışta @fitfak/ssl'i yüklüyor ve buradan
// require etmek, o soruyu sormanın bedelini tüm kripto yığınına çıkarırdı.
const { PROFILE_MAP, shortLivedProfiles } = require('../core/certificate-profiles');

// ============================================================================
// KISA ÖMÜRLÜ KİMLİK ÜRETİMİ -- Google BeyondCorp modeli
// ============================================================================
//
// Buradaki temel fikir tek cümlede: SERTİFİKA BİR KİMLİK DEĞİL, DOĞRULANMIŞ BİR
// OTURUMUN GEÇİCİ BİR YETKİSİDİR.
//
// Klasik PKI'da sertifika kimliğin KENDİSİDİR: bir yıl yaşar, kimlik bilgisi
// olarak dolaşır ve yanlış ellere geçtiğinde onu durdurmanın tek yolu iptaldir.
// İptalin çalışması için de doğrulayıcının CRL'i indirmiş ya da OCSP'ye
// ulaşabiliyor olması gerekir -- yani iptal, ağın ve önbelleklerin izin verdiği
// hızda yayılır. Pratikte bu saatlerdir.
//
// BeyondCorp bunu tersine çevirir. Sertifika, kimliğin kanıtlandığı ANDA üretilir
// ve dakikalar sonra kendiliğinden ölür. Bir kimlik bilgisinin çalınması hâlâ
// kötüdür, ama çalanın elindeki şey beş dakika sonra hiçbir şeydir. İptal
// mekanizması artık "CRL yayılsın" değil, "YENİLEME" -- ve yenilemeyi reddetmek
// anında etkilidir, çünkü karar üretim anında, tek bir yerde verilir.
//
// Bunun getirdiği yükümlülük şudur: HER YENİLEMEDE YETKİ YENİDEN DOĞRULANIR.
// Yenilemeyi "aynı şeyi bir kez daha imzala" olarak ele almak, kısa ömürlülüğün
// tek faydasını yok eder -- sertifika kısa yaşar ama ardındaki karar bir yıl
// önce verilmiş olur. NIST SP 800-207'nin "sürekli doğrulama" (continuous
// verification) ilkesi tam olarak budur ve aşağıdaki `assertStillAuthorised`
// onun uygulandığı yerdir.
//
//
// NEDEN HER SEFERİNDE YENİ ANAHTAR
//
// İstemci her üretimde yeni bir anahtar çifti üretir ve yeni bir CSR gönderir.
// Aynı anahtarı yeniden sertifikalandırmak, o anahtar bir kez sızdıysa sızıntıyı
// bir ömür daha taşımak demektir -- ve kısa ömürlü sertifikaların bütün amacı,
// bir sızıntının ömrünün sınırlı olması. Aşağıdaki tekillik kontrolü bunu
// zorlar: CANLI bir sertifikası olan bir açık anahtar ikinci kez
// sertifikalandırılamaz.
//
// Kontrolün "canlı" ile sınırlı olması bilinçli: süresi üç gün önce dolmuş bir
// sertifikanın anahtarının yeniden kullanılması kötü bir alışkanlıktır ama bir
// güvenlik sınırı değildir -- o sertifika zaten ölü. Kaydı süresiz tutmak ise,
// iki buçuk dakikada bir yenilenen bir filoda sınırsız büyüyen bir tablo demek.

// Kısa ömürlü kayıtların ne kadar süre tutulacağı.
//
// Sertifikanın süresi dolduktan sonra da bir süre saklanır: bir olay incelemesi
// "beş dakika önce hangi kimlik neye bağlandı" sorusunu sorabilmeli, ve o soru
// sertifikanın süresi dolduğu anda anlamsızlaşmaz. Bir gün, hem o soruyu
// cevaplamaya yeter hem de tabloyu sınırlı tutar.
const RECORD_RETENTION_MS = 24 * 60 * 60 * 1000;

// Süresi dolmuş kayıtların süpürülme sıklığı. Her üretimde süpürmek, üretimi
// tablonun büyüklüğüne bağlı hâle getirirdi; hiç süpürmemek tabloyu sınırsız
// büyütürdü.
const SWEEP_INTERVAL_MS = 5 * 60 * 1000;
let lastSweepAt = 0;

function isWellFormedCsrPem(csrPem) {
  return typeof csrPem === 'string'
    && csrPem.includes('-----BEGIN CERTIFICATE REQUEST-----')
    && csrPem.includes('-----END CERTIFICATE REQUEST-----');
}

function shortLivedProfile(profile) {
  const mapping = PROFILE_MAP[profile];
  if (!mapping || !mapping.shortLived) {
    throw new AppError('not_short_lived',
      `'${profile}' kısa ömürlü bir profil değil. Kısa ömürlüler: ${shortLivedProfiles().join(', ')}`,
      { httpStatus: 400 });
  }
  return mapping;
}

// ============================================================================
// SÜREKLİ DOĞRULAMA
// ----------------------------------------------------------------------------
// Her üretimde -- ilkinde de, yenilemede de -- yeniden sorulan sorular.
// Yenilemenin ilk üretimden DAHA AZ kontrol içermesi, kısa ömürlülüğün
// faydasını sessizce ortadan kaldırırdı: sertifika beş dakikada bir tazelenir
// ama ardındaki yetki hiç yeniden bakılmaz.
// ============================================================================
async function assertStillAuthorised({ db, sessionManager, binding }) {
  const { userId, sessionId, deviceId } = binding;

  if (sessionId) {
    const session = await sessionManager.store.getSessionById(sessionId);
    if (!session || session.revoked) {
      throw new AppError('session_revoked',
        'Bu sertifikanın dayandığı oturum artık geçerli değil. Yeniden giriş yapın.',
        { httpStatus: 401 });
    }
    // Oturum başka bir kullanıcıya devredilmiş olamaz, ama bunu kontrol etmemek
    // bir gün devredilebilir hâle geldiğinde sessizce yanlış olurdu.
    if (userId && session.userId !== userId) {
      throw new AppError('session_mismatch', 'Oturum bu kimliğe ait değil', { httpStatus: 403 });
    }
  }

  if (userId) {
    const user = await db.collection('users').get(userId);
    if (!user) throw new AppError('user_not_found', 'Kullanıcı bulunamadı', { httpStatus: 404 });
    if (user.status && user.status !== 'active') {
      throw new AppError('account_not_active',
        'Hesap etkin değil; kısa ömürlü kimlik yenilenmeyecek', { httpStatus: 403 });
    }
  }

  if (deviceId && userId) {
    const devices = db.collection('user_devices');
    const device = await devices.findOne('userDeviceKey', `${userId}:${deviceId}`);
    if (!device) {
      // Cihaz kaydı silinmiş: kullanıcı "bu cihazı çıkar" dedi. Sertifikayı
      // iptal etmeye gerek yok -- yenilenmemesi yeterli ve dakikalar içinde
      // etkili.
      throw new AppError('device_unenrolled',
        'Bu cihazın kaydı kaldırılmış; kimlik yenilenmeyecek', { httpStatus: 403 });
    }
  }
}

// ============================================================================
// ÜRETİM
// ============================================================================

/**
 * Kısa ömürlü bir sertifika üretir ve kaydeder.
 *
 * @param {object} opts
 * @param {object} opts.db
 * @param {object} opts.pkiIssuer
 * @param {object} opts.sessionManager
 * @param {string} opts.profile          'workload' | 'session' | 'device' | 'service-identity'
 * @param {string} opts.csrPem
 * @param {string} opts.spiffeId         kimlik -- ÇAĞIRANIN İSTEDİĞİ değil, doğrulanan
 * @param {object} opts.binding          { userId, sessionId, deviceId, workloadName }
 * @param {string} opts.issuedVia        denetim izi: hangi yolla yetkilendirildi
 * @param {number}[opts.validitySeconds] profilin varsayılanını DARALTIR
 */
async function issueShortLivedCertificate({
  db, pkiIssuer, sessionManager, profile, csrPem, spiffeId,
  binding = {}, issuedVia = 'unknown', validitySeconds = null, subjectCn = null,
}) {
  shortLivedProfile(profile);

  if (!isWellFormedCsrPem(csrPem)) {
    throw new AppError('invalid_csr', 'Geçersiz CSR biçimi (PEM bekleniyor)', { httpStatus: 400 });
  }

  // Yetki, İMZADAN ÖNCE doğrulanır. Sonra doğrulamak, reddedilmiş bir istek için
  // imzalanmış ama teslim edilmemiş bir sertifika bırakırdı.
  await assertStillAuthorised({ db, sessionManager, binding });

  const parsedId = spiffe.parse(spiffeId);

  const issued = await pkiIssuer.signCertificateFromCsr({
    csrPem,
    profile,
    subjectOverride: { cn: subjectCn || parsedId.segments.join('/') },
    spiffeId: parsedId.uri,
    validitySeconds,
  });

  await recordIssuance({ db, issued, parsedId, binding, issuedVia });

  return {
    certPem: issued.certPem,
    chainPem: issued.chainPem,
    spiffeId: issued.spiffeId,
    serialNumberHex: issued.serialNumberHex,
    profile,
    notBefore: issued.notBefore.toISOString(),
    notAfter: issued.notAfter.toISOString(),
    // İstemcinin ne zaman geri gelmesi gerektiği. Ömrün YARISI, üçte ikisi değil:
    // beş dakikalık bir sertifikada üçte iki, yeniden denemek için 100 saniye
    // bırakır ve o pencereye sığan tek bir yavaş CA turu bir kesintidir.
    renewAfter: new Date(
      issued.notBefore.getTime()
      + Math.floor((issued.notAfter.getTime() - issued.notBefore.getTime()) / 2),
    ).toISOString(),
  };
}

async function recordIssuance({ db, issued, parsedId, binding, issuedVia }) {
  const certs = db.collection('workload_certificates');
  await sweepExpired(db).catch(() => {});

  try {
    await certs.insertUnique({
      serialNumberHex: issued.serialNumberHex,
      skidHex: issued.skidHex,
      spiffeId: parsedId.uri,
      profile: issued.profile,
      userId: binding.userId || '',
      sessionId: binding.sessionId || '',
      deviceId: binding.deviceId || '',
      workloadName: binding.workloadName || '',
      tokenSubject: binding.tokenSubject || '',
      issuedVia,
      notBefore: BigInt(issued.notBefore.getTime()),
      notAfter: BigInt(issued.notAfter.getTime()),
      createdAt: BigInt(Date.now()),
      status: 'valid',
    }, { unique: ['skidHex'] });
  } catch (err) {
    if (err.code === 'UNIQUE_CONSTRAINT' || err.code === 'ALREADY_EXISTS' || /already exists/i.test(err.message || '')) {
      // Aynı açık anahtar için hâlâ canlı bir sertifika var. İstemci yeni bir
      // anahtar üretmeyi atlamış demektir; bunu sessizce kabul etmek, sızmış bir
      // anahtarın ömrünü uzatmanın en kolay yolunu açık bırakır.
      throw new AppError('key_reuse',
        'Bu açık anahtar için hâlâ geçerli bir sertifika var. Kısa ömürlü kimlikte HER '
        + 'üretim yeni bir anahtar çifti gerektirir -- yeni bir anahtar üretip yeni bir CSR gönderin.',
        { httpStatus: 409 });
    }
    throw err;
  }
}

/**
 * Süresi dolmuş kayıtları temizler.
 *
 * Tekillik kontrolünün anlamlı kaldığı pencere, sertifikanın canlı olduğu
 * penceredir; ondan sonrasını tutmak yalnızca denetim içindir ve o da sınırsız
 * olmamalı. Süpürme fırsatçı: hata verirse üretim durmaz (çağıran `.catch`
 * ediyor), çünkü bir bakım işinin başarısızlığı bir kimlik doğrulamasını
 * düşürmemeli.
 */
async function sweepExpired(db, { now = Date.now(), force = false } = {}) {
  if (!force && now - lastSweepAt < SWEEP_INTERVAL_MS) return { swept: 0, skipped: true };
  lastSweepAt = now;

  const certs = db.collection('workload_certificates');
  const cutoff = now - RECORD_RETENTION_MS;
  const stale = await certs.findRange('notAfter', 1, cutoff);
  let swept = 0;
  for (const row of stale) {
    await certs.delete(row._id);
    swept += 1;
  }
  return { swept, skipped: false };
}

// ============================================================================
// YETKİLENDİRME ÖN YÜZLERİ
// ----------------------------------------------------------------------------
// Her biri "bu çağıran kim" sorusunu farklı bir kanıtla cevaplar ve hepsi aynı
// üretim yoluna çıkar. Kimliğin ÇAĞIRAN tarafından seçilemiyor olması bunların
// ortak özelliği: SPIFFE kimliği her durumda doğrulanmış bağlamdan TÜRETİLİR,
// istekten okunmaz.
// ============================================================================

/**
 * Tarayıcıda oturum açmış bir kullanıcı için oturum kimliği.
 *
 * Kimlik `spiffe://<alan>/session/<sessionId>` -- kullanıcı kimliği DEĞİL.
 * Fark önemli: sertifika kullanıcının kendisini değil, o kullanıcının BU
 * oturumunu temsil eder; oturum iptal edildiğinde sertifika yenilenmez ve
 * kullanıcının diğer oturumları etkilenmez.
 */
async function issueForSession({
  db, pkiIssuer, sessionManager, session, csrPem, validitySeconds = null,
}) {
  if (!session || session.revoked) {
    throw new AppError('unauthenticated', 'Oturum gerekli', { httpStatus: 401 });
  }
  const user = await db.collection('users').get(session.userId);
  if (!user) throw new AppError('user_not_found', 'Kullanıcı bulunamadı', { httpStatus: 404 });

  return issueShortLivedCertificate({
    db,
    pkiIssuer,
    sessionManager,
    profile: 'session',
    csrPem,
    spiffeId: spiffe.identities.session(session.sessionId).uri,
    subjectCn: user.username,
    binding: { userId: session.userId, sessionId: session.sessionId, deviceId: session.deviceId || null },
    issuedVia: 'session',
    validitySeconds,
  });
}

/**
 * Kayıtlı bir cihaz için cihaz kimliği.
 *
 * Cihaz kaydı `user_devices` tablosundadır ve kullanıcı onu profilinden
 * kaldırabilir. Kaldırıldığında bu sertifika İPTAL EDİLMEZ -- yenilenmez, ki
 * dakikalar içinde aynı sonucu verir ve bir CRL'in yayılmasını beklemez.
 */
async function issueForDevice({
  db, pkiIssuer, sessionManager, session, deviceId, csrPem, validitySeconds = null,
}) {
  if (!session || session.revoked) {
    throw new AppError('unauthenticated', 'Oturum gerekli', { httpStatus: 401 });
  }
  if (!deviceId) throw new AppError('invalid_request', 'deviceId gerekli', { httpStatus: 400 });

  return issueShortLivedCertificate({
    db,
    pkiIssuer,
    sessionManager,
    profile: 'device',
    csrPem,
    spiffeId: spiffe.identities.device(deviceId).uri,
    binding: { userId: session.userId, sessionId: session.sessionId, deviceId },
    issuedVia: 'device_binding',
    validitySeconds,
  });
}

/**
 * Bir iş yükü (arka uç servis, iş, otomasyon) için iş yükü kimliği.
 *
 * Yetki, çağıranın taşıdığı OAuth erişim jetonundan gelir; ama İSİM jetondan
 * GELMEZ. `workloads` tablosu -- yapılandırma -- hangi client_id'nin hangi iş
 * yükü adını alabileceğini söyler. Jetonun kendi adını seçmesine izin vermek,
 * keyfi bir `sub` üretebilen herkesin sistemdeki herhangi bir kimliğe
 * bürünebilmesi demek olurdu.
 */
async function issueForWorkload({
  db, pkiIssuer, sessionManager, introspection, workloadName, instanceId = null,
  csrPem, workloadRegistry, validitySeconds = null,
}) {
  if (!introspection || introspection.active !== true) {
    throw new AppError('invalid_token', 'Erişim jetonu geçerli değil', { httpStatus: 401 });
  }
  const entry = workloadRegistry[workloadName];
  // Bilinmeyen iş yükü ile reddedilen jeton aynı mesajı döner: kimlik
  // doğrulamamış bir çağırana hangi iş yükü adlarının var olduğunu söylemek
  // bedava keşiftir.
  if (!entry) throw new AppError('workload_not_authorised', 'Bu kimlik için yetki yok', { httpStatus: 403 });

  const scopes = String(introspection.scope || '').split(/\s+/).filter(Boolean);
  if (entry.requiredScope && !scopes.includes(entry.requiredScope)) {
    throw new AppError('workload_not_authorised', 'Bu kimlik için yetki yok', { httpStatus: 403 });
  }
  if (entry.allowedClients && !entry.allowedClients.includes(introspection.aud)) {
    throw new AppError('workload_not_authorised', 'Bu kimlik için yetki yok', { httpStatus: 403 });
  }

  return issueShortLivedCertificate({
    db,
    pkiIssuer,
    sessionManager,
    profile: entry.profile || 'workload',
    csrPem,
    spiffeId: spiffe.identities.workload(workloadName, instanceId).uri,
    subjectCn: workloadName,
    binding: {
      workloadName,
      sessionId: introspection.sid || null,
      // Jetonun `sub` alanı BURAYA yazılmıyor.
      //
      // Bir iş yükü jetonunun öznesi bir servis asıl kimliğidir, `users`
      // tablosunda bir satır değil. Onu `userId` diye kaydetmek, sürekli
      // doğrulamanın her yenilemede var olmayan bir kullanıcıyı aramasına ve
      // her iş yükünün ikinci turda düşmesine yol açar -- yani mekanizma
      // çalışıyor görünür ve tam olarak korumaya çalıştığı şeyi kırar.
      // Denetim için ayrı bir alanda taşınıyor.
      tokenSubject: introspection.sub || null,
    },
    issuedVia: 'oauth_token',
    validitySeconds: validitySeconds || entry.validitySeconds || null,
  });
}

// ============================================================================
// SORGULAMA
// ============================================================================

/** Bir SPIFFE kimliği için hâlâ canlı olan sertifikalar. */
async function listLiveCertificates({ db, spiffeId, now = Date.now() }) {
  const rows = await db.collection('workload_certificates').find('spiffeId', spiffeId);
  return rows
    .filter((row) => Number(row.notAfter) > now && row.status === 'valid')
    .map(toView)
    .sort((a, b) => b.notAfter - a.notAfter);
}

/** Bir oturuma ait canlı kısa ömürlü kimlikler -- "çıkış yap" bunları kapatır. */
async function listForSession({ db, sessionId, now = Date.now() }) {
  const rows = await db.collection('workload_certificates').find('sessionId', sessionId);
  return rows.filter((row) => Number(row.notAfter) > now).map(toView);
}

function toView(row) {
  return {
    serialNumberHex: row.serialNumberHex,
    spiffeId: row.spiffeId,
    profile: row.profile,
    issuedVia: row.issuedVia,
    notBefore: Number(row.notBefore),
    notAfter: Number(row.notAfter),
    status: row.status,
  };
}

module.exports = {
  issueShortLivedCertificate,
  issueForSession,
  issueForDevice,
  issueForWorkload,
  assertStillAuthorised,
  listLiveCertificates,
  listForSession,
  sweepExpired,
  RECORD_RETENTION_MS,
};
