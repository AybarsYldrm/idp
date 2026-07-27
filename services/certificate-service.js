'use strict';

const { AppError } = require('../core/errors');
const { scanFindAll } = require('../db/query-utils');

function isWellFormedCsrPem(csrPem) {
  return typeof csrPem === 'string'
    && csrPem.includes('-----BEGIN CERTIFICATE REQUEST-----')
    && csrPem.includes('-----END CERTIFICATE REQUEST-----');
}

// ============================================================================
// RBAC: bir kullanıcının hangi sertifika PROFİLLERİNİ (client-auth, server-auth,
// timestamping, vb.) talep edebileceğini kontrol eder. Varsayılan: HERKES 'client-auth'
// talep edebilir (kendi kimliğiyle mTLS girişi için). Daha ayrıcalıklı profiller (ör.
// 'timestamping', 'server-auth') ya kullanıcının `certProfiles` alanında AÇIKÇA
// verilmiş olmalı, ya da kullanıcı admin olmalı -- Snowflake/RBAC sisteminizin
// "kişinin yetkisi her türden sertifika üretmeye uygunsa" ifadesinin karşılığı budur.
// ============================================================================
function userCanRequestProfile(userRow, profile) {
  if (profile === 'client-auth') return true;
  if (userRow.role === 'admin' || userRow.isAdmin) return true;
  const allowed = JSON.parse(userRow.certProfiles || '[]');
  return allowed.includes(profile);
}

/**
 * Device Code (ya da herhangi bir zaten-doğrulanmış) oturumla giriş yapmış bir
 * kullanıcının CSR'ını alıp, RBAC'a göre izin verilen bir profil ile imzalar.
 * GERÇEK imzalama core/pki-issuer.js'e (sizin @fitfak/ssl'inize) delege edilir --
 * bu fonksiyon SADECE RBAC kapısı + DB kaydı + ince PEM biçim kontrolü yapar.
 */
async function requestCertificate({
  db, pkiIssuer, userId, csrPem, profile = 'client-auth',
}) {
  if (!isWellFormedCsrPem(csrPem)) {
    throw new AppError('invalid_csr', 'Geçersiz CSR biçimi (PEM bekleniyor)', { httpStatus: 400 });
  }
  const users = db.collection('users');
  const userRow = await users.get(userId);
  if (!userRow) throw new AppError('user_not_found', 'Kullanıcı bulunamadı', { httpStatus: 404 });

  if (!userCanRequestProfile(userRow, profile)) {
    throw new AppError(
      'profile_not_allowed',
      `Bu hesabın '${profile}' profilinde sertifika talep etme izni yok`,
      { httpStatus: 403 },
    );
  }

  const certs = db.collection('certificates');

  const {
    certPem, serialNumberHex, skidHex, notBefore, notAfter,
  } = await pkiIssuer.signCertificateFromCsr({
    csrPem,
    profile,
    subjectOverride: { cn: userRow.username, email: userRow.email },
  });

  // Anahtar tekilliği, imzalamadan ÖNCE bir ön-kontrolle DEĞİL, kaydın kendisiyle
  // ATOMİK olarak zorlanır.
  //
  // Önceki hâli `findOne('skidHex', ...)` ile bakıp sonra `insert()` ediyordu. Bu iki
  // ayrı await'tir: aynı CSR ile eşzamanlı gelen iki istek de "yok" görür ve ikisi de
  // yazar -- yani korumanın var olma sebebi olan senaryo, tam da onu denerken kaçar.
  // `insertUnique` kontrolü yazma kuyruğunun İÇİNDE yapar; ikinci istek
  // ALREADY_EXISTS/UNIQUE_CONSTRAINT ile döner.
  //
  // İmza kontrolden önce atıldığı için reddedilen bir istekte ortada imzalanmış ama
  // kaydedilmemiş bir sertifika kalır. Bu bilinçli bir tercih: o sertifika hiçbir zaman
  // istemciye verilmez ve kaydı olmadığı için OCSP/CRL tarafından 'unknown' sayılır --
  // yani doğrulanamaz. Tersi sıralama (önce kaydet, sonra imzala) ise imzalama
  // başarısız olduğunda anahtarı kalıcı olarak yakardı.
  try {
    await certs.insertUnique({
      serialNumberHex,
      skidHex,
      userId,
      subjectCn: userRow.username,
      profile,
      certPem,
      notBefore: BigInt(notBefore.getTime()),
      notAfter: BigInt(notAfter.getTime()),
      status: 'valid',
      revokedAt: 0n,
      revocationReason: '',
      createdAt: BigInt(Date.now()),
      issuedVia: 'device_code',
    }, { unique: ['skidHex'] });
  } catch (e) {
    if (e.code === 'UNIQUE_CONSTRAINT' || e.code === 'ALREADY_EXISTS' || /already exists/i.test(e.message || '')) {
      throw new AppError(
        'key_already_certified',
        'Bu açık anahtar için zaten bir sertifika üretilmiş. Lütfen yeni bir anahtar çifti ve CSR oluşturun.',
        { httpStatus: 409 },
      );
    }
    throw e;
  }

  return {
    certPem, serialNumberHex, notBefore: notBefore.toISOString(), notAfter: notAfter.toISOString(),
  };
}

async function revokeCertificate({
  db, serialNumberHex, reason, actingUserId, actingUserRole,
}) {
  const certs = db.collection('certificates');
  const row = await certs.findOne('serialNumberHex', serialNumberHex);
  if (!row) throw new AppError('not_found', 'Sertifika bulunamadı', { httpStatus: 404 });
  if (row.userId !== actingUserId && actingUserRole !== 'admin') {
    throw new AppError('forbidden', 'Bu sertifikayı iptal etme yetkiniz yok', { httpStatus: 403 });
  }
  await certs.update(row._id, {
    status: 'revoked', revokedAt: BigInt(Date.now()), revocationReason: reason || 'unspecified',
  });
  return { revoked: true };
}

async function getCertificateStatus({ db, serialNumberHex }) {
  const certs = db.collection('certificates');
  const row = await certs.findOne('serialNumberHex', serialNumberHex);
  if (!row) return { status: 'unknown' };
  return {
    status: row.status,
    subjectCn: row.subjectCn,
    profile: row.profile,
    notBefore: Number(row.notBefore),
    notAfter: Number(row.notAfter),
    revokedAt: row.status === 'revoked' ? Number(row.revokedAt) : null,
  };
}

async function listCertificatesForUser({ db, userId }) {
  const certs = db.collection('certificates');
  const rows = await scanFindAll(certs, 'userId', userId);
  return rows.map((row) => ({
    serialNumberHex: row.serialNumberHex,
    subjectCn: row.subjectCn,
    profile: row.profile,
    status: row.status,
    notBefore: Number(row.notBefore),
    notAfter: Number(row.notAfter),
    createdAt: Number(row.createdAt),
  }));
}

async function listAllCertificates({ db }) {
  const certs = db.collection('certificates');
  const result = [];
  // eslint-disable-next-line no-restricted-syntax
  for await (const row of certs.scan()) {
    result.push({
      serialNumberHex: row.serialNumberHex,
      userId: row.userId,
      subjectCn: row.subjectCn,
      profile: row.profile,
      status: row.status,
      notBefore: Number(row.notBefore),
      notAfter: Number(row.notAfter),
      createdAt: Number(row.createdAt),
    });
  }
  return result;
}

module.exports = {
  requestCertificate,
  revokeCertificate,
  getCertificateStatus,
  listCertificatesForUser,
  listAllCertificates,
  userCanRequestProfile,
};