'use strict';

const { completeLogin } = require('./login-completion');

const { AppError } = require('../core/errors');
const authService = require('./auth-service');
const { scanFindAll } = require('../db/query-utils');

// ============================================================================
// KAYIT (bir passkey EKLEME) -- hem "zorunlu ilk MFA kurulumu" hem "sonradan yeni bir
// cihaz ekleme" için AYNI uç noktalar kullanılır; fark sadece hangi token ile çağrıldığı
// (setupToken vs. zaten aktif bir oturumun access token'ı -- ikincisi oauth-server.js'te
// normal Authorization header ile doğrulanır, bu dosya sadece userId'yi umursar).
// ============================================================================
async function beginRegistration({ db, webauthnService, userId, username, displayName }) {
  const creds = db.collection('webauthn_credentials');
  const existing = await scanFindAll(creds, 'userId', userId);
  const excludeCredentialIds = existing.map((c) => c.credentialId);
  return webauthnService.createRegistrationOptions({ userId, username, displayName, excludeCredentialIds });
}


async function finishRegistration({ db, webauthnService, challengeId, credential, userId, nickname }) {
  const result = webauthnService.verifyRegistration({ challengeId, credential });

  const creds = db.collection('webauthn_credentials');
  if (await creds.findOne('credentialId', result.credentialId)) {
    throw new AppError('credential_already_registered', 'Bu passkey zaten kayıtlı', { httpStatus: 409 });
  }

  await creds.insert({
    userId, credentialId: result.credentialId,
    publicKeyJwk: JSON.stringify(result.publicKeyJwk), coseAlg: result.coseAlg,
    signCount: BigInt(result.signCount), aaguid: result.aaguid || '',
    nickname: nickname || 'Passkey', createdAt: BigInt(Date.now()), lastUsedAt: BigInt(0),
  });

  await authService.markMfaMethodEnrolled({ db, userId, method: 'webauthn' });
  return { registered: true, credentialId: result.credentialId };
}

// ============================================================================
// KİMLİK DOĞRULAMA (login) -- hem BİRİNCİL yöntem (parolasız giriş) hem İKİNCİL faktör
// (parola sonrası) olarak kullanılabilir; `mfaChallengeToken` verilip verilmemesi bu ikisini
// ayırır (bkz. auth-service.js başındaki politika açıklaması).
// ============================================================================
async function beginAuthentication({ db, webauthnService, username, purpose = 'primary' }) {
  const users = db.collection('users');
  const creds = db.collection('webauthn_credentials');

  let allowCredentialIds = [];
  if (username) {
    const user = await users.findOne('username', username);
    if (user) {
      const rows = await scanFindAll(creds, 'userId', String(user._id));
      allowCredentialIds = rows.map((r) => r.credentialId);
    }
  }
  // username verilmemişse (discoverable/resident-key akışı): allowCredentialIds boş kalır,
  // tarayıcı kullanıcıya cihazında kayıtlı TÜM passkey'leri gösterir.
  //
  // userVerification seçimi: 'primary' (parolasız giriş) modunda WebAuthn TEK BAŞINA tam
  // MFA yerine geçmek zorunda olduğu için 'required' istiyoruz -- uyumlu authenticator/
  // tarayıcılar UV yapamıyorsa ceremony'yi TARAYICI TARAFINDA reddeder (sunucuya hiç
  // ulaşmaz). 'second_factor' modunda (parola zaten doğrulandı) possession tek başına
  // yeterli olduğu için 'preferred' yeterli -- kullanıcıya gereksiz PIN/biyometrik
  // sürtünmesi eklemiyoruz.
  const userVerification = purpose === 'primary' ? 'required' : 'preferred';
  return webauthnService.createAuthenticationOptions({ allowCredentialIds, userVerification });
}

async function finishAuthentication({
  db, sessionManager, webauthnService, challengeId, credential, mfaChallengeToken,
  ip, userAgent, fingerprintId, deviceId = null, isNewDeviceCookie = false, mailer = null,
}) {
  const creds = db.collection('webauthn_credentials');
  const row = await creds.findOne('credentialId', credential.id);
  if (!row) throw new AppError('unknown_credential', 'Bu passkey tanınmıyor', { httpStatus: 401 });

  const storedCredential = { publicKeyJwk: JSON.parse(row.publicKeyJwk), signCount: Number(row.signCount) };
  const authResult = webauthnService.verifyAuthentication({ challengeId, credential, storedCredential });

  await creds.update(row._id, { signCount: BigInt(authResult.newSignCount), lastUsedAt: BigInt(Date.now()) });

  if (mfaChallengeToken) {
    // İKİNCİL FAKTÖR modu: parola zaten doğrulandı (1. faktör = knowledge). Herhangi bir
    // başarılı WebAuthn assertion'ı (UV şartı olmadan) 2. faktör (possession) olarak
    // yeterlidir -- iki BAĞIMSIZ faktör tamamlanmış olur.
    const pending = await authService.consumeMfaChallengeToken(mfaChallengeToken);
    if (!pending || pending.userId !== row.userId) {
      throw new AppError('invalid_mfa_challenge', 'Geçersiz veya süresi dolmuş 2FA isteği', { httpStatus: 401 });
    }
    return completeLogin({
      db, sessionManager, userId: row.userId, ip, userAgent, fingerprintId,
      deviceId, isNewDeviceCookie, mailer, method: 'parola + güvenlik anahtarı',
    });
  }

  // BİRİNCİL yöntem modu (parolasız giriş): sadece UV (user verification) doğrulanmışsa
  // -- yani authenticator biyometrik/PIN ile kullanıcıyı DOĞRULADIYSA -- bu TEK BAŞINA
  // yeterli MFA'dır (possession + inherence/knowledge, tek ceremony'de). UV yoksa
  // (örn. PIN'siz bir güvenlik anahtarı) sadece possession kanıtlanmış olur -> ikinci
  // bağımsız bir faktör zorunlu kılınır.
  //
  // NOT: beginAuthentication artık birincil girişte userVerification:'required' istediği
  // için, uyumlu tarayıcı/authenticator'larda bu dal pratikte NADİREN tetiklenir (UV
  // sağlanamıyorsa ceremony tarayıcı tarafında zaten reddedilir, sunucuya hiç gelmez).
  // Yine de savunma katmanı olarak burada bırakıyoruz -- eski/uyumsuz istemciler veya
  // ileride 'preferred' ile çağrılan başka bir akış için.
  if (authResult.userVerified) {
    return completeLogin({
      db, sessionManager, userId: row.userId, ip, userAgent, fingerprintId,
      deviceId, isNewDeviceCookie, mailer, method: 'passkey',
    });
  }

  const user = await db.collection('users').get(row.userId);
  const otherMethods = JSON.parse(user?.mfaMethods || '[]').filter((m) => m !== 'webauthn');
  if (otherMethods.length === 0) {
    // Kullanıcının TEK MFA yöntemi webauthn VE bu ceremony UV sağlayamadı -- teklif
    // edilebilecek gerçek bir ikinci faktör yok. Kullanıcının olmadığı bir yöntemi
    // (ör. hiç kurulmamış TOTP) var gibi göstermek yerine, açıkça yeniden deneme
    // isteyen bir hata döndürüyoruz.
    throw new AppError(
      'second_factor_unavailable',
      'Bu girişim yeterli doğrulama sağlamadı ve hesapta başka bir 2FA yöntemi kurulu değil. Lütfen güvenlik anahtarınızı PIN/biyometrik ile tekrar deneyin.',
      { httpStatus: 401 },
    );
  }
  return {
    requiresSecondFactor: true,
    mfaChallengeToken: await authService.issueMfaChallengeToken(row.userId),
    availableMethods: otherMethods,
    reason: 'webauthn_without_user_verification',
  };
}

module.exports = { beginRegistration, finishRegistration, beginAuthentication, finishAuthentication };
