'use strict';

module.exports = {
  users: {
    fields: [
      { no: 2, name: 'username', type: 'string', index: true, required: true },
      { no: 3, name: 'email', type: 'string', blindIndex: true, required: true },
      { no: 4, name: 'passwordHash', type: 'string' },
      { no: 5, name: 'status', type: 'string' },
      { no: 6, name: 'mfaMethods', type: 'string' },
      { no: 7, name: 'isAdmin', type: 'bool' },
      { no: 8, name: 'createdAt', type: 'uint64' },
      { no: 9, name: 'emailVerified', type: 'bool' },
      { no: 10, name: 'role', type: 'string' },
      { no: 11, name: 'certProfiles', type: 'string' },
      // SRP-6a. Sunucu parolayı ya da bir parola hash'ini DEĞİL, bir doğrulayıcı
      // (v = g^x mod N) saklar. `passwordHash` (no:4) korunuyor çünkü mevcut
      // hesaplar hâlâ onunla giriş yapıyor: bir kullanıcı SRP ile ilk kez
      // giriş yaptığında (ya da parolasını değiştirdiğinde) doğrulayıcı
      // tarayıcıda üretilip buraya yazılır, sonra passwordHash silinebilir.
      // İkisini birden zorunlu kılmak, mevcut herkesi aynı anda parola
      // sıfırlamaya mecbur bırakırdı.
      { no: 12, name: 'srpSalt', type: 'string' },
      { no: 13, name: 'srpVerifier', type: 'string' },
    ],
  },
  webauthn_credentials: {
    fields: [
      { no: 2, name: 'userId', type: 'string', index: true, required: true },
      { no: 3, name: 'credentialId', type: 'string', blindIndex: true, required: true },
      { no: 4, name: 'publicKeyJwk', type: 'string' },
      { no: 5, name: 'coseAlg', type: 'int32' },
      { no: 6, name: 'signCount', type: 'uint64' },
      { no: 7, name: 'aaguid', type: 'string' },
      { no: 8, name: 'nickname', type: 'string' },
      { no: 9, name: 'createdAt', type: 'uint64' },
      { no: 10, name: 'lastUsedAt', type: 'uint64' },
    ],
  },
  totp_credentials: {
    fields: [
      { no: 2, name: 'userId', type: 'string', index: true, required: true },
      { no: 3, name: 'secretBase64', type: 'string' },
      { no: 4, name: 'lastUsedCounter', type: 'int64' },
      { no: 5, name: 'createdAt', type: 'uint64' },
    ],
  },
  sessions: {
    fields: [
      { no: 2, name: 'sessionId', type: 'string', index: true, required: true },
      { no: 3, name: 'userId', type: 'string', index: true, required: true },
      { no: 4, name: 'ip', type: 'string' },
      { no: 5, name: 'userAgent', type: 'string' },
      { no: 6, name: 'fingerprintId', type: 'string' },
      { no: 7, name: 'audiences', type: 'string' },
      { no: 8, name: 'scope', type: 'string' },
      { no: 9, name: 'createdAt', type: 'uint64' },
      { no: 10, name: 'lastSeenAt', type: 'uint64' },
      { no: 11, name: 'revoked', type: 'bool' },
      { no: 12, name: 'revokedReason', type: 'string' },
      // Oturumun bağlı olduğu tarayıcı. Aynı (userId, deviceId) için yeni bir
      // oturum satırı AÇILMAZ; var olan tazelenir. Bkz. core/device-binding.js.
      { no: 13, name: 'deviceId', type: 'string', index: true },
    ],
  },

  // Kullanıcı başına görülmüş tarayıcılar. Adım yükseltme ve şüpheli giriş
  // bildirimi bu tabloya dayanır: hiç görülmemiş bir cihazdan giriş, parola
  // doğru olsa bile ikinci faktör ister ve kullanıcıya haber verilir.
  user_devices: {
    fields: [
      // userId:deviceId -- tekil arama için tek anahtar. İki alanı ayrı ayrı
      // sorgulayıp kesişim almak, her giriş için iki tur demek olurdu.
      { no: 2, name: 'userDeviceKey', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'userId', type: 'string', index: true, required: true },
      { no: 4, name: 'deviceId', type: 'string' },
      { no: 5, name: 'firstSeenAt', type: 'uint64' },
      { no: 6, name: 'lastSeenAt', type: 'uint64' },
      { no: 7, name: 'firstIp', type: 'string' },
      { no: 8, name: 'lastIp', type: 'string' },
      { no: 9, name: 'userAgent', type: 'string' },
      { no: 10, name: 'label', type: 'string' },
      { no: 11, name: 'trusted', type: 'bool' },
      { no: 12, name: 'loginCount', type: 'uint64' },
    ],
  },
  // Kullanıcı profili. `users` tablosundan AYRI tutuluyor: profil verisi
  // (avatar özellikle) her kimlik doğrulama okumasında gereksiz yere taşınırdı,
  // oysa users satırı her istekte okunuyor.
  user_profiles: {
    fields: [
      { no: 2, name: 'userId', type: 'string', index: true, required: true },
      { no: 3, name: 'displayName', type: 'string' },
      { no: 4, name: 'bio', type: 'string' },
      { no: 5, name: 'locale', type: 'string' },
      { no: 6, name: 'timezone', type: 'string' },
      // Temizlenmiş avatar baytları. Nesne deposu (object-store) yerine burada:
      // o depo gömülü motorun DDK'sına ve yerel disk yoluna bağlıdır, IdP ise
      // uzak bir veritabanına gRPC ile de bağlanabilmeli. 256 KB'lık bir sınır
      // kaydı taşımaz.
      { no: 7, name: 'avatarBytes', type: 'bytes' },
      { no: 8, name: 'avatarContentType', type: 'string' },
      { no: 9, name: 'avatarWidth', type: 'int32' },
      { no: 10, name: 'avatarHeight', type: 'int32' },
      // Avatarın ETag'i: değişmediyse tarayıcı yeniden indirmesin.
      { no: 11, name: 'avatarEtag', type: 'string' },
      { no: 12, name: 'updatedAt', type: 'uint64' },
      // E-posta tercihleri. Güvenlik uyarıları KAPATILAMAZ (aşağıya bkz.),
      // bu yüzden burada yalnızca kapatılabilir olanlar var.
      { no: 13, name: 'notifyProduct', type: 'bool' },
      { no: 14, name: 'notifyNewDevice', type: 'bool' },
      { no: 15, name: 'notifyNewsletter', type: 'bool' },
    ],
  },
  refresh_tokens: {
    fields: [
      { no: 2, name: 'hash', type: 'string', index: true, required: true },
      { no: 3, name: 'sessionId', type: 'string', index: true, required: true },
      { no: 4, name: 'audience', type: 'string' },
      { no: 5, name: 'scope', type: 'string' },
      { no: 6, name: 'createdAt', type: 'uint64' },
      { no: 7, name: 'expiresAt', type: 'uint64' },
      { no: 8, name: 'used', type: 'bool' },
    ],
  },
  oauth_clients: {
    fields: [
      { no: 2, name: 'clientId', type: 'string', index: true, required: true },
      { no: 3, name: 'clientSecret', type: 'string' },
      { no: 4, name: 'name', type: 'string' },
      { no: 5, name: 'redirectUris', type: 'string' },
      { no: 6, name: 'allowedScopes', type: 'string' },
      { no: 7, name: 'createdAt', type: 'uint64' },
    ],
  },
  ephemeral_state: {
    fields: [
      { no: 2, name: 'key', type: 'string', index: true, required: true },
      { no: 3, name: 'valueJson', type: 'string' },
      { no: 4, name: 'expiresAt', type: 'uint64' },
    ],
  },
  certificates: {
    fields: [
      { no: 2, name: 'serialNumberHex', type: 'string', index: true, required: true },
      { no: 3, name: 'userId', type: 'string', index: true },
      { no: 4, name: 'subjectCn', type: 'string' },
      { no: 5, name: 'profile', type: 'string' },
      { no: 6, name: 'certPem', type: 'string' },
      { no: 7, name: 'notBefore', type: 'uint64' },
      { no: 8, name: 'notAfter', type: 'uint64' },
      { no: 9, name: 'status', type: 'string' },
      { no: 10, name: 'revokedAt', type: 'uint64' },
      { no: 11, name: 'revocationReason', type: 'string' },
      { no: 12, name: 'createdAt', type: 'uint64' },
      { no: 13, name: 'issuedVia', type: 'string' },
      { no: 14, name: 'skidHex', type: 'string', index: true },
    ],
  },
  // Certificate Transparency log girdileri (RFC 6962).
  //
  // EKLEME-YALNIZCA: bu koleksiyona güncelleme/silme yolu yok. Merkle ağacı
  // geçmişi değiştirmeyi kanıtlanabilir kılar; bir kaydı hiç yazmamaya karşı
  // koruma ise log'un birden fazla tarafça izlenmesidir.
  ct_log_entries: {
    fields: [
      { no: 2, name: 'dedupeKey', type: 'string', index: true, required: true },
      { no: 3, name: 'leafIndex', type: 'uint64', index: true },
      { no: 4, name: 'timestamp', type: 'uint64' },
      { no: 5, name: 'entryType', type: 'int32' },
      { no: 6, name: 'leafHashB64', type: 'string' },
      { no: 7, name: 'merkleLeafB64', type: 'string' },
      { no: 8, name: 'sctB64', type: 'string' },
    ],
  },
  acme_accounts: {
    fields: [
      { no: 2, name: 'accountId', type: 'string', index: true, required: true },
      { no: 3, name: 'jwkThumbprint', type: 'string', index: true },
      { no: 4, name: 'jwkJson', type: 'string' },
      { no: 5, name: 'contact', type: 'string' },
      { no: 6, name: 'status', type: 'string' },
      { no: 7, name: 'createdAt', type: 'uint64' },
    ],
  },
  acme_orders: {
    fields: [
      { no: 2, name: 'orderId', type: 'string', index: true, required: true },
      { no: 3, name: 'accountId', type: 'string', index: true },
      { no: 4, name: 'status', type: 'string' },
      { no: 5, name: 'identifiersJson', type: 'string' },
      { no: 6, name: 'authorizationIdsJson', type: 'string' },
      { no: 7, name: 'certificateSerial', type: 'string' },
      { no: 8, name: 'expiresAt', type: 'uint64' },
      { no: 9, name: 'createdAt', type: 'uint64' },
    ],
  },
  acme_authorizations: {
    fields: [
      { no: 2, name: 'authzId', type: 'string', index: true, required: true },
      { no: 3, name: 'orderId', type: 'string', index: true },
      { no: 4, name: 'identifier', type: 'string' },
      { no: 5, name: 'status', type: 'string' },
      { no: 6, name: 'challengesJson', type: 'string' },
      { no: 7, name: 'expiresAt', type: 'uint64' },
    ],
  },
};