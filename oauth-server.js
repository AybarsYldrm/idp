'use strict';

// ============================================================================
// ❄️ fitfak-idp -- session.fitfak.net için bağımsız OAuth2/WebAuthn Kimlik Sağlayıcı
// ============================================================================

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const { loadOrCreateSigningKeyPair, publicKeyToJwks } = require('./core/keys');
const { SessionManager, ACCOUNTS_COOKIE_NAME } = require('./core/session-manager');
const { WebAuthnService } = require('./core/webauthn');
const { ProofOfWorkService } = require('./core/proof-of-work');
const { DbEphemeralStore, PrefixedEphemeralStore } = require('./core/ephemeral-store');
const { LoginProtection } = require('./core/rate-limiter');
const { createSameOriginGuard } = require('./core/same-origin');
const { UserQuota } = require('./core/user-quota');
const cookieConsent = require('./core/cookie-consent');
const {
  Server, Service, GRPC_STATUS, GrpcError, requireBearerAuth,
} = require('./core/http-transport');
const { mountBidiBridge } = require('./core/bidi-bridge');
const qrcode = require('@fitfak/qr');
const { ProductionPkiIssuer } = require('./core/pki-issuer');
const certificateService = require('./services/certificate-service');
const { AcmeService } = require('./services/acme-service');
const ocspService = require('./services/ocsp-service');
const crlService = require('./services/crl-service');
const { createStatusHandler, createPolicyHandler } = require('./services/status-server');
const { createCtLog, createCtHandler, CT_PATH_PREFIX } = require('./services/ct-log-service');
const { safeRedirect } = require('./core/safe-redirect');
const deviceBinding = require('./core/device-binding');
const { AppError } = require('./core/errors');
const schema = require('./db/schema');

const authService = require('./services/auth-service');
const webauthnServiceModule = require('./services/webauthn-service');
const { OAuthService, createDbClientStore } = require('./services/oauth-service');
const srpAuthService = require('./services/srp-auth-service');
const profileService = require('./services/profile-service');
const consentService = require('./services/consent-service');

// ----------------------------------------------------------------------------
// 🏗️ YAPILANDIRMA
// ----------------------------------------------------------------------------
// Buradaki satırlar eskiden `process.env.X = "..."` biçiminde kendi ortamını
// eziyordu ve içlerinde CANLI sırlar vardı (veritabanı kök sırrı, SMTP parolası,
// bir kasa kimliği). Bunlar depoya işlendiği için artık git geçmişindedir --
// koddan silmek onları geçmişten kaldırmaz. İLGİLİ KİMLİK BİLGİLERİ
// DÖNDÜRÜLMELİDİR; ayrıntı için README'deki "Sır rotasyonu" bölümüne bakın.
const config = require('./core/config').load();
const { connectToDatabase } = require('./core/db-bootstrap');

const PORT = config.port;
const ISSUER = config.issuer;
const RP_ID = config.rpId;
const COOKIE_DOMAIN = config.cookieDomain;
const TRUST_HOST = config.trustHost;
const TRUST_ISSUER = process.env.FITFAK_IDP_TRUST_ISSUER || `https://${TRUST_HOST}`;
const KEY_DIR = config.keyDir;

// Gerçek çift-yönlü (bidi) akış yalnızca gerçek HTTP/2 üzerinden mümkün; düz
// porttaki her şey HTTP/1.1 ile çalışıyor. 0 verilerek kapatılabilir -- test
// ortamında sertifika dosyaları olmayabilir ve bunun için ayrı bir port açmak
// gereksiz.
const HTTP2_PORT = Number(process.env.FITFAK_IDP_HTTP2_PORT || 0);

// Mantıksal host başına bir bağlama adresi. Ayrım Host header'ıyla DEĞİL soket
// seviyesinde yapılır: Host, istemcinin yazdığı bir dizedir; yerel adres değildir.
const IDP_IP = config.bind.idp;       // session.fitfak.net
const PKI_IP = config.bind.trust;     // trust.fitfak.net
const ADMIN_IP = config.bind.admin;   // one.fitfak.net
const STATUS_IP = config.bind.status; // status.trust.fitfak.net / time.trust.fitfak.net

// Durum değiştiren, COOKIE ile kimliklenen uç noktalar için köken kapısı.
// Gerekçesi core/same-origin.js'in başında. Geliştirmede sayfa doğrudan
// http://127.0.0.1:PORT üzerinden açılıyor; o kökeni yalnızca üretim DIŞINDA
// listeye alıyoruz -- üretimde tek geçerli köken ISSUER'dır.
const DEV_ORIGINS = config.isProduction ? [] : [
  `http://${IDP_IP}:${PORT}`, `http://127.0.0.1:${PORT}`, `http://localhost:${PORT}`,
];
const requireSameOrigin = createSameOriginGuard({
  allowedOrigins: [ISSUER, ...DEV_ORIGINS],
});
// trust.fitfak.net'teki uç noktaları çağıran sayfa session.fitfak.net'te
// duruyor: istek köken-ötesi ama site-içi. Gerekçe core/same-origin.js'te.
const requireTrustOrigin = createSameOriginGuard({
  allowedOrigins: [ISSUER, TRUST_ISSUER, ...DEV_ORIGINS],
  allowSameSite: true,
});

// ----------------------------------------------------------------------------
// 🏗️ VERİTABANI KURULUMU
// ----------------------------------------------------------------------------
// Yumurta-tavuk sorununun çözümü core/db-bootstrap.js'te: ilk çalıştırmada
// bootstrap TLS -> enrolment -> mTLS, sonraki her açılışta diskteki
// sertifikadan devam. Ayrıntılı gerekçe o dosyanın başındadır.
async function bootstrapDatabase() {
  if (config.devMockDb) {
    console.warn('[fitfak-idp] UYARI: FITFAK_IDP_DEV_DB=1 -- bellek-içi MOCK veritabanı (kalıcılık ve şifreleme YOK).');
    const { createMockDb } = require('./test/mock-db');
    return { db: createMockDb(Object.keys(schema)), mode: 'mock' };
  }

  const result = await connectToDatabase({ config, logger: console });

  // Şemayı her açılışta uygula. Bu bir no-op değildir: alan eklemek bir
  // migrasyondur ve motor bunu tespit edip indeksleri yeniden kurar; kırıcı bir
  // değişiklik ise açılışta reddedilir -- ilk yazma denemesinde değil.
  if (typeof result.db.applySchemaRegistry === 'function') {
    await result.db.applySchemaRegistry(schema);
  } else {
    for (const [name, def] of Object.entries(schema)) {
      await result.db.defineCollectionAsync(name, def);
    }
  }
  return result;
}

// ----------------------------------------------------------------------------
// 🌐 KÜÇÜK HTTP YARDIMCILARI
// ----------------------------------------------------------------------------
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJsonBody(req) {
  const raw = await readRawBody(req);
  if (raw.length === 0) return {};
  try {
    return JSON.parse(raw.toString('utf8'));
  } catch {
    throw new AppError('invalid_json', 'İstek gövdesi geçerli JSON değil', { httpStatus: 400 });
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

const TRUSTED_IP_HEADER = config.trustedIpHeader;

function isPlausibleIp(ip) {
  return typeof ip === 'string' && ip.length > 0 && ip.length < 46 && !/[^0-9a-fA-F.:%]/.test(ip);
}

function getIp(req) {
  const trustedHeaderValue = req.headers[TRUSTED_IP_HEADER];
  if (trustedHeaderValue) {
    const ip = (Array.isArray(trustedHeaderValue) ? trustedHeaderValue[0] : trustedHeaderValue).split(',')[0].trim();
    if (isPlausibleIp(ip)) return ip;
  }
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const parts = (Array.isArray(xff) ? xff[0] : xff).split(',').map((s) => s.trim());
    const candidate = parts[parts.length - 1];
    if (isPlausibleIp(candidate)) return candidate;
  }
  return req.socket?.remoteAddress || 'unknown';
}

function sendJson(res, status, obj) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(obj));
}

function timingSafeEqualStrings(a, b) {
  const bufA = Buffer.from(String(a ?? ''));
  const bufB = Buffer.from(String(b ?? ''));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function wrapHandler(fn) {
  return async (req, res) => {
    try {
      await fn(req, res);
    } catch (e) {
      const status = e.httpStatus || 500;
      if (status >= 500) console.error('[fitfak-idp] beklenmeyen hata:', e);
      // "Çok sık denediniz" deyip ne zaman denenebileceğini söylememek,
      // istemciyi daha sık denemeye iter.
      if (e.retryAfterSeconds) res.setHeader('retry-after', String(e.retryAfterSeconds));
      sendJson(res, status, { error: e.code || 'internal_error', error_description: e.message || 'İç sunucu hatası' });
    }
  };
}

async function main() {
  const { db, mode: dbMode } = await bootstrapDatabase();
  console.log(`[fitfak-idp] Veritabanı bağlantısı hazır (mod: ${dbMode}).`);

  // --------------------------------------------------------------------------
  // ⚙️ SERVİSLER
  // --------------------------------------------------------------------------
  const signingKeyPair = loadOrCreateSigningKeyPair(KEY_DIR);
  const sessionManager = new SessionManager({
    store: authService.createSessionStoreAdapter(db),
    signingKeyPair, issuer: ISSUER, cookieDomain: COOKIE_DOMAIN,
  });
  const webauthn = new WebAuthnService({ rpId: RP_ID, rpName: 'Fitfak Kimlik', origin: ISSUER });

  const sharedEphemeralStore = new DbEphemeralStore(db);
  authService.configureEphemeralStore(sharedEphemeralStore);
  const antiBot = {
    rateLimiter: new LoginProtection(),
    pow: new ProofOfWorkService({ store: new PrefixedEphemeralStore(sharedEphemeralStore, 'pow:') }),
  };

  // --------------------------------------------------------------------------
  // 🔐 PKI / ACME / OCSP / CRL 
  // --------------------------------------------------------------------------
  process.env.FITFAK_IDP_REAL_PKI = '1';
  if (process.env.FITFAK_IDP_REAL_PKI === '1') {
    console.log('[fitfak-idp] ÜRETİM MODU: Gerçek PKI / ACME / OCSP / CRL altyapısı devrede.');
  } else {
    console.warn('[fitfak-idp] UYARI: PKI/ACME/OCSP/CRL SAHTE (dev-mock) issuer ile çalışıyor -- ÜRETİMDE KULLANMAYIN.');
  }
  
  // CT log'u önce kurulur: sertifika üretimi ona bağlı (önsertifika -> SCT ->
  // sertifika). Log yoksa sertifikalar SCT'siz üretilir, üretim durmaz.
  const ctLog = createCtLog({ db, keyDir: config.keyDir });
  const ctPublicKeyPem = require('node:fs').readFileSync(
    path.join(config.keyDir, 'ct-log.pub'), 'utf8',
  );
  const pkiIssuer = new ProductionPkiIssuer(config.caDir, { ctLog });
  const acmeService = new AcmeService({
    db, pkiIssuer, nonceStore: new PrefixedEphemeralStore(sharedEphemeralStore, 'acmenonce:'), issuer: TRUST_ISSUER,
    http01Port: Number(process.env.FITFAK_IDP_ACME_HTTP01_PORT || 80),
  });

  const clientStore = createDbClientStore(db);

  if (process.env.FITFAK_IDP_DNS_CLIENT_ID && process.env.FITFAK_IDP_DNS_CLIENT_SECRET) {
    const existingDnsClient = await clientStore.getClient(process.env.FITFAK_IDP_DNS_CLIENT_ID);
    if (!existingDnsClient) {
      await clientStore.createClient({
        clientId: process.env.FITFAK_IDP_DNS_CLIENT_ID,
        clientSecret: process.env.FITFAK_IDP_DNS_CLIENT_SECRET,
        name: 'DNS Paneli',
        redirectUris: [process.env.FITFAK_IDP_DNS_REDIRECT_URI || 'https://fitfak.net/oauth/callback'],
        allowedScopes: ['openid', 'profile', 'dns:read', 'dns:write'],
        clientUri: 'https://fitfak.net',
        // Kendi panelimiz: onay ekranı atlanır. "FITFAK, FITFAK hesabınıza
        // erişmek istiyor" diye sormak kullanıcıya bilgi vermez, yalnızca onu
        // onay ekranlarını okumadan geçmeye alıştırır.
        firstParty: true,
      });
      console.warn(`[fitfak-idp] DNS Paneli OAuth client'ı tohumlandı.`);
    }
  }

  const oauthService = new OAuthService({
    sessionManager, clientStore, db, issuer: ISSUER,
    authCodeStore: new PrefixedEphemeralStore(sharedEphemeralStore, 'authcode:'),
    deviceCodeStore: new PrefixedEphemeralStore(sharedEphemeralStore, 'devicecode:'),
    userCodeStore: new PrefixedEphemeralStore(sharedEphemeralStore, 'usercode:'),
    deviceCodePollIntervalS: Number(process.env.FITFAK_IDP_DEVICE_POLL_INTERVAL_S || 5),
  });
  // Onay ekranına giderken yetkilendirme isteğinin saklandığı yer.
  const consentStore = new PrefixedEphemeralStore(sharedEphemeralStore, 'consent:');

  // Giriş YAPMIŞ kullanıcının pahalı işlemleri için kota. Giriş öncesini
  // koruyan LoginProtection'dan ayrı bir eksen -- gerekçesi core/user-quota.js'te.
  const userQuota = new UserQuota();
  async function requireUserQuota(userId, action) {
    return userQuota.enforce(userId, action);
  }

  // --------------------------------------------------------------------------
  // ✉️ SABİT SMTP / E-POSTA YAPILANDIRMASI
  // --------------------------------------------------------------------------
  let mailer = null;
  if (config.smtp.host) {
    try {
      const { SMTPService } = require('./core/mailer');
      mailer = new SMTPService({
        host: config.smtp.host,
        port: config.smtp.port,
        username: config.smtp.username,
        password: config.smtp.password,
      });
      mailer.defaultFrom = config.smtp.from || config.smtp.username;
      console.log(`[fitfak-idp] SMTP yapılandırıldı: ${config.smtp.username}@${config.smtp.host}`);
    } catch (e) {
      console.warn('[fitfak-idp] UYARI: SMTP servisi yüklenemedi:', e.message);
    }
  } else {
    // E-posta olmadan doğrulama kodları ve şüpheli-oturum bildirimleri
    // gönderilemez. Sessizce devam etmek yerine bunu açıkça söylüyoruz:
    // kayıt akışı çalışır görünüp kullanıcıya kod ulaşmazsa sebebi burasıdır.
    console.warn('[fitfak-idp] UYARI: SMTP_HOST ayarlanmamış -- doğrulama kodları yalnızca loga yazılacak.');
  }

  async function resolveUsernameFromEmail(reqBody) {
    const inputStr = reqBody.email || reqBody.username;
    if (inputStr && inputStr.includes('@')) {
      try {
        const userRow = await db.collection('users').findOne('email', inputStr);
        if (userRow && userRow.username) return userRow.username;
      } catch (e) {
        const results = await db.collection('users').findOne('*', inputStr);
        if (Array.isArray(results)) {
          const match = results.find(r => r.email === inputStr);
          if (match) return match.username;
        }
      }
    }
    return inputStr;
  }

  async function resolveCurrentSession(req) {
    let at = null;
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        at = authHeader.split(' ')[1];
    }
    if (!at) {
        at = parseCookies(req)['__Secure-fitfak_at'];
    }

    if (!at) return null;
    let payload;
    try { 
        ({ payload } = sessionManager.verifyAccessToken(at)); 
    } catch { 
        return null; 
    }

    const session = await sessionManager.store.getSessionById(payload.sid);
    if (!session || session.revoked) return null;
    return { userId: payload.sub, sessionId: payload.sid, revoked: false };
  }

  async function resolveValidAccounts(req) {
    let sessionIds = [];
    try { sessionIds = JSON.parse(decodeURIComponent(parseCookies(req)[ACCOUNTS_COOKIE_NAME] || '[]')); } catch { sessionIds = []; }
    const out = [];
    for (const sid of sessionIds) {
      const session = await sessionManager.store.getSessionById(sid);
      if (!session || session.revoked) continue;
      const userRow = await db.collection('users').get(session.userId);
      if (!userRow) continue;
      out.push({ sessionId: sid, userId: session.userId, username: userRow.username, email: userRow.email });
    }
    return out;
  }

  async function addSessionToAccountsList(req, { sessionId, userId }) {
    const current = await resolveValidAccounts(req);
    const filtered = current.filter((a) => a.userId !== userId && a.sessionId !== sessionId);
    return [...filtered.map((a) => a.sessionId), sessionId];
  }

  /**
   * Yönetici yetkisi TEK bir kurala dayanır: doğrulanmış e-posta adresi
   * yapılandırmadaki yönetici adresine eşit mi.
   *
   * Önceki hâlde üç ayrı yol vardı (`role === 'admin'`, `isAdmin` bayrağı, sabit
   * kodlanmış bir adres) ve herhangi birinin doğru olması yetiyordu. Bu, yetkinin
   * nereden geldiğini okunamaz kılar: `role` alanını yazabilen HER kod yolu --
   * bir admin uç noktası, bir migrasyon, ileride eklenecek bir kayıt akışı --
   * sessizce yeni bir yönetici üretebilir. Tek ve değişmez bir kimlik, yetki
   * yükseltmeyi "hangi kod bu alanı yazabiliyor" sorusundan çıkarıp
   * yapılandırma sorusuna indirger.
   *
   * E-postanın DOĞRULANMIŞ olması da şart: aksi halde o adresi kayıt sırasında
   * yazmak yöneticilik için yeterli olurdu.
   */
  async function requireAdmin(req) {
    const session = await resolveCurrentSession(req);
    if (!session) throw new AppError('unauthenticated', 'Giriş yapılmamış', { httpStatus: 401 });
    const userRow = await db.collection('users').get(session.userId);

    const email = String(userRow?.email || '').toLowerCase();
    if (!userRow || !userRow.emailVerified || email !== config.adminEmail) {
      throw new AppError('forbidden', 'Bu işlem için yönetici yetkisi gerekli', { httpStatus: 403 });
    }
    return { ...session, username: userRow.username, email };
  }

  // Cihaz kimliği için ayrı bir HMAC anahtarı: token imzalama anahtarıyla aynı
  // sırrı kullanmak, iki farklı amacı tek anahtara bağlar ve birini döndürmeyi
  // diğerini de kırmadan imkânsız kılar.
  const deviceSecret = crypto.createHash('sha256')
    .update(config.db.rootSecret || Buffer.alloc(32))
    .update('fitfak-device-binding-v1')
    .digest();

  function currentDevice(req) {
    return deviceBinding.resolveDevice(req, { secret: deviceSecret, parseCookies });
  }

  async function applyFullLoginCookies(req, res, session) {
    const accountsList = await addSessionToAccountsList(req, { sessionId: session.sessionId, userId: session.userId });
    const cookiesToSet = [
      ...sessionManager.buildSsoCookies({ accessToken: session.accessToken, refreshToken: session.refreshToken }),
      sessionManager.buildAccountsListCookie(accountsList),
    ];
    // Cihaz çerezi yalnızca yeni üretildiğinde yazılır; her yanıtta yeniden
    // yazmak süresini sürekli uzatır ve "bu tarayıcıyı ne zamandır tanıyoruz"
    // sorusunu anlamsızlaştırır.
    if (session.deviceId && session.isNewDeviceCookie) {
      cookiesToSet.push(deviceBinding.buildDeviceCookie(session.deviceId, {
        secret: deviceSecret, cookieDomain: COOKIE_DOMAIN,
      }));
    }
    res.setHeader('set-cookie', cookiesToSet);
  }

  async function resolveUserIdForMfaSetup(req, body) {
    if (body.setupToken) {
      const pending = await authService.verifySetupToken(body.setupToken);
      if (!pending) throw new AppError('invalid_setup_token', 'Geçersiz veya süresi dolmuş', { httpStatus: 401 });
      return pending.userId;
    }
    const match = /^Bearer\s+(.+)$/.exec(req.headers.authorization || '');
    if (!match) throw new AppError('unauthenticated', 'Yetkisiz', { httpStatus: 401 });
    const { payload } = sessionManager.verifyAccessToken(match[1]);
    return payload.sub;
  }

  // --------------------------------------------------------------------------
  // 🌐 HTTP ROTALARI (Multi-Bind ile IP Bazlı Yönlendirme)
  // --------------------------------------------------------------------------
  const server = new Server();

  // IDP ROTALARI (127.0.0.1)
  server.addHttpHandler({ method: 'GET', path: '/.well-known/jwks.json' }, (req, res) => { sendJson(res, 200, publicKeyToJwks(signingKeyPair.publicKey, signingKeyPair.kid)); }, IDP_IP);
  server.addHttpHandler({ method: 'GET', path: '/.well-known/openid-configuration' }, (req, res) => {
    sendJson(res, 200, {
      issuer: ISSUER, authorization_endpoint: `${ISSUER}/oauth/authorize`, token_endpoint: `${ISSUER}/oauth/token`,
      userinfo_endpoint: `${ISSUER}/oauth/userinfo`, jwks_uri: `${ISSUER}/.well-known/jwks.json`,
      introspection_endpoint: `${ISSUER}/oauth/introspect`, response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
      device_authorization_endpoint: `${ISSUER}/oauth/device/code`, code_challenge_methods_supported: ['S256'],
      subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['ES256'],
    });
  }, IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/pow-challenge' }, wrapHandler(async (req, res) => {
    const recommended = antiBot.rateLimiter.recommendedPowDifficultyBits({ ip: getIp(req) });
    sendJson(res, 200, await antiBot.pow.issueChallenge({ difficultyBits: recommended }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/register' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    await authService.enforceAntiAutomation({
      antiBot, ip: getIp(req), username: body.username, headers: req.headers, socket: req.socket,
      clientFingerprint: body.fingerprint, powChallengeId: body.powChallengeId, powNonce: body.powNonce,
    });
    sendJson(res, 200, await authService.register({
      db, username: body.username, email: body.email, passwordPlain: body.password, mailer,
      srpSaltB64: body.srpSaltB64, srpVerifierB64: body.srpVerifierB64,
    }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/verify-email/resend' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    sendJson(res, 200, await authService.resendVerificationEmail({ db, email: body.email, mailer }));
  }), IDP_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/auth/password-reset/request' }, wrapHandler(async (req, res) => {
      const body = await readJsonBody(req);
      // NOT: yanıt e-posta kayıtlı olsa da olmasa da AYNI (bkz. auth-service.js'teki
      // kullanıcı numaralandırma koruması notu) -- istemciye asla "bu e-posta yok" demiyoruz.
      sendJson(res, 200, await authService.requestPasswordReset({ db, email: body.email, mailer }));
    }));
    server.addHttpHandler({ method: 'POST', path: '/auth/password-reset/confirm' }, wrapHandler(async (req, res) => {
      const body = await readJsonBody(req);
      const result = await authService.confirmPasswordReset({
        db, sessionManager, email: body.email, code: body.code, newPassword: body.newPassword,
      });
      // Parola sıfırlandığında TÜM oturumlar iptal edildiği için bu tarayıcının SSO
      // cookie'lerini de temizliyoruz -- aksi halde kullanıcı "giriş yapmış" görünürken
      // aslında iptal edilmiş bir oturumla dolaşırdı.
      res.setHeader('set-cookie', [...sessionManager.buildLogoutCookies(), sessionManager.expireAccountsListCookie()]);
      sendJson(res, 200, result);
    }));
    server.addHttpHandler({ method: 'POST', path: '/auth/verify-email/confirm' }, wrapHandler(async (req, res) => {
      const body = await readJsonBody(req);
      sendJson(res, 200, await authService.verifyEmail({ db, email: body.email, code: body.code }));
    }));

  server.addHttpHandler({ method: 'POST', path: '/auth/mfa/totp/begin' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    const enrollment = await authService.beginTotpEnrollment({ db, setupToken: body.setupToken, accountLabel: body.username });
    const qrPngBuffer = qrcode.generatePngBuffer(enrollment.provisioningUri);
    sendJson(res, 200, { ...enrollment, qrCodeBase64: `data:image/png;base64,${qrPngBuffer.toString('base64')}` });
  }), IDP_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/auth/mfa/totp/finish' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    sendJson(res, 200, await authService.finishTotpEnrollment({ db, setupToken: body.setupToken, code: body.code }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/webauthn/register/begin' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    const userId = await resolveUserIdForMfaSetup(req, body);
    sendJson(res, 200, await webauthnServiceModule.beginRegistration({
      db, webauthnService: webauthn, userId, username: body.username, displayName: body.displayName,
    }));
  }), IDP_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/auth/webauthn/register/finish' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    const userId = await resolveUserIdForMfaSetup(req, body);
    sendJson(res, 200, await webauthnServiceModule.finishRegistration({
      db, webauthnService: webauthn, challengeId: body.challengeId, credential: body.credential, userId, nickname: body.nickname,
    }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/reset-password/request' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    await authService.enforceAntiAutomation({
      antiBot, ip: getIp(req), username: `reset:${body.email}`, headers: req.headers, socket: req.socket,
      clientFingerprint: body.fingerprint, powChallengeId: body.powChallengeId, powNonce: body.powNonce,
    });
    sendJson(res, 200, await authService.requestPasswordReset({
      db, email: body.email, mailer, antiBot, ip: getIp(req), headers: req.headers, socket: req.socket,
      clientFingerprint: body.fingerprint, powChallengeId: body.powChallengeId, powNonce: body.powNonce
    }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/reset-password/confirm' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    sendJson(res, 200, await authService.confirmPasswordReset({ db, email: body.email, code: body.code, newPasswordPlain: body.newPassword, sessionManager }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/login/password' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    const targetUsername = await resolveUsernameFromEmail(body);
    await authService.enforceAntiAutomation({
      antiBot, ip: getIp(req), username: targetUsername, headers: req.headers, socket: req.socket,
      clientFingerprint: body.fingerprint, powChallengeId: body.powChallengeId, powNonce: body.powNonce,
    });
    sendJson(res, 200, await authService.loginWithPassword({ db, username: targetUsername, passwordPlain: body.password, antiBot }));
  }), IDP_IP);

  // ---- SRP-6a: parolanın sunucuya HİÇ ulaşmadığı giriş -----------------------
  // İki adım, tek kullanımlık durum. Ayrıntılı gerekçe services/srp-auth-service.js'te.
  const srpStateStore = new PrefixedEphemeralStore(sharedEphemeralStore, 'srp:');

  server.addHttpHandler({ method: 'POST', path: '/auth/srp/begin' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    await authService.enforceAntiAutomation({
      antiBot, ip: getIp(req), username: `srp:${body.identity}`, headers: req.headers, socket: req.socket,
      clientFingerprint: body.fingerprint, powChallengeId: body.powChallengeId, powNonce: body.powNonce,
    });
    sendJson(res, 200, await srpAuthService.beginSrpLogin({
      db, store: srpStateStore, config, identity: body.identity,
    }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/srp/finish' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    const { M2, userId } = await srpAuthService.finishSrpLogin({
      db, store: srpStateStore, stateId: body.stateId, A: body.A, M1: body.M1,
    });
    // Parola kanıtlandı ama bu TEK faktördür. Oturum burada verilmez; mevcut
    // akıştaki gibi bir 2. faktör (TOTP ya da WebAuthn) isteniyor. Sunucunun M2
    // kanıtı da dönüyor -- istemci bunu doğrulamazsa sahte bir sunucuyla
    // konuştuğunu anlayamaz.
    const challenge = await authService.issueMfaChallengeForUser({ db, userId });
    sendJson(res, 200, { M2, ...challenge });
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/srp/upgrade' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    sendJson(res, 200, await srpAuthService.upgradeLegacyAccountToSrp({
      db, authService,
      mfaChallengeToken: body.mfaChallengeToken, setupToken: body.setupToken,
      saltB64: body.saltB64, verifierB64: body.verifierB64,
    }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/login/totp' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    const { deviceId, isNew } = currentDevice(req);
    const session = await authService.completeLoginWithTotp({
      db, sessionManager, mfaChallengeToken: body.mfaChallengeToken, code: body.code,
      ip: getIp(req), userAgent: req.headers['user-agent'], antiBot,
      deviceId, isNewDeviceCookie: isNew, mailer,
    });
    await applyFullLoginCookies(req, res, session);
    sendJson(res, 200, { sessionId: session.sessionId, expiresIn: session.expiresIn });
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/webauthn/login/begin' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    const targetUsername = await resolveUsernameFromEmail(body);
    sendJson(res, 200, await webauthnServiceModule.beginAuthentication({
      db, webauthnService: webauthn, username: targetUsername, purpose: body.purpose || 'primary',
    }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/webauthn/login/finish' }, wrapHandler(async (req, res) => {
    const body = await readJsonBody(req);
    const { deviceId, isNew } = currentDevice(req);
    const result = await webauthnServiceModule.finishAuthentication({
      db, sessionManager, webauthnService: webauthn, challengeId: body.challengeId, credential: body.credential,
      mfaChallengeToken: body.mfaChallengeToken, ip: getIp(req), userAgent: req.headers['user-agent'],
      deviceId, isNewDeviceCookie: isNew, mailer,
    });
    if (result.accessToken) {
      await applyFullLoginCookies(req, res, result);
      sendJson(res, 200, { sessionId: result.sessionId, expiresIn: result.expiresIn });
    } else {
      sendJson(res, 200, result);
    }
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/switch-account' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    const body = await readJsonBody(req);
    const accounts = await resolveValidAccounts(req);
    const target = accounts.find((a) => a.sessionId === body.sessionId);
    if (!target) throw new AppError('not_found', 'Bu hesap bu tarayıcıda bulunamadı', { httpStatus: 404 });
    const tokens = await sessionManager.issueTokensForClient({ sessionId: target.sessionId, clientId: 'self', scope: 'openid profile' });
    await applyFullLoginCookies(req, res, {
      accessToken: tokens.accessToken, refreshToken: tokens.refreshToken,
      sessionId: target.sessionId, userId: target.userId,
    });
    // Hesap değiştirdikten sonra nereye gidileceği yanıtta dönüyor. Önceden
    // yalnızca {switched:true} dönüyordu ve istemci nereye gideceğini
    // bilmediği için kullanıcı seçim ekranında kalıyordu.
    sendJson(res, 200, {
      switched: true,
      username: target.username,
      redirectTo: safeRedirect(body.returnTo, { fallback: config.postLoginUrl, selfOrigin: ISSUER }),
    });
  }), IDP_IP);

  server.addHttpHandler({ method: 'GET', path: '/auth/accounts' }, wrapHandler(async (req, res) => {
    const accounts = await resolveValidAccounts(req);
    const active = await resolveCurrentSession(req);
    sendJson(res, 200, { accounts: accounts.map((a) => ({ ...a, isActive: !!active && active.sessionId === a.sessionId })) });
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/logout' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    const session = await resolveCurrentSession(req);
    if (session) await authService.logout({ sessionManager, sessionId: session.sessionId });
    const remainingAccounts = (await resolveValidAccounts(req)).filter((a) => !session || a.sessionId !== session.sessionId);
    res.setHeader('set-cookie', [
      ...sessionManager.buildLogoutCookies(),
      remainingAccounts.length > 0 ? sessionManager.buildAccountsListCookie(remainingAccounts.map((a) => a.sessionId)) : sessionManager.expireAccountsListCookie(),
    ]);
    sendJson(res, 200, { loggedOut: true });
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/auth/logout-all' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    // Yetki, erişim token'ından DEĞİL bu tarayıcıdaki hesap listesinden geliyor.
    //
    // Önceki hâli resolveCurrentSession() istiyordu, yani geçerli bir erişim
    // token'ı. Ama /auth/logout tam olarak o çerezi siliyor -- dolayısıyla
    // "önce bir hesaptan çık, sonra hepsinden çık" dizisi 401 ile bitiyordu ve
    // kullanıcı, tarayıcıda hâlâ açık duran diğer hesaplarını kapatamıyordu.
    // Çıkış yapmanın kimlik kanıtı gerektirmesi zaten yanlış yönde bir kısıt:
    // burada verilen karar "bu tarayıcıdaki her şeyi kapat".
    const accounts = await resolveValidAccounts(req);
    const current = await resolveCurrentSession(req);

    const sessionIds = new Set(accounts.map((a) => a.sessionId));
    if (current) sessionIds.add(current.sessionId);

    // Bu tarayıcıda bilinen her hesabın TÜM oturumları kapatılır -- "her yerden
    // çıkış yap" bunu ister, yalnızca bu tarayıcıdakileri değil.
    const userIds = new Set(accounts.map((a) => a.userId));
    if (current) userIds.add(current.userId);
    for (const userId of userIds) {
      for (const s of await sessionManager.listSessions(userId)) {
        if (!s.revoked) sessionIds.add(s.sessionId);
      }
    }

    let count = 0;
    for (const sessionId of sessionIds) {
      try { await sessionManager.revokeSession(sessionId, 'logout_all'); count += 1; }
      catch (_) { /* zaten iptal edilmiş olabilir */ }
    }

    res.setHeader('set-cookie', [
      ...sessionManager.buildLogoutCookies(),
      sessionManager.expireAccountsListCookie(),
    ]);
    sendJson(res, 200, { loggedOut: true, count });
  }), IDP_IP);

  server.addHttpHandler({ method: 'GET', path: '/auth/sessions' }, wrapHandler(async (req, res) => {
    const current = await resolveCurrentSession(req);
    if (!current) throw new AppError('unauthenticated', 'Giriş yapılmamış', { httpStatus: 401 });
    
    // Veritabanındaki tüm oturumları çek
    const sessions = await sessionManager.listSessions(current.userId);
    
    // SADECE aktif (iptal edilmemiş) olanları filtrele
    const activeSessions = sessions.filter((s) => !s.revoked);
    
    sendJson(res, 200, { 
      sessions: activeSessions.map((s) => ({ 
        sessionId: s.sessionId, 
        ip: s.ip, 
        userAgent: s.userAgent, 
        audiences: s.audiences, 
        createdAt: s.createdAt, 
        lastSeenAt: s.lastSeenAt, 
        revoked: s.revoked, 
        isCurrent: s.sessionId === current.sessionId 
      })) 
    });
  }), IDP_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/auth/sessions/revoke' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    const current = await resolveCurrentSession(req);
    if (!current) throw new AppError('unauthenticated', 'Giriş yapılmamış', { httpStatus: 401 });
    const body = await readJsonBody(req);
    const target = await sessionManager.store.getSessionById(body.sessionId);
    if (!target || target.userId !== current.userId) throw new AppError('not_found', 'Oturum bulunamadı', { httpStatus: 404 });
    await sessionManager.revokeSession(body.sessionId, 'user_requested');
    sendJson(res, 200, { revoked: true });
  }), IDP_IP);

  // Yetkilendirme isteğinin parametreleri, onay ekranından sonra da lazım. URL'de
  // taşımak yerine bir yardımcıda toplanıp sunucuda saklanıyor (bkz.
  // services/consent-service.js -- "Bekleyen yetkilendirme isteği").
  // İç isimler camelCase, tel üzerindeki isimler snake_case. Aradaki eşleme TEK
  // bir yerde: girişe gönderip geri döndürürken URL'i iç isimlerle yeniden
  // kurmak, kullanıcıyı `/oauth/authorize?clientId=...` gibi -- sunucunun
  // OKUYAMADIĞI -- bir adrese döndürürdü. Yani "giriş yap, sonra kaldığın
  // yerden devam et" akışı, tam da devam etmesi gereken noktada kırılırdı.
  const AUTHORIZE_PARAM_NAMES = {
    clientId: 'client_id', redirectUri: 'redirect_uri', responseType: 'response_type',
    scope: 'scope', state: 'state',
    codeChallenge: 'code_challenge', codeChallengeMethod: 'code_challenge_method',
    prompt: 'prompt',
  };

  function authorizationParams(q) {
    const out = {};
    for (const [internal, wire] of Object.entries(AUTHORIZE_PARAM_NAMES)) out[internal] = q.get(wire);
    return out;
  }

  function authorizationUrl(params) {
    const q = new URLSearchParams();
    for (const [internal, wire] of Object.entries(AUTHORIZE_PARAM_NAMES)) {
      if (params[internal] != null && params[internal] !== '') q.set(wire, params[internal]);
    }
    return `/oauth/authorize?${q.toString()}`;
  }

  async function finishAuthorization(req, res, params, { consentGranted = false } = {}) {
    const accounts = await resolveValidAccounts(req);
    const silent = String(params.prompt || '').split(/\s+/).includes('none');

    // Birden fazla açık hesap varsa hangisi adına izin verildiği kullanıcıya
    // sorulmalı. prompt=none bunu göstermeyi yasakladığı için hata döner --
    // aksi halde IdP, kullanıcının kastetmediği hesabı seçerdi.
    if (accounts.length >= 2) {
      if (silent) {
        res.statusCode = 302;
        res.setHeader('location', oauthService._errorRedirect({
          redirectUri: params.redirectUri, state: params.state,
          error: 'account_selection_required', description: 'Birden fazla açık hesap var',
        }));
        return res.end();
      }
      const back = authorizationUrl(params);
      res.statusCode = 302;
      res.setHeader('location', `/login?return_to=${encodeURIComponent(safeRedirect(back, { fallback: '/portal', selfOrigin: ISSUER }))}&choose_account=1`);
      return res.end();
    }
    const currentSession = accounts.length === 1
      ? { userId: accounts[0].userId, sessionId: accounts[0].sessionId, revoked: false } : null;

    const result = await oauthService.authorize({ ...params, currentSession, consentGranted });

    if (result.requiresConsent) {
      const pending = await consentService.createPendingAuthorization({
        store: consentStore,
        request: { params, userId: String(currentSession.userId), sessionId: currentSession.sessionId },
      });
      res.statusCode = 302;
      res.setHeader('location', `/consent?request=${encodeURIComponent(pending)}`);
      return res.end();
    }

    if (result.requiresLogin) {
      const back = authorizationUrl(params);
      res.statusCode = 302;
      res.setHeader('location', `/login?return_to=${encodeURIComponent(safeRedirect(back, { fallback: '/portal', selfOrigin: ISSUER }))}`);
      return res.end();
    }

    res.statusCode = 302;
    res.setHeader('location', result.errorRedirect || result.redirectTo);
    return res.end();
  }

  server.addHttpHandler({ method: 'GET', path: '/oauth/authorize' }, wrapHandler(async (req, res) => {
    const url = new URL(req.url, ISSUER);
    const q = url.searchParams;
    const client = await clientStore.getClient(q.get('client_id'));
    if (!client || !client.redirectUris.includes(q.get('redirect_uri'))) throw new AppError('invalid_request', 'Geçersiz client_id ya da redirect_uri', { httpStatus: 400 });
    return finishAuthorization(req, res, authorizationParams(q));
  }), IDP_IP);

  // ---- onay ekranı ----------------------------------------------------------
  // Sayfanın kendisi statik; ne istendiğini buradan öğrenir. `request`
  // tanıtıcısı olmadan gösterilecek bir şey yok, o yüzden doğrudan /consent'e
  // giren kullanıcı portala gider.
  server.addHttpHandler({ method: 'GET', path: '/consent/info' }, wrapHandler(async (req, res) => {
    const url = new URL(req.url, ISSUER);
    const session = await resolveCurrentSession(req);
    if (!session) throw new AppError('unauthenticated', 'Giriş yapılmamış', { httpStatus: 401 });

    const pending = await consentService.readPendingAuthorization({ store: consentStore, id: url.searchParams.get('request') });
    if (!pending) throw new AppError('not_found', 'Bu onay isteği bulunamadı ya da süresi doldu', { httpStatus: 404 });
    // Bekleyen istek, onu BAŞLATAN oturuma bağlı. Aksi halde bir sekmede
    // hesap değiştiren kullanıcı, diğer sekmedeki onayı yanlış hesap adına
    // verebilirdi.
    if (String(pending.userId) !== String(session.userId)) {
      throw new AppError('not_found', 'Bu onay isteği bu hesaba ait değil', { httpStatus: 404 });
    }

    const client = await clientStore.getClient(pending.params.clientId);
    if (!client) throw new AppError('not_found', 'Uygulama bulunamadı', { httpStatus: 404 });

    const scopes = consentService.resolveRequestedScopes({ requested: pending.params.scope, client });
    const existing = await consentService.getGrant({ db, userId: session.userId, clientId: client.clientId });
    const held = new Set(existing ? existing.scopes : []);
    const profile = await profileService.getProfile({ db, userId: session.userId });

    sendJson(res, 200, {
      client: {
        clientId: client.clientId, name: client.name, clientUri: client.clientUri || null,
        // Kullanıcı nereye gönderileceğini görmeli: onay ekranındaki asıl
        // soru "kime" değil, "nereye".
        redirectHost: new URL(pending.params.redirectUri).host,
      },
      account: {
        username: profile.username, email: profile.email,
        displayName: profile.displayName, avatarUrl: profile.avatarUrl,
      },
      // Daha önce verilmiş izinler ayrı işaretleniyor: kullanıcı NEYİN yeni
      // olduğunu görmeli, yoksa her seferinde aynı listeyi okumaya çalışır.
      scopes: scopes.map((s) => ({ ...consentService.describeScope(s), isNew: !held.has(s) })),
      previouslyGranted: existing ? existing.scopes : [],
    });
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/consent/decide' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    const session = await resolveCurrentSession(req);
    if (!session) throw new AppError('unauthenticated', 'Giriş yapılmamış', { httpStatus: 401 });
    const body = await readJsonBody(req);

    // Tek kullanımlık: tüketildikten sonra aynı tanıtıcı ikinci bir izin
    // veremez.
    const pending = await consentService.consumePendingAuthorization({ store: consentStore, id: body.request });
    if (!pending) throw new AppError('not_found', 'Bu onay isteği bulunamadı ya da süresi doldu', { httpStatus: 404 });
    if (String(pending.userId) !== String(session.userId)) {
      throw new AppError('not_found', 'Bu onay isteği bu hesaba ait değil', { httpStatus: 404 });
    }

    const client = await clientStore.getClient(pending.params.clientId);
    if (!client) throw new AppError('not_found', 'Uygulama bulunamadı', { httpStatus: 404 });

    if (!body.approve) {
      // Reddetme de bir cevaptır ve client'a İLETİLİR: kullanıcı reddettiğinde
      // uygulamanın sonsuza kadar beklemesi değil, "hayır" demesi gerekir.
      return sendJson(res, 200, {
        redirectTo: oauthService._errorRedirect({
          redirectUri: pending.params.redirectUri, state: pending.params.state,
          error: 'access_denied', description: 'Kullanıcı izni reddetti',
        }),
      });
    }

    const scopes = consentService.resolveRequestedScopes({ requested: pending.params.scope, client });
    await consentService.saveGrant({ db, userId: session.userId, clientId: client.clientId, scopes });

    const result = await oauthService.authorize({
      ...pending.params,
      currentSession: { userId: session.userId, sessionId: session.sessionId, revoked: false },
      consentGranted: true,
    });
    sendJson(res, 200, { redirectTo: result.errorRedirect || result.redirectTo });
  }), IDP_IP);

  // ---- çerez tercihleri -----------------------------------------------------
  // İstatistik çerezi ile oturum çerezi AYRI kategoriler. Gerekçe
  // core/cookie-consent.js'in başında: aynı kategoride sayıldıkları sürece ya
  // istatistik rızasız yazılır ya da "hepsini reddet" oturumu kapatır.
  //
  // Uç noktalar oturum İSTEMEZ: rıza, giriş yapmamış ziyaretçi için de geçerli
  // bir karardır ve tam olarak o ziyaretçiye sorulması gerekir.
  server.addHttpHandler({ method: 'GET', path: '/api/cookies' }, wrapHandler(async (req, res) => {
    const prefs = cookieConsent.readPreferences(req.headers.cookie);
    sendJson(res, 200, {
      ...cookieConsent.describeCatalog(),
      preferences: cookieConsent.preferencesAreCurrent(prefs) ? prefs : null,
      // Bant yalnızca karar VERİLMEMİŞSE gösterilir. Verilmiş bir kararı
      // tekrar tekrar sormak, kullanıcıyı okumadan kabul etmeye iter.
      needsDecision: !cookieConsent.preferencesAreCurrent(prefs),
    });
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/api/cookies' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    const body = await readJsonBody(req);
    const istatistik = body.istatistik === true;

    const setCookies = [cookieConsent.buildPreferencesCookie({ istatistik }, { domain: COOKIE_DOMAIN })];
    if (istatistik) {
      // Zaten varsa yenisini yazmıyoruz: her onayda yeni tanıtıcı üretmek,
      // ölçümü bozar ve kullanıcıya yeni bir tanıtıcı vermiş olurdu.
      if (!cookieConsent.parseCookieHeader(req.headers.cookie)[cookieConsent.STATS_COOKIE]) {
        setCookies.push(cookieConsent.buildStatisticsCookie({ domain: COOKIE_DOMAIN }));
      }
    } else {
      // Rıza geri alındığında çerez SİLİNİR. "Bir daha yazmayız" demek yetmez:
      // yazılmış olan hâlâ tarayıcıda durur ve her istekte gönderilir.
      setCookies.push(cookieConsent.expireStatisticsCookie({ domain: COOKIE_DOMAIN }));
    }
    res.setHeader('set-cookie', setCookies);
    sendJson(res, 200, { saved: true, istatistik });
  }), IDP_IP);

  // Verilmiş izinler: listeleme ve geri alma. /profile sayfasındaki "bağlı
  // uygulamalar" bölümü bunları kullanır.
  server.addHttpHandler({ method: 'GET', path: '/account/grants' }, wrapHandler(async (req, res) => {
    const session = await resolveCurrentSession(req);
    if (!session) throw new AppError('unauthenticated', 'Giriş yapılmamış', { httpStatus: 401 });
    sendJson(res, 200, { grants: await consentService.listGrants({ db, userId: session.userId, clientStore }) });
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/account/grants/revoke' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    const session = await resolveCurrentSession(req);
    if (!session) throw new AppError('unauthenticated', 'Giriş yapılmamış', { httpStatus: 401 });
    const body = await readJsonBody(req);
    sendJson(res, 200, await consentService.revokeGrant({
      db, userId: session.userId, clientId: body.clientId, sessionManager,
    }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/oauth/token' }, wrapHandler(async (req, res) => {
    const raw = await readRawBody(req);
    const contentType = req.headers['content-type'] || '';
    const body = contentType.includes('application/x-www-form-urlencoded') ? Object.fromEntries(new URLSearchParams(raw.toString('utf8'))) : JSON.parse(raw.toString('utf8') || '{}');
    const result = await oauthService.token({ grantType: body.grant_type, code: body.code, redirectUri: body.redirect_uri, codeVerifier: body.code_verifier, clientId: body.client_id, refreshToken: body.refresh_token, deviceCode: body.device_code, ip: getIp(req), userAgent: req.headers['user-agent'] });
    sendJson(res, 200, { access_token: result.accessToken, refresh_token: result.refreshToken, token_type: result.tokenType, expires_in: result.expiresIn });
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/oauth/device/code' }, wrapHandler(async (req, res) => {
    const raw = await readRawBody(req);
    const contentType = req.headers['content-type'] || '';
    const body = contentType.includes('application/x-www-form-urlencoded') ? Object.fromEntries(new URLSearchParams(raw.toString('utf8'))) : JSON.parse(raw.toString('utf8') || '{}');
    const result = await oauthService.startDeviceAuthorization({ clientId: body.client_id, scope: body.scope });
    sendJson(res, 200, { device_code: result.deviceCode, user_code: result.userCode, verification_uri: result.verificationUri, verification_uri_complete: result.verificationUriComplete, expires_in: result.expiresIn, interval: result.interval });
  }), IDP_IP);

  const DEVICE_INFO_MIN_RESPONSE_MS = 150;
  async function checkDeviceCodeRateLimit(req) {
    const { limited } = antiBot.rateLimiter.recordAttempt({ ip: `device-info:${getIp(req)}` });
    if (limited) throw new AppError('rate_limited', 'Çok fazla istek', { httpStatus: 429 });
  }
  async function withConstantTimeFloor(minMs, fn) {
    const startedAt = Date.now();
    try { return await fn(); } finally {
      const elapsed = Date.now() - startedAt;
      if (elapsed < minMs) await new Promise((resolve) => setTimeout(resolve, minMs - elapsed));
    }
  }

  server.addHttpHandler({ method: 'GET', path: '/device/info' }, wrapHandler(async (req, res) => {
    await checkDeviceCodeRateLimit(req);
    const url = new URL(req.url, ISSUER);
    const info = await withConstantTimeFloor(DEVICE_INFO_MIN_RESPONSE_MS, () => oauthService.lookupDeviceCodeByUserCode(url.searchParams.get('user_code')));
    if (!info) throw new AppError('invalid_user_code', 'Geçersiz', { httpStatus: 400 });
    sendJson(res, 200, info);
  }), IDP_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/device/approve' }, wrapHandler(async (req, res) => {
    await checkDeviceCodeRateLimit(req);
    const currentSession = await resolveCurrentSession(req);
    const body = await readJsonBody(req);
    const result = await withConstantTimeFloor(DEVICE_INFO_MIN_RESPONSE_MS, () => oauthService.approveDeviceCode({ userCode: body.userCode, currentSession }));
    sendJson(res, 200, result);
  }), IDP_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/device/deny' }, wrapHandler(async (req, res) => {
    await checkDeviceCodeRateLimit(req);
    const body = await readJsonBody(req);
    const result = await withConstantTimeFloor(DEVICE_INFO_MIN_RESPONSE_MS, () => oauthService.denyDeviceCode({ userCode: body.userCode }));
    sendJson(res, 200, result);
  }), IDP_IP);
  
  server.addHttpHandler({ method: 'GET', path: '/device' }, (req, res) => {
    const url = new URL(req.url, ISSUER);
    const target = new URL('/login', ISSUER);
    target.searchParams.set('device', '1');
    if (url.searchParams.get('user_code')) target.searchParams.set('user_code', url.searchParams.get('user_code'));
    res.statusCode = 302;
    res.setHeader('location', `${target.pathname}${target.search}`);
    res.end();
  }, IDP_IP);

  // ---- profil, avatar, tercihler, hesap silme --------------------------------
  const profileStore = new PrefixedEphemeralStore(sharedEphemeralStore, 'profile:');

  async function requireSession(req) {
    const session = await resolveCurrentSession(req);
    if (!session) throw new AppError('unauthenticated', 'Giriş yapılmamış', { httpStatus: 401 });
    return session;
  }

  // Profil API'si /api/ altında; /profile SAYFANIN kendisidir. İkisi aynı yolda
  // olamaz -- aynı method+path için ilk kayıtlı işleyici kazanır ve sayfa hiç
  // sunulmazdı.
  server.addHttpHandler({ method: 'GET', path: '/api/profile' }, wrapHandler(async (req, res) => {
    const session = await requireSession(req);
    sendJson(res, 200, await profileService.getProfile({ db, userId: session.userId }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/api/profile' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    const session = await requireSession(req);
    const body = await readJsonBody(req);
    sendJson(res, 200, await profileService.updateProfile({
      db, userId: session.userId,
      displayName: body.displayName, bio: body.bio, locale: body.locale, timezone: body.timezone,
    }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/api/profile/notifications' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    const session = await requireSession(req);
    const body = await readJsonBody(req);
    sendJson(res, 200, await profileService.updateNotificationPreferences({
      db, userId: session.userId,
      product: body.product, newDevice: body.newDevice, newsletter: body.newsletter,
    }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/api/profile/avatar' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    const session = await requireSession(req);
    await requireUserQuota(session.userId, 'avatar');
    // Gövde ham baytlar. content-type'a BAKILMIYOR: biçim kararı yalnızca
    // baytlardan veriliyor (bkz. core/image-guard.js).
    const raw = await readRawBody(req);
    sendJson(res, 200, await profileService.setAvatar({ db, userId: session.userId, bytes: raw }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/api/profile/avatar/delete' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    const session = await requireSession(req);
    sendJson(res, 200, await profileService.deleteAvatar({ db, userId: session.userId }));
  }), IDP_IP);

  server.addHttpHandler((req) => req.method === 'GET' && req.url.split('?')[0].startsWith('/profile/avatar/'),
    wrapHandler(async (req, res) => {
      const userId = req.url.split('?')[0].slice('/profile/avatar/'.length);
      const avatar = await profileService.getAvatar({ db, userId });
      if (!avatar) { res.statusCode = 404; return res.end(); }

      if (req.headers['if-none-match'] === `"${avatar.etag}"`) {
        res.statusCode = 304; return res.end();
      }
      res.statusCode = 200;
      res.setHeader('content-type', avatar.contentType);
      res.setHeader('etag', `"${avatar.etag}"`);
      // Avatar baytları kullanıcı tarafından yüklenmiştir. Temizlenmiş olsa
      // bile tarayıcıya "bunu asla belge olarak yorumlama" demek gerekir:
      // nosniff olmadan içerik koklama, PNG'yi HTML sanabilir; CSP sandbox
      // ise dosya bir şekilde belge olarak açılırsa script çalışmasını keser.
      res.setHeader('x-content-type-options', 'nosniff');
      res.setHeader('content-security-policy', "default-src 'none'; sandbox");
      res.setHeader('content-disposition', 'inline');
      // ETag URL'de taşındığı için uzun önbellek güvenli.
      res.setHeader('cache-control', 'public, max-age=86400, immutable');
      res.end(avatar.bytes);
    }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/api/account/delete' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    const session = await requireSession(req);
    await requireUserQuota(session.userId, 'account-delete');
    sendJson(res, 200, await profileService.requestAccountDeletion({
      db, userId: session.userId, mailer, ephemeralStore: profileStore,
    }));
  }), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/api/account/delete/confirm' }, wrapHandler(async (req, res) => {
    requireSameOrigin(req);
    const session = await requireSession(req);
    await requireUserQuota(session.userId, 'account-delete-confirm');
    const body = await readJsonBody(req);
    const result = await profileService.confirmAccountDeletion({
      db, userId: session.userId, code: body.code,
      ephemeralStore: profileStore, sessionManager,
    });
    res.setHeader('set-cookie', [
      ...sessionManager.buildLogoutCookies(),
      sessionManager.expireAccountsListCookie(),
    ]);
    sendJson(res, 200, result);
  }), IDP_IP);

  server.addHttpHandler({ method: 'GET', path: '/oauth/userinfo' }, wrapHandler(async (req, res) => {
    const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=').map(decodeURIComponent)));
    const token = cookies['__Secure-fitfak_at'];
    if (!token) throw new AppError('invalid_token', 'Cookie içinde token eksik', { httpStatus: 401 });
    sendJson(res, 200, await oauthService.userinfo({ accessToken: token }));
}), IDP_IP);

  server.addHttpHandler({ method: 'POST', path: '/oauth/introspect' }, wrapHandler(async (req, res) => {
    const client = await clientStore.getClient(req.headers['x-client-id']);
    if (!client || !timingSafeEqualStrings(client.clientSecret, req.headers['x-client-secret'])) {
      throw new AppError('invalid_client', 'Geçersiz client', { httpStatus: 401 });
    }
    const body = await readJsonBody(req);
    sendJson(res, 200, await oauthService.introspect({ token: body.token }));
  }), IDP_IP);

  // ADMİN PANELİ (Arayüz Sunumu) (IDP)
  // Yönetim yüzeyi one.fitfak.net (127.0.0.3) üzerinde, giriş yüzeyinden AYRI
  // bir adreste. Ayrım yalnızca düzen için değil: session.fitfak.net herkese
  // açıkken, yönetim adresi ağ seviyesinde kapatılabilir hale gelir. Aynı
  // porttaki bir yol olsaydı, koruma yalnızca uygulama içindeki tek bir
  // kontrole (requireAdmin) bağlı kalırdı.
  server.addHttpHandler({ method: 'GET', path: '/admin' }, wrapHandler(async (req, res) => {
    // Sayfanın kendisi de oturum ister ve yönetici değilse girişe yollar --
    // aksi halde panel açılır, her AJAX çağrısı 403 döner ve kullanıcı ne
    // olduğunu anlamaz.
    const session = await resolveCurrentSession(req);
    if (!session) {
      res.statusCode = 302;
      res.setHeader('location', `/login?return_to=${encodeURIComponent('/admin')}`);
      return res.end();
    }
    await requireAdmin(req);
    servePage(res, 'admin-panel.html');
  }), ADMIN_IP);

  server.addHttpHandler({ method: 'GET', path: '/admin/users' }, wrapHandler(async (req, res) => {
    await requireAdmin(req);
    sendJson(res, 200, { users: await authService.listAllUsers({ db }) });
  }), ADMIN_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/admin/users/role' }, wrapHandler(async (req, res) => {
    const admin = await requireAdmin(req);
    const body = await readJsonBody(req);
    sendJson(res, 200, await authService.setUserRole({ db, targetUserId: body.userId, role: body.role, actingUserId: admin.userId }));
  }), ADMIN_IP);
  
  server.addHttpHandler({ method: 'GET', path: '/admin/sessions' }, wrapHandler(async (req, res) => {
    await requireAdmin(req);
    const url = new URL(req.url, ISSUER);
    const targetUserId = url.searchParams.get('userId');
    if (!targetUserId) throw new AppError('invalid_argument', 'userId gerekli', { httpStatus: 400 });
    const sessions = await sessionManager.listSessions(targetUserId);
    sendJson(res, 200, { sessions: sessions.map((s) => ({ sessionId: s.sessionId, ip: s.ip, userAgent: s.userAgent, audiences: s.audiences, createdAt: s.createdAt, lastSeenAt: s.lastSeenAt, revoked: s.revoked })) });
  }), ADMIN_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/admin/sessions/revoke' }, wrapHandler(async (req, res) => {
    await requireAdmin(req);
    const body = await readJsonBody(req);
    await sessionManager.revokeSession(body.sessionId, 'admin_revoked');
    sendJson(res, 200, { revoked: true });
  }), ADMIN_IP);

  server.addHttpHandler({ method: 'GET', path: '/admin/oauth-clients' }, wrapHandler(async (req, res) => {
    await requireAdmin(req);
    const clients = await clientStore.listClients();
    sendJson(res, 200, { clients: clients.map((c) => ({ ...c, clientSecret: undefined, clientSecretMasked: `••••${c.clientSecret.slice(-4)}` })) });
  }), ADMIN_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/admin/oauth-clients' }, wrapHandler(async (req, res) => {
    await requireAdmin(req);
    const body = await readJsonBody(req);
    if (!body.clientId || !Array.isArray(body.redirectUris) || body.redirectUris.length === 0) throw new AppError('invalid_argument', 'Eksik parametre', { httpStatus: 400 });
    const clientSecret = body.clientSecret || crypto.randomBytes(24).toString('base64url');
    const created = await clientStore.createClient({ clientId: body.clientId, clientSecret, name: body.name || body.clientId, redirectUris: body.redirectUris, allowedScopes: body.allowedScopes || ['openid', 'profile'] });
    sendJson(res, 200, { ...created, clientSecret });
  }), ADMIN_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/admin/oauth-clients/update' }, wrapHandler(async (req, res) => {
    await requireAdmin(req);
    const body = await readJsonBody(req);
    sendJson(res, 200, await clientStore.updateClient(body.clientId, { name: body.name, redirectUris: body.redirectUris, allowedScopes: body.allowedScopes }));
  }), ADMIN_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/admin/oauth-clients/delete' }, wrapHandler(async (req, res) => {
    await requireAdmin(req);
    const body = await readJsonBody(req);
    sendJson(res, 200, await clientStore.deleteClient(body.clientId));
  }), ADMIN_IP);

  // PKI ROTALARI (127.0.0.2)
  server.addHttpHandler({ method: 'POST', path: '/device/certificate' }, wrapHandler(async (req, res) => {
    requireTrustOrigin(req);
    const session = await resolveCurrentSession(req);
    if (!session) throw new AppError('unauthenticated', 'Giriş yapılmamış', { httpStatus: 401 });
    await requireUserQuota(session.userId, 'certificate');
    const body = await readJsonBody(req);
    const result = await certificateService.requestCertificate({ db, pkiIssuer, userId: session.userId, csrPem: body.csrPem, profile: body.profile || 'client-auth' });
    sendJson(res, 200, result);
  }), PKI_IP);
  
  server.addHttpHandler({ method: 'GET', path: '/device/certificates' }, wrapHandler(async (req, res) => {
    const session = await resolveCurrentSession(req);
    if (!session) throw new AppError('unauthenticated', 'Giriş yapılmamış', { httpStatus: 401 });
    sendJson(res, 200, { certificates: await certificateService.listCertificatesForUser({ db, userId: session.userId }) });
  }), PKI_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/device/certificate/revoke' }, wrapHandler(async (req, res) => {
    requireTrustOrigin(req);
    const session = await resolveCurrentSession(req);
    if (!session) throw new AppError('unauthenticated', 'Giriş yapılmamış', { httpStatus: 401 });
    const body = await readJsonBody(req);
    const result = await certificateService.revokeCertificate({ db, serialNumberHex: body.serialNumberHex, reason: body.reason, actingUserId: session.userId });
    await crlService.invalidateCrlCache(new PrefixedEphemeralStore(sharedEphemeralStore, 'crlcache:'));
    sendJson(res, 200, result);
  }), PKI_IP);

  // --------------------------------------------------------------------------
  // 📡 status.trust.fitfak.net -- OCSP / CRL / CA yayını (31.58.245.241:80)
  // --------------------------------------------------------------------------
  // Bunlar sertifikalarda AIA/CDP olarak yazan adreslerdir ve DÜZ HTTP'dir.
  // HTTPS olsaydı, bir sertifikanın iptal durumunu sorgulamak için önce başka
  // bir sertifikayı doğrulamak gerekirdi -- sorgu, doğrulamak istediği şeye
  // bağımlı hale gelirdi. Yanıtlar zaten kendi içlerinde imzalıdır.
  const statusHandler = createStatusHandler({
    db, pkiIssuer, cacheStore: new PrefixedEphemeralStore(sharedEphemeralStore, 'crlcache:'),
  });
  server.addHttpHandler(
    (req) => ['/ocsp', '/crl', '/crl/root', '/intermediate.crt', '/root.crt', '/chain.pem', '/']
      .includes(req.url.split('?')[0].replace(/\/+$/, '') || '/')
      || req.url.startsWith('/ocsp/'),
    statusHandler,
    STATUS_IP,
  );

  // Certificate Transparency log'u -- trust.fitfak.net/ct/v1/*
  const ctHandler = createCtHandler({ ctLog, publicKeyPem: ctPublicKeyPem });
  server.addHttpHandler(
    (req) => req.url.split('?')[0].startsWith(CT_PATH_PREFIX),
    ctHandler,
    PKI_IP,
  );

  // trust.fitfak.net/policy -- politika dağıtımı (127.0.0.2)
  const policyHandler = createPolicyHandler();
  server.addHttpHandler(
    (req) => req.method === 'GET' && req.url.split('?')[0].startsWith('/policy'),
    policyHandler,
    PKI_IP,
  );

  // CA sertifikaları trust.fitfak.net üzerinden de erişilebilir kalsın: eski
  // sertifikalardaki AIA adresleri buraya işaret ediyor olabilir.
  server.addHttpHandler({ method: 'GET', path: '/intermediate.crt' }, (req, res) => {
    res.setHeader('content-type', 'application/pkix-cert');
    res.end(pkiIssuer.subCA.certPem);
  }, PKI_IP);
  server.addHttpHandler({ method: 'GET', path: '/root.crt' }, (req, res) => {
    res.setHeader('content-type', 'application/pkix-cert');
    res.end(pkiIssuer.rootCA.certPem);
  }, PKI_IP);

  // ACME ROTALARI (PKI - 127.0.0.2)
  server.addHttpHandler({ method: 'GET', path: '/acme/directory' }, (req, res) => { sendJson(res, 200, acmeService.directory()); }, PKI_IP);
  
  server.addHttpHandler((req) => (req.method === 'GET' || req.method === 'HEAD') && req.url === '/acme/new-nonce', wrapHandler(async (req, res) => { 
    res.setHeader('Replay-Nonce', await acmeService.issueNonce()); res.setHeader('Cache-Control', 'no-store'); res.statusCode = 204; res.end(); 
  }), PKI_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/acme/new-account' }, wrapHandler(async (req, res) => { 
    const jwsObj = await readJsonBody(req); const result = await acmeService.newAccount(jwsObj); res.setHeader('Replay-Nonce', await acmeService.issueNonce()); res.setHeader('Location', `${TRUST_ISSUER}/acme/account/${result.accountId}`); sendJson(res, result.isNew ? 201 : 200, { status: result.status, orders: `${TRUST_ISSUER}/acme/account/${result.accountId}/orders` }); 
  }), PKI_IP);
  
  server.addHttpHandler({ method: 'POST', path: '/acme/new-order' }, wrapHandler(async (req, res) => { 
    const jwsObj = await readJsonBody(req); const order = await acmeService.newOrder(jwsObj); res.setHeader('Replay-Nonce', await acmeService.issueNonce()); res.setHeader('Location', `${TRUST_ISSUER}/acme/order/${order.orderId}`); sendJson(res, 201, order); 
  }), PKI_IP);
  
  server.addHttpHandler((req) => req.method === 'POST' && req.url.startsWith('/acme/authz/'), wrapHandler(async (req, res) => { 
    const authzId = req.url.split('/').pop(); sendJson(res, 200, await acmeService.getAuthorization(authzId)); 
  }), PKI_IP);
  
  server.addHttpHandler((req) => req.method === 'POST' && req.url.startsWith('/acme/challenge/'), wrapHandler(async (req, res) => { 
    const authzId = req.url.split('/').pop(); const jwsObj = await readJsonBody(req); const result = await acmeService.respondToChallenge(authzId, jwsObj); res.setHeader('Replay-Nonce', await acmeService.issueNonce()); sendJson(res, 200, result); 
  }), PKI_IP);
  
  server.addHttpHandler((req) => req.method === 'POST' && /\/acme\/order\/[^/]+\/finalize$/.test(req.url), wrapHandler(async (req, res) => { 
    const orderId = req.url.split('/')[3]; const jwsObj = await readJsonBody(req); const result = await acmeService.finalizeOrder(orderId, jwsObj); res.setHeader('Replay-Nonce', await acmeService.issueNonce()); sendJson(res, 200, result); 
  }), PKI_IP);
  
  server.addHttpHandler((req) => req.method === 'POST' && req.url.startsWith('/acme/cert/'), wrapHandler(async (req, res) => { 
    const serial = req.url.split('/').pop(); const certPem = await acmeService.downloadCertificate(serial); res.setHeader('content-type', 'application/pem-certificate-chain'); res.end(certPem); 
  }), PKI_IP);
  
  server.addHttpHandler({ method: 'GET', path: '/admin/certificates' }, wrapHandler(async (req, res) => { await requireAdmin(req); sendJson(res, 200, { certificates: await certificateService.listAllCertificates({ db }) }); }), ADMIN_IP);
  server.addHttpHandler({ method: 'POST', path: '/admin/certificates/revoke' }, wrapHandler(async (req, res) => { const admin = await requireAdmin(req); const body = await readJsonBody(req); const result = await certificateService.revokeCertificate({ db, serialNumberHex: body.serialNumberHex, reason: body.reason, actingUserId: admin.userId, actingUserRole: 'admin' }); await crlService.invalidateCrlCache(new PrefixedEphemeralStore(sharedEphemeralStore, 'crlcache:')); sendJson(res, 200, result); }), ADMIN_IP);

  server.addHttpHandler({ method: 'GET', path: '/admin/acme-orders' }, wrapHandler(async (req, res) => {
      await requireAdmin(req);
      const orders = [];
      // eslint-disable-next-line no-restricted-syntax
      for await (const row of db.collection('acme_orders').scan()) {
        orders.push({
          orderId: row.orderId,
          accountId: row.accountId,
          status: row.status,
          identifiers: JSON.parse(row.identifiersJson || '[]'),
          certificateSerial: row.certificateSerial || null,
          createdAt: Number(row.createdAt),
        });
      }
      const accounts = [];
      // eslint-disable-next-line no-restricted-syntax
      for await (const row of db.collection('acme_accounts').scan()) {
        accounts.push({
          accountId: row.accountId, contact: JSON.parse(row.contact || '[]'), status: row.status, createdAt: Number(row.createdAt),
        });
      }
      sendJson(res, 200, { orders, accounts });
    }), ADMIN_IP);
    server.addHttpHandler({ method: 'POST', path: '/admin/users/cert-profiles' }, wrapHandler(async (req, res) => {
      await requireAdmin(req);
      const body = await readJsonBody(req);
      const users = db.collection('users');
      const target = await users.get(body.userId);
      if (!target) throw new AppError('not_found', 'Kullanıcı bulunamadı', { httpStatus: 404 });
      const allowed = ['client-auth', 'server-auth', 'timestamping'];
      const profiles = (body.certProfiles || []).filter((p) => allowed.includes(p));
      await users.update(body.userId, { certProfiles: JSON.stringify(profiles) });
      sendJson(res, 200, { updated: true, certProfiles: profiles });
    }), ADMIN_IP);
  
    // ---- istemci tarafı yapılandırması (giriş sayfasının nereye yönlendireceği vb.) ----
    // Giriş tamamlandığında kullanıcı buraya yönlendirilir. Varsayılan olarak IdP'nin
    // kendi hesap portalı; FITFAK_IDP_POST_LOGIN_URL ile fitfak.net gibi kendi
    // uygulamanıza yönlendirebilirsiniz.
    server.addHttpHandler({ method: 'GET', path: '/config' }, (req, res) => {
      sendJson(res, 200, {
        postLoginUrl: config.postLoginUrl,
        issuer: ISSUER,
        trustIssuer: TRUST_ISSUER,
      });
    });

  // STATİK VARLIKLAR (IDP) -- yalnızca script/stil, HTML DEĞİL.
  //
  // /static/ altından HTML sunmak, temiz URL'lere konan kimlik kontrollerini
  // atlatmanın yolu olurdu: /portal oturum ister ama /static/portal.html aynı
  // sayfayı kontrolsüz verirdi. Sayfalar yalnızca kendi rotalarından erişilebilir.
  const PUBLIC_DIR = path.join(__dirname, 'public');
  const STATIC_CONTENT_TYPES = {
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.woff2': 'font/woff2',
  };
  server.addHttpHandler(
    (req) => req.method === 'GET' && req.url.split('?')[0].startsWith('/static/')
      && !req.url.split('?')[0].endsWith('.html'),
    (req, res) => {
      const rel = decodeURIComponent(req.url.split('?')[0].slice('/static/'.length));
      const filePath = path.join(PUBLIC_DIR, rel);
      // path.join zaten '..' çözer; kontrolü ondan SONRA yapmak, '/static/../x'
      // gibi girdilerin PUBLIC_DIR dışına çıkmasını engeller.
      if (!filePath.startsWith(PUBLIC_DIR + path.sep) || !fs.existsSync(filePath)) {
        res.statusCode = 404; res.end('bulunamadı'); return;
      }
      const type = STATIC_CONTENT_TYPES[path.extname(filePath)];
      if (!type) { res.statusCode = 404; res.end('bulunamadı'); return; }
      res.setHeader('content-type', type);
      res.setHeader('x-content-type-options', 'nosniff');
      res.setHeader('cache-control', 'public, max-age=3600');
      res.end(fs.readFileSync(filePath));
    },
    IDP_IP
  );
  // ---- temiz URL'ler ---------------------------------------------------------
  // Adres çubuğunda '.html' görünmemeli: dosya adı bir uygulama detayıdır,
  // sayfayı yeniden adlandırmak ya da başka bir şeyle sunmak kullanıcıların
  // yer imlerini kırmamalı.
  const PAGES = {
    '/login': 'demo-login.html',
    '/portal': 'portal.html',
    '/device': 'demo-login.html',
    '/hesap': 'portal.html',   // Türkçe takma ad
    '/profile': 'profile.html',
    '/profil': 'profile.html', // Türkçe takma ad
    '/consent': 'consent.html',
    // Yazdığımız her çerezin listesi ve tercih ekranı. Oturum İSTEMEZ: rıza,
    // giriş yapmamış ziyaretçi için de geçerli bir karardır.
    '/cookies': 'cookies.html',
    '/cerezler': 'cookies.html', // Türkçe takma ad
    // Tasarım paketinin canlı referansı. Diğer servisler fitfak-ui.css'i
    // kopyalayıp bu sayfaya bakarak aynı görünümü kurabilir.
    '/design': 'design-pack.html',
  };

  function servePage(res, file) {
    const filePath = path.join(PUBLIC_DIR, file);
    if (!fs.existsSync(filePath)) { res.statusCode = 404; res.end('bulunamadı'); return; }
    res.statusCode = 200;
    res.setHeader('content-type', 'text/html; charset=utf-8');
    // Giriş sayfaları önbelleğe alınmamalı: oturum durumuna göre farklı
    // davranıyorlar ve bir ara önbellek bunu bilmiyor.
    res.setHeader('cache-control', 'no-store');
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('x-frame-options', 'DENY');
    res.setHeader('referrer-policy', 'strict-origin-when-cross-origin');
    res.end(fs.readFileSync(filePath));
  }

  // Oturum isteyen sayfalar: oturumsuz açıldığında BOŞ bir sayfa göstermek
  // yerine girişe gider ve girişten SONRA buraya geri döner. Eksik olan buydu --
  // portala giren oturumsuz kullanıcı boş bir sayfa görüyordu ve girişten sonra
  // da portala dönmenin bir yolu yoktu.
  const AUTHENTICATED_PAGES = ['/portal', '/hesap', '/profile', '/profil', '/consent'];
  for (const route of AUTHENTICATED_PAGES) {
    const file = PAGES[route];
    server.addHttpHandler({ method: 'GET', path: route }, wrapHandler(async (req, res) => {
      const session = await resolveCurrentSession(req);
      if (!session) {
        res.statusCode = 302;
        // Sorgu dizesi korunuyor: /consent?request=... girişten sonra o isteğe
        // geri dönmeli, yoksa kullanıcı onay ekranını hiç göremez.
        res.setHeader('location', `/login?return_to=${encodeURIComponent(safeRedirect(req.url, { fallback: '/portal', selfOrigin: ISSUER }))}`);
        return res.end();
      }
      servePage(res, file);
    }), IDP_IP);
  }

  for (const [route, file] of Object.entries(PAGES)) {
    if (AUTHENTICATED_PAGES.includes(route)) continue; // yukarıda, kimlik kontrolüyle
    server.addHttpHandler({ method: 'GET', path: route }, (req, res) => servePage(res, file), IDP_IP);
  }

  // Eski /static/*.html bağlantıları kalıcı olarak temiz URL'lere taşınıyor:
  // dışarıda paylaşılmış bağlantılar kırılmasın.
  server.addHttpHandler(
    (req) => req.method === 'GET' && /^\/static\/[a-z-]+\.html$/.test(req.url.split('?')[0]),
    (req, res) => {
      const [pathname, query] = req.url.split('?');
      const file = pathname.slice('/static/'.length);
      const route = Object.keys(PAGES).find((r) => PAGES[r] === file);
      res.statusCode = route ? 301 : 404;
      if (route) res.setHeader('location', route + (query ? `?${query}` : ''));
      res.end(route ? '' : 'bulunamadı');
    },
    IDP_IP,
  );

  server.addHttpHandler({ method: 'GET', path: '/' }, async (req, res) => {
    const session = await resolveCurrentSession(req);
    res.statusCode = 302;
    res.setHeader('location', session ? '/portal' : '/login');
    res.end();
  }, IDP_IP);

  // gRPC SERVİSLERİ (IDP)
  function requireClientCredentials() {
    return async (call) => {
      const clientId = call.metadata['x-client-id'];
      const clientSecret = call.metadata['x-client-secret'];
      const client = await clientStore.getClient(clientId);
      if (!client || !timingSafeEqualStrings(client.clientSecret, clientSecret)) throw new GrpcError(GRPC_STATUS.UNAUTHENTICATED, 'geçersiz client kimlik bilgileri');
      call.context.clientId = clientId;
    };
  }

  const identitySvc = new Service('IdentityService');
  identitySvc.use(requireClientCredentials());
  identitySvc.addUnary('IntrospectToken', async (call) => oauthService.introspect({ token: call.request.token }));
  identitySvc.addUnary('VerifySession', async (call) => { const session = await sessionManager.store.getSessionById(call.request.sessionId); if (!session || session.revoked) return { valid: false }; if (!session.audiences.includes(call.context.clientId)) throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, 'izinsiz erişim'); return { valid: true, userId: session.userId, scope: session.scope }; });
  identitySvc.addUnary('GetUserSessions', async (call) => { const all = await sessionManager.listSessions(call.request.userId); const scoped = all.filter((s) => s.audiences.includes(call.context.clientId)); return { sessions: scoped.map((s) => ({ sessionId: s.sessionId, createdAt: s.createdAt.toISOString(), lastSeenAt: s.lastSeenAt.toISOString(), revoked: s.revoked })) }; });
  identitySvc.addUnary('RevokeSession', async (call) => { const session = await sessionManager.store.getSessionById(call.request.sessionId); if (!session) throw new GrpcError(GRPC_STATUS.NOT_FOUND, 'bulunamadı'); if (!session.audiences.includes(call.context.clientId)) throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, 'izinsiz'); await sessionManager.revokeSession(call.request.sessionId, `revoked_by_rp:${call.context.clientId}`); return { revoked: true }; });
  server.addService(identitySvc, IDP_IP);

  mountBidiBridge(server, '/events/sessions', async (call) => {
    const subscribedUserIds = new Set();
    call.on('message', (msg) => { if (msg.type === 'subscribe_user' && msg.userId) { subscribedUserIds.add(msg.userId); call.send({ type: 'subscribed', userId: msg.userId }); } });
    call.on('end', () => call.end());
  });

  await new Promise((resolve) => server.listen(PORT, {
    ...(HTTP2_PORT ? { http2Port: HTTP2_PORT } : {}),
    host: [...new Set([IDP_IP, PKI_IP, ADMIN_IP, STATUS_IP])],
  }, resolve));
  console.log(
    `[fitfak-idp] dinliyor:\n`
    + `  ${IDP_IP}:${PORT}    session.fitfak.net   (giris, OAuth, oturum)\n`
    + `  ${PKI_IP}:${PORT}    trust.fitfak.net     (ACME, sertifika, /policy)\n`
    + `  ${ADMIN_IP}:${PORT}    one.fitfak.net       (yonetim)\n`
    + `  ${STATUS_IP}:${PORT}  status.trust.fitfak.net (OCSP, CRL, CA yayini)\n`
    + `  issuer=${ISSUER} rpId=${RP_ID}`,
  );
  // Testler için: canlı sunucuya karşı koşan testlerin veritabanına ve oturum
  // yöneticisine de erişmesi gerekiyor (kayıt tohumlamak, PoW + e-posta
  // doğrulaması + TOTP kaydı zincirini her testte tekrarlamamak için oturum
  // üretmek).
  server._db = db;
  server._sessionManager = sessionManager;
  return server;
}

if (require.main === module) {
  main().catch((e) => {
    console.error('[fitfak-idp] başlatma hatası:', e);
    process.exit(1);
  });
}

module.exports = { main };
