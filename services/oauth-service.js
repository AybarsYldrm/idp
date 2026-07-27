'use strict';

const crypto = require('node:crypto');
const { AppError } = require('../core/errors');
const base64url = require('../core/base64url');
const { InMemoryEphemeralStore } = require('../core/ephemeral-store');

const AUTH_CODE_TTL_MS = 60 * 1000; // yetkilendirme kodu kısacık ömürlü ve tek kullanımlık olmalı
const DEVICE_CODE_TTL_MS = 10 * 60 * 1000; // RFC 8628 önerisi: birkaç dakika

// İnsan tarafından kolayca okunup elle yazılabilecek bir kod: karışıklık yaratan
// karakterler (0/O, 1/I/L) hariç tutulur, XXXX-XXXX biçiminde.
function generateUserCode() {
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 8; i++) {
    if (i === 4) code += '-';
    code += alphabet[crypto.randomInt(alphabet.length)];
  }
  return code;
}

class OAuthService {
  /**
   * @param {object} opts
   * @param {import('../core/session-manager').SessionManager} opts.sessionManager
   * @param {object} opts.clientStore - { getClient(clientId) -> {clientId, redirectUris:string[], allowedScopes:string[], name} | null }
   * @param {object} opts.db          - users koleksiyonuna (userinfo için) erişim
   * @param {string} opts.issuer
   * @param {object} [opts.authCodeStore] - core/ephemeral-store.js arayüzü ({get,set,delete}, hepsi
   *   async). Verilmezse tek-instance bellek-içi store kullanılır -- birden fazla instance
   *   koşuyorsanız oauth-server.js DbEphemeralStore enjekte eder (bkz. o dosyanın notu).
   */
  constructor({
    sessionManager, clientStore, db, issuer, authCodeStore, deviceCodeStore, userCodeStore, deviceCodePollIntervalS,
  }) {
    this.sessionManager = sessionManager;
    this.clientStore = clientStore;
    this.db = db;
    this.issuer = issuer;
    this.authCodes = authCodeStore || new InMemoryEphemeralStore();
    this.deviceCodes = deviceCodeStore || new InMemoryEphemeralStore();
    this.userCodes = userCodeStore || new InMemoryEphemeralStore();
    this.deviceCodePollIntervalS = deviceCodePollIntervalS || 5;
  }

  /**
   * GET /oauth/authorize mantığı. `currentSession` -- Domain=.fitfak.net SSO cookie'sinden
   * çözülmüş, HÂLİHAZIRDA doğrulanmış oturum (varsa) -- transport katmanı (oauth-server.js)
   * tarafından buraya geçirilir. Eğer geçerli bir oturum varsa kullanıcıya HİÇBİR login
   * formu göstermeden doğrudan yetkilendirme kodu üretilir -- SSO'nun "sihirli" kısmı
   * tam olarak burasıdır.
   */
  async authorize({ clientId, redirectUri, responseType, scope, state, codeChallenge, codeChallengeMethod, currentSession }) {
    const client = await this.clientStore.getClient(clientId);
    if (!client) throw new AppError('invalid_client', 'Bilinmeyen client_id', { httpStatus: 400 });
    if (!client.redirectUris.includes(redirectUri)) {
      throw new AppError('invalid_request', 'redirect_uri bu client için kayıtlı değil', { httpStatus: 400 });
    }
    if (responseType !== 'code') {
      throw new AppError('unsupported_response_type', "sadece response_type=code destekleniyor", { httpStatus: 400 });
    }
    if (codeChallengeMethod !== 'S256' || !codeChallenge) {
      throw new AppError('invalid_request', 'PKCE (code_challenge_method=S256) zorunludur', { httpStatus: 400 });
    }

    if (!currentSession || currentSession.revoked) {
      return { requiresLogin: true };
    }

    const code = base64url.encode(crypto.randomBytes(32));
    await this.authCodes.set(code, {
      clientId, redirectUri, codeChallenge, scope,
      userId: currentSession.userId, sessionId: currentSession.sessionId, used: false,
    }, AUTH_CODE_TTL_MS);

    const redirectUrl = new URL(redirectUri);
    redirectUrl.searchParams.set('code', code);
    if (state) redirectUrl.searchParams.set('state', state);
    return { redirectTo: redirectUrl.toString() };
  }

  /** POST /oauth/token -- authorization_code (PKCE), refresh_token ve device_code grant'lerini yönetir. */
  async token({ grantType, code, redirectUri, codeVerifier, clientId, refreshToken, ip, userAgent, deviceCode }) {
    if (grantType === 'authorization_code') {
      return this._exchangeAuthorizationCode({ code, redirectUri, codeVerifier, clientId });
    }
    if (grantType === 'refresh_token') {
      const tokens = await this.sessionManager.refresh({ refreshToken, ip, userAgent });
      return { ...tokens, tokenType: 'Bearer' };
    }
    if (grantType === 'urn:ietf:params:oauth:grant-type:device_code') {
      return this._exchangeDeviceCode({ deviceCode, clientId });
    }
    throw new AppError('unsupported_grant_type', `Desteklenmeyen grant_type: '${grantType}'`, { httpStatus: 400 });
  }

  async _exchangeAuthorizationCode({ code, redirectUri, codeVerifier, clientId }) {
    const entry = await this.authCodes.get(code);
    if (!entry) throw new AppError('invalid_grant', 'Bilinmeyen, süresi dolmuş veya zaten kullanılmış kod', { httpStatus: 400 });
    await this.authCodes.delete(code); // tek kullanımlık -- sonuç ne olursa olsun tüket

    if (entry.clientId !== clientId || entry.redirectUri !== redirectUri) {
      throw new AppError('invalid_grant', 'client_id/redirect_uri eşleşmedi', { httpStatus: 400 });
    }

    // PKCE doğrulaması: S256(code_verifier) === code_challenge (yetkilendirme kodunun
    // ÇALINSA bile başka bir client tarafından kullanılamamasını garanti eden adım).
    const computedChallenge = base64url.encode(crypto.createHash('sha256').update(codeVerifier || '').digest());
    if (computedChallenge !== entry.codeChallenge) {
      throw new AppError('invalid_grant', 'PKCE doğrulaması başarısız (code_verifier eşleşmedi)', { httpStatus: 400 });
    }

    const tokens = await this.sessionManager.issueTokensForClient({
      sessionId: entry.sessionId, clientId, scope: entry.scope,
    });
    return { ...tokens, tokenType: 'Bearer' };
  }

  // ============================================================================
  // DEVICE AUTHORIZATION GRANT (RFC 8628) -- terminal/CLI, akıllı TV gibi ekranı zengin
  // bir tarayıcı barındıramayan/URL yönlendirmesi alamayan cihazlar için. Akış:
  //   1) Cihaz (CLI) POST /oauth/device/code çağırır -> device_code (cihazda saklanır,
  //      kullanıcıya HİÇ gösterilmez) + user_code (kullanıcıya gösterilir, kısa/okunaklı)
  //      + verification_uri alır.
  //   2) Kullanıcı, BAŞKA bir cihazda (telefon/tarayıcı) verification_uri'yi açar, normal
  //      şekilde giriş yapar (zaten girişliyse SSO ile anında), user_code'u onaylar.
  //   3) Cihaz, interval saniyede bir POST /oauth/token (grant_type=...device_code) ile
  //      "onaylandı mı" diye sorar (poll) -- onaylanana kadar authorization_pending döner.
  // ============================================================================
  async startDeviceAuthorization({ clientId, scope }) {
    const client = await this.clientStore.getClient(clientId);
    if (!client) throw new AppError('invalid_client', 'Bilinmeyen client_id', { httpStatus: 400 });

    const deviceCode = base64url.encode(crypto.randomBytes(32));
    // user_code çakışması pratikte imkansıza yakın (32^8 olasılık) ama savunma amaçlı birkaç deneme.
    let userCode;
    for (let attempt = 0; attempt < 5; attempt++) {
      const candidate = generateUserCode();
      // eslint-disable-next-line no-await-in-loop
      if (!(await this.userCodes.get(candidate))) { userCode = candidate; break; }
    }
    if (!userCode) throw new AppError('server_error', 'Kod üretilemedi, tekrar deneyin', { httpStatus: 500 });

    // NOT: `expiresAt` KASITLI olarak entry'nin İÇİNDE (mutlak zaman damgası olarak)
    // tutuluyor -- store'un KENDİ TTL'i (aşağıda geniş bir tampon payı ile veriliyor)
    // sadece "en kötü ihtimalle ne zaman temizlensin" içindir. Gerçek RFC 8628 süre
    // dolumu kontrolü BU alana bakar -- aksi halde slow_down takibi için entry'yi her
    // poll'da yeniden yazmak (aşağıya bkz.) TTL'i sürekli SIFIRLAYIP cihaz kodunu
    // sınırsız uzatabilirdi.
    const expiresAt = Date.now() + DEVICE_CODE_TTL_MS;
    await this.deviceCodes.set(deviceCode, {
      clientId, scope: scope || 'openid profile', status: 'pending', userCode, expiresAt, lastPolledAt: 0,
    }, DEVICE_CODE_TTL_MS + 60_000);
    await this.userCodes.set(userCode, { deviceCode }, DEVICE_CODE_TTL_MS);

    return {
      deviceCode,
      userCode,
      verificationUri: `${this.issuer}/device`,
      verificationUriComplete: `${this.issuer}/device?user_code=${encodeURIComponent(userCode)}`,
      expiresIn: Math.floor(DEVICE_CODE_TTL_MS / 1000),
      interval: this.deviceCodePollIntervalS,
    };
  }

  /** Onay sayfası (GET /device) "hangi uygulama erişim istiyor" bilgisini göstermek için çağırır. */
  async lookupDeviceCodeByUserCode(userCode) {
    const normalized = String(userCode || '').trim().toUpperCase();
    const pointer = await this.userCodes.get(normalized);
    if (!pointer) return null;
    const entry = await this.deviceCodes.get(pointer.deviceCode);
    if (!entry) return null;
    const client = await this.clientStore.getClient(entry.clientId);
    return {
      clientName: client?.name || entry.clientId, scope: entry.scope, status: entry.status,
    };
  }

  async approveDeviceCode({ userCode, currentSession }) {
    if (!currentSession || currentSession.revoked) {
      throw new AppError('unauthenticated', 'Onaylamak için giriş yapmalısınız', { httpStatus: 401 });
    }
    const normalized = String(userCode || '').trim().toUpperCase();
    const pointer = await this.userCodes.get(normalized);
    if (!pointer) throw new AppError('invalid_user_code', 'Geçersiz ya da süresi dolmuş kod', { httpStatus: 400 });
    const entry = await this.deviceCodes.get(pointer.deviceCode);
    if (!entry) throw new AppError('invalid_user_code', 'Geçersiz ya da süresi dolmuş kod', { httpStatus: 400 });

    await this.deviceCodes.set(pointer.deviceCode, {
      ...entry, status: 'approved', userId: currentSession.userId, sessionId: currentSession.sessionId,
    }, DEVICE_CODE_TTL_MS);
    return { approved: true };
  }

  async denyDeviceCode({ userCode }) {
    const normalized = String(userCode || '').trim().toUpperCase();
    const pointer = await this.userCodes.get(normalized);
    if (pointer) {
      const entry = await this.deviceCodes.get(pointer.deviceCode);
      if (entry) await this.deviceCodes.set(pointer.deviceCode, { ...entry, status: 'denied' }, DEVICE_CODE_TTL_MS);
    }
    return { denied: true };
  }

  async _exchangeDeviceCode({ deviceCode, clientId }) {
    if (!deviceCode) throw new AppError('invalid_request', 'device_code gerekli', { httpStatus: 400 });
    const entry = await this.deviceCodes.get(deviceCode);
    if (!entry || Date.now() > entry.expiresAt) {
      if (entry) await this.deviceCodes.delete(deviceCode);
      throw new AppError('expired_token', 'Kod süresi dolmuş ya da geçersiz', { httpStatus: 400 });
    }
    if (entry.clientId !== clientId) throw new AppError('invalid_grant', 'client_id eşleşmedi', { httpStatus: 400 });

    if (entry.status === 'denied') {
      await this.deviceCodes.delete(deviceCode);
      throw new AppError('access_denied', 'Kullanıcı isteği reddetti', { httpStatus: 400 });
    }

    // RFC 8628 §3.5 'slow_down': istemci, son poll'undan bu yana en az `interval` saniye
    // GEÇMEDEN tekrar sorarsa, sunucu bunu AÇIKÇA bildirmelidir (sessizce authorization_
    // pending dönmek yerine) -- aksi halde istemciler agresif poll ederek gereksiz yük
    // bindirebilir. Son poll zamanı entry'nin İÇİNDE (paylaşılan store'da, instance'lar
    // arası tutarlı) tutuluyor.
    const now = Date.now();
    const minIntervalMs = this.deviceCodePollIntervalS * 1000;
    const tooSoon = entry.lastPolledAt && (now - entry.lastPolledAt) < minIntervalMs;
    const remainingTtlMs = Math.max(1000, entry.expiresAt - now + 60_000);
    await this.deviceCodes.set(deviceCode, { ...entry, lastPolledAt: now }, remainingTtlMs);
    if (tooSoon) {
      throw new AppError('slow_down', `Çok hızlı sorguluyorsunuz -- en az ${this.deviceCodePollIntervalS} saniyede bir deneyin`, { httpStatus: 400 });
    }

    if (entry.status === 'pending') {
      // RFC 8628: bu bir "gerçek" hata değil -- istemci `interval` saniye bekleyip
      // tekrar denemeli. Yine de standart hata gövdesi ({error: 'authorization_pending'})
      // ile taşınır.
      throw new AppError('authorization_pending', 'Kullanıcı henüz onaylamadı', { httpStatus: 400 });
    }

    // onaylandı -- tek kullanımlık, TÜKET (aynı device_code ikinci kez token almasın)
    await this.deviceCodes.delete(deviceCode);
    const tokens = await this.sessionManager.issueTokensForClient({
      sessionId: entry.sessionId, clientId, scope: entry.scope,
    });
    return { ...tokens, tokenType: 'Bearer' };
  }

  /** GET /oauth/userinfo (OIDC benzeri) -- Bearer access token ile çağrılır. */
  async userinfo({ accessToken }) {
    const { payload } = this.sessionManager.verifyAccessToken(accessToken);
    const users = this.db.collection('users');
    const user = await users.get(payload.sub);
    if (!user) throw new AppError('invalid_token', 'Token geçerli ama kullanıcı artık mevcut değil', { httpStatus: 401 });
    return {
      sub: payload.sub,
      username: user.username,
      preferred_username: user.username, // standart OIDC claim adı
      email: user.email,
      email_verified: !!user.emailVerified,
      role: user.role || 'user',
      mfa_methods: JSON.parse(user.mfaMethods || '[]'),
      cert_profiles: JSON.parse(user.certProfiles || '[]'),
    };
  }

  /**
   * RFC 7662 tarzı introspection -- relying party'lerin BACKEND'LERİ (örn. dns.fitfak.net'in
   * kendi sunucusu) bunu çağırarak "bu access token HÂLÂ geçerli mi VE arkasındaki oturum
   * iptal edilmiş mi" sorusunu, sadece yerel JWT doğrulamasının (imza+exp) kaçıracağı
   * "oturum arada iptal edildi" durumunu da yakalayacak şekilde sorabilir. client/identity-
   * client.js bu uç noktayı sarmalıyor (gRPC üzerinden).
   */
  async introspect({ token }) {
    let payload;
    try {
      ({ payload } = this.sessionManager.verifyAccessToken(token));
    } catch {
      return { active: false };
    }
    const session = await this.sessionManager.store.getSessionById(payload.sid);
    if (!session || session.revoked) return { active: false };
    return { active: true, sub: payload.sub, aud: payload.aud, scope: payload.scope, sid: payload.sid };
  }
}

// ============================================================================
// DB-tabanlı client registry -- `oauth_clients` koleksiyonu (bkz. db/schema.js).
// /admin/oauth-clients/* uç noktaları (oauth-server.js) bunu yönetir; redirect URI'ler
// dahil her şey DB'de saklanır ve admin panelinden düzenlenebilir.
// ============================================================================
function createDbClientStore(db) {
  const clients = db.collection('oauth_clients');

  function toView(row) {
    return {
      clientId: row.clientId, clientSecret: row.clientSecret, name: row.name,
      redirectUris: JSON.parse(row.redirectUris || '[]'),
      allowedScopes: JSON.parse(row.allowedScopes || '[]'),
      createdAt: Number(row.createdAt),
    };
  }

  return {
    async getClient(clientId) {
      const row = await clients.findOne('clientId', clientId);
      return row ? toView(row) : null;
    },
    async listClients() {
      const result = [];
      // eslint-disable-next-line no-restricted-syntax
      for await (const row of clients.scan()) result.push(toView(row));
      return result;
    },
    async createClient({
      clientId, clientSecret, name, redirectUris, allowedScopes,
    }) {
      if (await clients.findOne('clientId', clientId)) {
        throw new AppError('client_exists', 'Bu clientId zaten kayıtlı', { httpStatus: 409 });
      }
      await clients.insert({
        clientId,
        clientSecret,
        name: name || clientId,
        redirectUris: JSON.stringify(redirectUris || []),
        allowedScopes: JSON.stringify(allowedScopes || []),
        createdAt: BigInt(Date.now()),
      });
      return toView({
        clientId, clientSecret, name, redirectUris: JSON.stringify(redirectUris || []), allowedScopes: JSON.stringify(allowedScopes || []), createdAt: BigInt(Date.now()),
      });
    },
    async updateClient(clientId, patch) {
      const row = await clients.findOne('clientId', clientId);
      if (!row) throw new AppError('not_found', 'Client bulunamadı', { httpStatus: 404 });
      const next = {};
      if (patch.name !== undefined) next.name = patch.name;
      if (patch.redirectUris !== undefined) next.redirectUris = JSON.stringify(patch.redirectUris);
      if (patch.allowedScopes !== undefined) next.allowedScopes = JSON.stringify(patch.allowedScopes);
      if (patch.clientSecret !== undefined) next.clientSecret = patch.clientSecret;
      await clients.update(row._id, next);
      return { updated: true };
    },
    async deleteClient(clientId) {
      const row = await clients.findOne('clientId', clientId);
      if (row) await clients.delete(row._id);
      return { deleted: true };
    },
  };
}

// Testler/hızlı-demo için basit, statik (bellek-içi) client registry -- üretimde
// createDbClientStore kullanın (admin panelinden yönetilebilir).
function createStaticClientStore(clients) {
  const byId = new Map(clients.map((c) => [c.clientId, c]));
  return { async getClient(clientId) { return byId.get(clientId) || null; } };
}

module.exports = { OAuthService, createStaticClientStore, createDbClientStore };
