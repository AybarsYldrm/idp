'use strict';

const crypto = require('node:crypto');
const jwtEs256 = require('./jwt-es256');
const cookies = require('./cookies');
const base64url = require('./base64url');

const ACCESS_TOKEN_TTL_S = 10 * 60; // 10 dk -- kısa ömürlü, iptal edilemez (JWT) olduğu için kısa tutuluyor
const REFRESH_TOKEN_TTL_S = 30 * 24 * 60 * 60; // 30 gün
// Çoklu-hesap seçici (Microsoft/Google tarzı "bir hesap seçin") için: bu tarayıcıda
// AKTİF OLARAK giriş yapılmış (ama illa "şu an aktif" olmayan) tüm sessionId'lerin
// listesi. __Secure-fitfak_at/rt hangi hesabın ŞU AN aktif olduğunu taşır; bu cookie
// ise "bu tarayıcıda BAŞKA hangi hesaplar da açık" sorusuna cevap verir -- bkz.
// oauth-server.js: resolveValidAccounts / /auth/accounts / /auth/switch-account.
const ACCOUNTS_COOKIE_NAME = '__Secure-fitfak_accounts';
const ACCOUNTS_COOKIE_TTL_S = REFRESH_TOKEN_TTL_S;

// ============================================================================
// `store` ARAYÜZÜ (SessionManager, @fitfak/database'i DOĞRUDAN BİLMEZ -- bu kasıtlı bir
// ayrım: çekirdek mantık test edilebilir/taşınabilir kalsın diye. Gerçek DB'ye bağlamak
// için services/auth-service.js içindeki `createSessionStoreAdapter(db)` fonksiyonuna
// bakın; testler için test/mock-store.js basit bir in-memory uygulama sağlıyor.)
//
//   createSession({ sessionId, userId, ip, userAgent, fingerprintId, createdAt, lastSeenAt, revoked, audiences, scope })
//   getSessionById(sessionId) -> { userId, revoked, audiences?: string[], scope?, ... } | null
//   touchSession(sessionId, { lastSeenAt, ip, userAgent })
//   addAudienceToSession(sessionId, clientId) -- oturumun audiences kümesine yeni bir RP ekler
//   revokeSession(sessionId, reason)
//   listSessionsForUser(userId) -> Array<session>
//   insertRefreshToken({ hash, sessionId, audience, scope, createdAt, expiresAt, used })
//   findRefreshTokenByHash(hash) -> { sessionId, audience?, scope?, expiresAt, used } | null
//   markRefreshTokenUsed(hash, { usedAt })
// ============================================================================

class SessionError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

class SessionManager {
  constructor({ store, signingKeyPair, issuer, cookieDomain }) {
    this.store = store;
    this.privateKey = signingKeyPair.privateKey;
    this.publicKey = signingKeyPair.publicKey;
    this.kid = signingKeyPair.kid;
    this.issuer = issuer;
    this.cookieDomain = cookieDomain;
  }

  /** İlk girişte (password/WebAuthn/TOTP akışı TAMAMLANDIKTAN sonra) çağrılır: yeni bir
   * oturum kaydı + ilk token çiftini oluşturur. `audiences` başlangıçta `['self']` --
   * IdP'nin kendi session-yönetimi arayüzü için. Farklı relying party'ler (dns.fitfak.net
   * vb.) için token üretmek üzere OAuth kod değişimi sırasında `issueTokensForClient`
   * kullanılır (aşağıda) -- BİR oturum, SSO sayesinde ZAMAN İÇİNDE BİRDEN FAZLA RP için
   * token üretebilir, bu yüzden bu bir DİZİ (tek bir string değil). */
  async createSession({ userId, ip, userAgent, fingerprintId, deviceId = null, scope = 'openid profile' }) {
    const sessionId = crypto.randomUUID();
    const now = new Date();
    await this.store.createSession({
      sessionId, userId, ip, userAgent, fingerprintId, deviceId,
      createdAt: now, lastSeenAt: now, revoked: false, audiences: ['self'], scope,
    });
    const tokens = await this._issueTokenPair({ sessionId, userId, audience: 'self', scope });
    return { sessionId, userId, ...tokens };
  }

  /**
   * Aynı tarayıcıdan tekrar giriş: YENİ oturum açmak yerine var olanı tazeler.
   *
   * Önceki davranış her girişte koşulsuz yeni bir satır yaratıyordu, dolayısıyla
   * bir kullanıcının oturumlar listesi kendi tekrar girişleriyle doluyordu.
   * Bu yalnızca dağınık değil, güvenlik açısından da kötü: listede gerçekten
   * yabancı bir oturum varsa kendi gürültüsünün içinde kaybolur ve kullanıcıya
   * "hepsini kapat" dışında bir seçenek kalmaz.
   *
   * Tazeleme, oturumu YENİDEN AÇMAK değildir: iptal edilmiş bir oturum asla
   * geri getirilmez (aşağıda revoked kontrolü), yalnızca hâlâ geçerli olan bir
   * oturuma taze token verilir.
   */
  async refreshExistingSession({ sessionId, ip, userAgent, scope = 'openid profile' }) {
    const session = await this.store.getSessionById(sessionId);
    if (!session || session.revoked) {
      throw new SessionError('session_revoked', 'oturum artık aktif değil');
    }
    await this.store.touchSession(sessionId, { lastSeenAt: new Date(), ip, userAgent });
    const tokens = await this._issueTokenPair({
      sessionId, userId: session.userId, audience: 'self', scope,
    });
    return { sessionId, userId: session.userId, reused: true, ...tokens };
  }

  /** Zaten kimliği doğrulanmış (SSO çerezi geçerli) bir oturum için, belirli bir OAuth
   * client'ına (relying party) özel yeni bir token çifti üretir -- oturumun KENDİSİNİ
   * yeniden oluşturmaz, sadece o clientId/scope'a bağlı taze bir access+refresh çifti
   * verir. oauth-service.js /oauth/token (authorization_code grant) burayı çağırır. Bu
   * RP daha önce bu oturumla hiç görülmediyse, oturumun `audiences` kümesine eklenir --
   * gRPC IdentityService'in "sadece KENDİ RP'nizin oturumlarını görün/iptal edin" sınırı
   * (bkz. oauth-server.js) buna dayanıyor. */
  async issueTokensForClient({ sessionId, clientId, scope }) {
    const session = await this.store.getSessionById(sessionId);
    if (!session || session.revoked) throw new SessionError('session_revoked', 'oturum artık aktif değil');
    if (!(session.audiences || []).includes(clientId)) {
      await this.store.addAudienceToSession(sessionId, clientId);
    }
    return this._issueTokenPair({ sessionId, userId: session.userId, audience: clientId, scope });
  }

  async _issueTokenPair({ sessionId, userId, audience, scope }) {
    const accessToken = jwtEs256.sign(
      { sub: userId, iss: this.issuer, aud: audience, sid: sessionId, scope },
      this.privateKey,
      { kid: this.kid, expiresInSeconds: ACCESS_TOKEN_TTL_S },
    );

    const refreshTokenRaw = base64url.encode(crypto.randomBytes(32));
    const refreshTokenHash = sha256Hex(refreshTokenRaw);
    // `audience`/`scope` BİLEREK bu satırdaki refresh token kaydının ÜZERİNDE saklanıyor
    // (oturumun ÜZERİNDE değil): bir oturumun birden fazla RP'ye ait, PARALEL yaşayan
    // refresh-token "soy ağacı" olabilir -- her biri rotate() edildiğinde KENDİ
    // audience/scope'unu korumalı, oturumun paylaşılan tek bir alanına değil.
    await this.store.insertRefreshToken({
      hash: refreshTokenHash,
      sessionId,
      audience,
      scope,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_S * 1000),
      used: false,
    });

    // `scope` DÖNÜŞ DEĞERİNDE de taşınır.
    //
    // RFC 6749 §5.1 onu yalnızca "verilen kapsam istenenden farklıysa" zorunlu
    // kılıyor, bu yüzden eksikliği uzun süre fark edilmedi. Ama relying
    // party'nin elinde yerel bir oturum kaydı varsa, o kaydın kapsam alanını
    // güncelleyebilmesi için yanıtta bir kapsam GÖRMESİ gerekir: yoksa
    // "kapsam boş" ile "kapsam bildirilmedi" ayırt edilemez.
    //
    // fitfak-smtp tam olarak buna takılmıştı: kullanıcı `cert:issue` onayını
    // veriyor, IdP kapsamı access token'ın İÇİNE yazıyor, ama yanıtta
    // göndermediği için posta sunucusu yerel kaydına boş yazıyor ve sertifika
    // isteği "Oturumunuz cert:issue kapsamını taşımıyor" ile reddediliyordu --
    // sonsuza kadar, çünkü her yeni onay turu aynı yere varıyordu.
    return { accessToken, refreshToken: refreshTokenRaw, expiresIn: ACCESS_TOKEN_TTL_S, scope };
  }

  /** Access token'ı ES256 public key ile doğrular (stateless -- veritabanına gitmez).
   * Bir token, kendi `exp`'i dolana kadar teknik olarak geçerlidir; oturumun ARADA iptal
   * edilip edilmediğini görmek için (örn. "şüpheli oturumu hemen kapat" senaryosu)
   * services/oauth-service.js'teki introspect() -- veritabanına bakan -- kullanılmalı. */
  verifyAccessToken(token) {
    return jwtEs256.verify(token, this.publicKey);
  }

  /**
   * Refresh token ROTASYONU + YENİDEN KULLANIM (reuse) TESPİTİ.
   *
   * Standart akış: sunulan refresh token bulunur, `used=true` işaretlenir, YENİ bir
   * access+refresh çifti verilir. Eğer sunulan token DAHA ÖNCE zaten kullanılmışsa (used
   * === true) -- bu, token'ın bir yerden ÇALINDIĞININ güçlü bir işaretidir: meşru istemci
   * onu zaten bir kez kullanıp yenisini almıştı; şimdi ikinci bir taraf (saldırgan) AYNI
   * (artık eski) token'ı tekrar sunuyor. Bu durumda tüm oturumu (ve onunla ilişkili HER
   * token'ı) iptal ediyoruz -- sadece bu token'ı değil -- çünkü saldırgan zincirin
   * neresinden bir token yakaladığını bilemeyiz.
   */
  async refresh({ refreshToken, ip, userAgent }) {
    const hash = sha256Hex(refreshToken);
    const record = await this.store.findRefreshTokenByHash(hash);
    if (!record) throw new SessionError('invalid_refresh_token', 'refresh token tanınmadı');

    const session = await this.store.getSessionById(record.sessionId);
    if (!session) throw new SessionError('invalid_refresh_token', 'ilişkili oturum bulunamadı');

    if (record.used || session.revoked) {
      if (!session.revoked) {
        await this.store.revokeSession(record.sessionId, 'refresh_token_reuse_detected');
      }
      throw new SessionError('refresh_token_reuse', 'refresh token yeniden kullanımı tespit edildi; oturum iptal edildi');
    }
    if (record.expiresAt < new Date()) throw new SessionError('expired_refresh_token', 'refresh token süresi dolmuş');

    await this.store.markRefreshTokenUsed(hash, { usedAt: new Date() });
    await this.store.touchSession(record.sessionId, { lastSeenAt: new Date(), ip, userAgent });

    return this._issueTokenPair({
      sessionId: record.sessionId,
      userId: session.userId,
      audience: record.audience || 'self',
      scope: record.scope || 'openid profile',
    });
  }

  async revokeSession(sessionId, reason = 'user_requested') {
    await this.store.revokeSession(sessionId, reason);
  }

  async listSessions(userId) {
    return this.store.listSessionsForUser(userId);
  }

  buildSsoCookies({ accessToken, refreshToken }) {
    return [
      cookies.serializeCookie('__Secure-fitfak_at', accessToken, {
        domain: this.cookieDomain, path: '/', maxAgeSeconds: ACCESS_TOKEN_TTL_S,
        httpOnly: true, secure: true, sameSite: 'Lax',
      }),
      // refresh token cookie'si kasıtlı olarak dar bir path'e (`/oauth/token`) hapsedilir --
      // domain genelindeki her istekte tarayıcı tarafından gönderilmesin diye (maruz
      // kalma yüzeyini azaltma).
      cookies.serializeCookie('__Secure-fitfak_rt', refreshToken, {
        domain: this.cookieDomain, path: '/oauth/token', maxAgeSeconds: REFRESH_TOKEN_TTL_S,
        httpOnly: true, secure: true, sameSite: 'Lax',
      }),
    ];
  }

  buildLogoutCookies() {
    return [
      cookies.expireCookie('__Secure-fitfak_at', { domain: this.cookieDomain, path: '/' }),
      cookies.expireCookie('__Secure-fitfak_rt', { domain: this.cookieDomain, path: '/oauth/token' }),
    ];
  }

  buildAccountsListCookie(sessionIds) {
    return cookies.serializeCookie(ACCOUNTS_COOKIE_NAME, encodeURIComponent(JSON.stringify(sessionIds)), {
      domain: this.cookieDomain, path: '/', maxAgeSeconds: ACCOUNTS_COOKIE_TTL_S,
      httpOnly: true, secure: true, sameSite: 'Lax',
    });
  }

  expireAccountsListCookie() {
    return cookies.expireCookie(ACCOUNTS_COOKIE_NAME, { domain: this.cookieDomain, path: '/' });
  }
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

module.exports = {
  SessionManager, SessionError, ACCESS_TOKEN_TTL_S, REFRESH_TOKEN_TTL_S, ACCOUNTS_COOKIE_NAME,
};
