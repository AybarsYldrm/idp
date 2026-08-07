'use strict';

const crypto = require('node:crypto');
const { AppError } = require('../core/errors');
const base64url = require('../core/base64url');
const { InMemoryEphemeralStore } = require('../core/ephemeral-store');
const consent = require('./consent-service');
const redirects = require('../core/oauth-redirect');

const AUTH_CODE_TTL_MS = 60 * 1000; // yetkilendirme kodu kısacık ömürlü ve tek kullanımlık olmalı
const DEVICE_CODE_TTL_MS = 10 * 60 * 1000; // RFC 8628 önerisi: birkaç dakika

// Cihaz akışının "bağlantı" tutamağı. verification_uri_complete'in içinde
// kullanıcı kodu yerine bu duruyor; ilk açılışta tüketilir. Kısa, çünkü tek
// işlevi kullanıcıyı QR koddan sayfaya taşımak.
const DEVICE_LINK_TTL_MS = 10 * 60 * 1000;

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
    sessionManager, clientStore, db, issuer, authCodeStore, deviceCodeStore, userCodeStore,
    deviceLinkStore, deviceCodePollIntervalS,
  }) {
    this.sessionManager = sessionManager;
    this.clientStore = clientStore;
    this.db = db;
    this.issuer = issuer;
    this.authCodes = authCodeStore || new InMemoryEphemeralStore();
    this.deviceCodes = deviceCodeStore || new InMemoryEphemeralStore();
    this.userCodes = userCodeStore || new InMemoryEphemeralStore();
    this.deviceLinks = deviceLinkStore || new InMemoryEphemeralStore();
    this.deviceCodePollIntervalS = deviceCodePollIntervalS || 5;
  }

  /**
   * Yetkilendirme isteğinin işaret ettiği KAYITLI yönlendirme adresini bulur.
   *
   * İki giriş biçimi kabul edilir ve ikisi de aynı kayda çözülmek zorundadır:
   *
   *   ru=<tutamak>      bu dağıtımın tercih ettiği biçim. Kayıtlı olmayan bir
   *                     adres istekte GÖRÜNEMEZ, dolayısıyla "kayıtlı mı"
   *                     kontrolü bir if bloğu değil, aramanın başarısız olması.
   *   redirect_uri=<url> RFC 6749 §4.1.1'in istediği biçim. Standart istemciler
   *                     bunu gönderir ve göndermek zorundadır, o yüzden
   *                     desteklenmemesi seçenek değil.
   *
   * İkisi birden geldiğinde ve AYNI kaydı göstermediklerinde istek reddedilir.
   * Birini kabul edip diğerini yok saymak, iki alandan hangisinin geçerli
   * olduğunu istemcinin değil sunucunun bildiği bir belirsizlik yaratır -- ve
   * bu tür belirsizlikler, iki bileşenin farklı alanı okuduğu her yerde bir
   * atlatma yoludur.
   */
  async _resolveRedirect({ client, redirectUri, redirectHandle }) {
    if (!redirectUri && !redirectHandle) {
      throw new AppError('invalid_request',
        'redirect_uri ya da ru (kayıtlı yönlendirme tutamağı) gerekli', { httpStatus: 400 });
    }

    const byHandle = redirectHandle
      ? await this.clientStore.resolveRedirectHandle(client.clientId, redirectHandle)
      : null;
    if (redirectHandle && !byHandle) {
      throw new AppError('invalid_request', 'Bilinmeyen yönlendirme tutamağı', { httpStatus: 400 });
    }

    const byUri = redirectUri
      ? await this.clientStore.resolveRedirectUri(client.clientId, redirectUri)
      : null;
    if (redirectUri && !byUri) {
      throw new AppError('invalid_request', 'redirect_uri bu client için kayıtlı değil', { httpStatus: 400 });
    }

    if (byHandle && byUri && byHandle.handle !== byUri.handle) {
      throw new AppError('invalid_request',
        'redirect_uri ve ru farklı kayıtları gösteriyor', { httpStatus: 400 });
    }
    return byHandle || byUri;
  }

  /**
   * GET /oauth/authorize mantığı. `currentSession` -- Domain=.fitfak.net SSO cookie'sinden
   * çözülmüş, HÂLİHAZIRDA doğrulanmış oturum (varsa) -- transport katmanı (oauth-server.js)
   * tarafından buraya geçirilir. Geçerli bir oturum VE verilmiş bir izin varsa
   * kullanıcıya hiçbir form gösterilmeden yetkilendirme kodu üretilir -- SSO'nun
   * "sihirli" kısmı tam olarak burasıdır. Ama izin YOKSA bu sihir, kullanıcıya
   * sorulmadan hesabının paylaşılması anlamına gelirdi; o yüzden onay ekranı
   * (services/consent-service.js) araya girer.
   *
   * Dönüş: { requiresLogin } | { requiresConsent, client, scopes } |
   *        { redirectTo } | { errorRedirect }
   */
  async authorize({
    clientId, redirectUri, redirectHandle, responseType, scope, state,
    codeChallenge, codeChallengeMethod, currentSession, prompt, consentGranted,
  }) {
    const client = await this.clientStore.getClient(clientId);
    if (!client) throw new AppError('invalid_client', 'Bilinmeyen client_id', { httpStatus: 400 });

    const registered = await this._resolveRedirect({ client, redirectUri, redirectHandle });
    const resolvedRedirectUri = registered.redirectUri;

    // BURADAN İTİBAREN yönlendirme adresi doğrulanmıştır ve hatalar client'a GERİ
    // YÖNLENDİRİLİR (RFC 6749 §4.1.2.1). Doğrulanmamış bir adrese hata yollamak,
    // IdP'yi açık yönlendirme aracına çevirirdi -- o yüzden yukarıdaki kontroller
    // hâlâ 400 döner, aşağıdakiler dönmez.
    const fail = (error, description) => ({
      errorRedirect: this._errorRedirect({ redirectUri: resolvedRedirectUri, state, error, description }),
    });

    if (responseType !== 'code') return fail('unsupported_response_type', 'sadece response_type=code destekleniyor');
    if (codeChallengeMethod !== 'S256' || !codeChallenge) {
      return fail('invalid_request', 'PKCE (code_challenge_method=S256) zorunludur');
    }

    let scopes;
    try {
      scopes = consent.resolveRequestedScopes({ requested: scope, client });
    } catch (err) {
      return fail('invalid_scope', err.message);
    }

    const prompts = new Set(String(prompt || '').split(/\s+/).filter(Boolean));
    // prompt=none: "kullanıcıya HİÇBİR şey gösterme". Sessiz yenileme için var
    // (gizli iframe). Gösterilecek bir şey varsa hata döner ki client, kullanıcıyı
    // görünür bir sekmede yeniden denemeye yönlendirebilsin (OIDC Core §3.1.2.6).
    const silent = prompts.has('none');
    if (silent && (prompts.has('login') || prompts.has('consent') || prompts.has('select_account'))) {
      return fail('invalid_request', "prompt=none başka bir prompt değeriyle birlikte kullanılamaz");
    }

    if (!currentSession || currentSession.revoked || prompts.has('login')) {
      if (silent) return fail('login_required', 'Oturum yok');
      return { requiresLogin: true };
    }

    const mustAsk = prompts.has('consent') || await consent.needsConsent({
      db: this.db, userId: currentSession.userId, client, scopes,
    });
    if (mustAsk && !consentGranted) {
      if (silent) return fail('consent_required', 'Kullanıcı onayı gerekli');
      return { requiresConsent: true, client, scopes };
    }

    // İzin taze de olsa eski de olsa, kullanımı kaydediyoruz: "bu uygulama en
    // son ne zaman hesabıma eriştil" sorusunun cevabı buradan geliyor.
    await consent.touchGrant({ db: this.db, userId: currentSession.userId, clientId });

    const { code, lookupKey } = redirects.issueAuthorizationCode({
      clientId, redirectHandle: registered.handle,
    });
    // Depoda `redirectHandle` saklanıyor, tam adres değil: jeton değişiminde
    // karşılaştırılan şey artık iki metin değil iki kayıt referansı, ve aynı
    // adresin iki farklı yazımı (sondaki eğik çizgi, port, harf büyüklüğü)
    // eşleşmeyi bozamaz.
    await this.authCodes.set(lookupKey, {
      clientId,
      redirectHandle: registered.handle,
      redirectUri: resolvedRedirectUri,
      codeChallenge,
      scope: consent.formatScope(scopes),
      userId: currentSession.userId,
      sessionId: currentSession.sessionId,
      used: false,
    }, AUTH_CODE_TTL_MS);

    await this.clientStore.touchRedirectUri(registered.handle);

    const redirectUrl = new URL(resolvedRedirectUri);
    redirectUrl.searchParams.set('code', code);
    if (state) redirectUrl.searchParams.set('state', state);
    return { redirectTo: redirectUrl.toString() };
  }

  _errorRedirect({ redirectUri, state, error, description }) {
    const url = new URL(redirectUri);
    url.searchParams.set('error', error);
    if (description) url.searchParams.set('error_description', description);
    if (state) url.searchParams.set('state', state);
    return url.toString();
  }

  /** POST /oauth/token -- authorization_code (PKCE), refresh_token ve device_code grant'lerini yönetir. */
  async token({
    grantType, code, redirectUri, redirectHandle, codeVerifier, clientId, refreshToken,
    ip, userAgent, deviceCode,
  }) {
    if (grantType === 'authorization_code') {
      return this._exchangeAuthorizationCode({ code, redirectUri, redirectHandle, codeVerifier, clientId });
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

  async _exchangeAuthorizationCode({ code, redirectUri, redirectHandle, codeVerifier, clientId }) {
    // Biçimsel olarak bozuk ya da BAŞKA bir istemciye ait olduğu kodun kendisinden
    // görülebilen istekler depoya hiç gitmez. Reddedilme mesajı, depodan dönen
    // "bilinmeyen kod" ile AYNI: hangi aşamada reddedildiğini söylemek, bir
    // saldırgana kodun neresinin yanlış olduğunu öğretir.
    const invalidGrant = () => new AppError('invalid_grant',
      'Bilinmeyen, süresi dolmuş veya zaten kullanılmış kod', { httpStatus: 400 });

    const parsed = redirects.parseAuthorizationCode(code, { clientId });
    if (!parsed) throw invalidGrant();

    const entry = await this.authCodes.get(parsed.lookupKey);
    if (!entry) throw invalidGrant();
    await this.authCodes.delete(parsed.lookupKey); // tek kullanımlık -- sonuç ne olursa olsun tüket

    if (entry.clientId !== clientId) throw invalidGrant();

    // RFC 6749 §4.1.3: redirect_uri yetkilendirme isteğindekiyle aynı olmalı.
    // Karşılaştırma artık iki metin arasında değil, iki kayıt referansı arasında:
    // aynı adresin sondaki eğik çizgiyle ya da açık portla yazılmış hâli
    // eşleşmeyi bozamaz. Standart istemciler adresi gönderir, bu dağıtımın
    // istemcileri tutamağı; ikisi de kabul edilir.
    if (redirectHandle && redirectHandle !== entry.redirectHandle) {
      throw new AppError('invalid_grant', 'redirect_uri eşleşmedi', { httpStatus: 400 });
    }
    if (redirectUri) {
      const registered = await this.clientStore.resolveRedirectUri(clientId, redirectUri);
      if (!registered || registered.handle !== entry.redirectHandle) {
        throw new AppError('invalid_grant', 'redirect_uri eşleşmedi', { httpStatus: 400 });
      }
    }
    if (!redirectUri && !redirectHandle) {
      throw new AppError('invalid_request', 'redirect_uri ya da ru gerekli', { httpStatus: 400 });
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
    // Kapsam BURADA doğrulanıyor, onay ekranında değil: cihaz akışında
    // kullanıcı ile cihaz farklı yerlerde: cihaz yetkisi olmayan bir kapsam
    // istediyse, kullanıcının ekranında ona onaylatılacak bir şey çıkmadan
    // önce reddedilmeli.
    const scopes = consent.resolveRequestedScopes({ requested: scope, client });

    const expiresAt = Date.now() + DEVICE_CODE_TTL_MS;
    await this.deviceCodes.set(deviceCode, {
      clientId, scope: consent.formatScope(scopes), status: 'pending', userCode, expiresAt, lastPolledAt: 0,
    }, DEVICE_CODE_TTL_MS + 60_000);
    await this.userCodes.set(userCode, { deviceCode }, DEVICE_CODE_TTL_MS);

    // verification_uri_complete artık kullanıcı kodunu TAŞIMIYOR.
    //
    // RFC 8628 §3.3.1 bu alanı kullanıcının kodu elle yazmasını gerektirmesin
    // diye tanımlar -- tipik olarak bir QR kodun içine konur. Ama kodu adresin
    // içine koymak onu adres çubuğuna, tarayıcı geçmişine, yönlendiren
    // (Referer) başlığına ve omzunuzun üzerinden bakan herkese koyar; ve o kod,
    // onaylandığı anda bir oturuma dönüşecek olan şeydir.
    //
    // Bunun yerine tek kullanımlık, opak bir bağlantı tutamağı üretiliyor.
    // /device/link/<tutamak> ilk açılışta TÜKETİLİR: sunucu kodu kısa ömürlü,
    // HttpOnly bir çereze koyar ve sorgu dizesi olmayan /device'a yönlendirir.
    // QR akışı bozulmaz, ama sızan bir adres ikinci kez işe yaramaz.
    const linkToken = base64url.encode(crypto.randomBytes(32));
    await this.deviceLinks.set(linkToken, { userCode }, DEVICE_LINK_TTL_MS);

    return {
      deviceCode,
      userCode,
      verificationUri: `${this.issuer}/device`,
      verificationUriComplete: `${this.issuer}/device/link/${linkToken}`,
      expiresIn: Math.floor(DEVICE_CODE_TTL_MS / 1000),
      interval: this.deviceCodePollIntervalS,
    };
  }

  /**
   * Bir bağlantı tutamağını tüketir ve arkasındaki kullanıcı kodunu döner.
   *
   * Tek kullanımlık: ikinci çağrı `null` döner. Tarayıcı geçmişinde ya da bir
   * ekran görüntüsünde kalan adres, kullanıcı onu bir kez açtıktan sonra hiçbir
   * işe yaramaz.
   */
  async consumeDeviceLink(linkToken) {
    const entry = await this.deviceLinks.get(linkToken);
    if (!entry) return null;
    await this.deviceLinks.delete(linkToken);
    // Kod hâlâ geçerli mi? Tutamak yaşıyor ama arkasındaki cihaz kodu süresi
    // dolmuş olabilir; kullanıcıyı çalışmayacak bir onay ekranına göndermek
    // yerine burada anlaşılır bir şekilde bitirmek daha iyi.
    const pointer = await this.userCodes.get(entry.userCode);
    return pointer ? entry.userCode : null;
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
      // Onay ekranı ham kapsam adlarını değil ne anlama geldiklerini gösterebilsin.
      scopes: consent.parseScope(entry.scope).map(consent.describeScope),
    };
  }

  /**
   * Cihaz kodunun kullanıcı tarafından onaylanması. Bu ekranın KENDİSİ onay
   * anıdır -- kullanıcı burada hangi uygulamaya ne verdiğini görür -- o yüzden
   * ayrı bir /consent turu yok, ama izin aynı yere kaydedilir: /profile'daki
   * "bağlı uygulamalar" listesi cihaz akışıyla verilen izinleri de göstermeli.
   */
  async approveDeviceCode({ userCode, currentSession }) {
    if (!currentSession || currentSession.revoked) {
      throw new AppError('unauthenticated', 'Onaylamak için giriş yapmalısınız', { httpStatus: 401 });
    }
    const normalized = String(userCode || '').trim().toUpperCase();
    const pointer = await this.userCodes.get(normalized);
    if (!pointer) throw new AppError('invalid_user_code', 'Geçersiz ya da süresi dolmuş kod', { httpStatus: 400 });
    const entry = await this.deviceCodes.get(pointer.deviceCode);
    if (!entry) throw new AppError('invalid_user_code', 'Geçersiz ya da süresi dolmuş kod', { httpStatus: 400 });

    await consent.saveGrant({
      db: this.db, userId: currentSession.userId, clientId: entry.clientId,
      scopes: consent.parseScope(entry.scope),
    });

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
function createDbClientStore(db, { handleSecret, allowInsecureLocalhost = false } = {}) {
  if (!handleSecret || handleSecret.length < 32) {
    throw new Error('[fitfak-idp] createDbClientStore: yönlendirme tutamaklarını türetmek için en az '
      + '32 baytlık bir handleSecret gerekli');
  }
  const clients = db.collection('oauth_clients');
  const redirectRows = db.collection('oauth_redirect_uris');

  function toView(row, redirectUris = []) {
    return {
      clientId: row.clientId, clientSecret: row.clientSecret, name: row.name,
      // Adresler artık kendi tablosunda. `oauth_clients.redirectUris` sütunu
      // yalnızca eski kayıtlar için okunuyor: yeni yazma yolları oraya bir şey
      // koymaz, çünkü iki yerde tutulan bir liste, ikisinin ayrışmasıyla biten
      // bir listedir.
      redirectUris: redirectUris.length ? redirectUris.map((r) => r.redirectUri) : JSON.parse(row.redirectUris || '[]'),
      redirects: redirectUris,
      allowedScopes: JSON.parse(row.allowedScopes || '[]'),
      // Onay ekranını atlama hakkı. Kayıt sırasında client'ın KENDİSİ
      // tarafından belirlenemez -- yalnızca admin verir.
      firstParty: !!row.firstParty,
      clientUri: row.clientUri || '',
      createdAt: Number(row.createdAt),
    };
  }

  function redirectView(row) {
    return {
      handle: row.handle,
      redirectUri: row.redirectUri,
      label: row.label || '',
      createdAt: Number(row.createdAt),
      lastUsedAt: Number(row.lastUsedAt) || null,
      disabled: !!row.disabled,
    };
  }

  async function listRedirects(clientId) {
    const rows = await redirectRows.find('clientId', clientId);
    return rows.filter((row) => !row.disabled).map(redirectView);
  }

  async function addRedirect(clientId, value, label = '') {
    const redirectUri = redirects.validateRedirectUri(value, { allowInsecureLocalhost });
    const key = redirects.clientUriKey(clientId, redirectUri);
    const existing = await redirectRows.findOne('clientUriKey', key);
    if (existing) {
      // Zaten kayıtlıysa aynı tutamak döner. İkinci bir kayıt oluşturmak, aynı
      // adresin iki tutamağı olması demek olurdu -- ve birini iptal etmek
      // diğerini bırakırdı.
      if (existing.disabled) await redirectRows.update(existing._id, { disabled: false });
      return redirectView(existing);
    }
    const row = {
      handle: redirects.deriveHandle({ clientId, redirectUri, secret: handleSecret }),
      clientId,
      redirectUri,
      clientUriKey: key,
      label: label || '',
      createdAt: BigInt(Date.now()),
      lastUsedAt: BigInt(0),
      disabled: false,
    };
    await redirectRows.insert(row);
    return redirectView(row);
  }

  return {
    async getClient(clientId) {
      const row = await clients.findOne('clientId', clientId);
      if (!row) return null;
      return toView(row, await listRedirects(clientId));
    },
    async listClients() {
      const result = [];
      // eslint-disable-next-line no-restricted-syntax
      for await (const row of clients.scan()) {
        result.push(toView(row, await listRedirects(row.clientId)));
      }
      return result;
    },

    // ---- yönlendirme adresleri ---------------------------------------------------------------

    listRedirectUris: listRedirects,
    addRedirectUri: addRedirect,

    /** Tutamaktan kayda. Başka bir istemcinin tutamağı bu istemci için çözülmez. */
    async resolveRedirectHandle(clientId, handle) {
      const row = await redirectRows.findOne('handle', String(handle || ''));
      if (!row || row.disabled || row.clientId !== clientId) return null;
      return redirectView(row);
    },

    /** Tam adresten kayda -- RFC 6749 uyumlu istemciler için. */
    async resolveRedirectUri(clientId, value) {
      let normalized;
      // Doğrulama burada da çalışıyor, çünkü gelen değer istemcinin YAZDIĞI bir
      // metin: normalleştirilmemiş bir adres, kayıtlı olanla eşleşmeyip
      // geçersiz sayılmalı -- ham metinle karşılaştırılıp kabul edilmemeli.
      try { normalized = redirects.validateRedirectUri(value, { allowInsecureLocalhost }); }
      catch (_) { return null; }
      const row = await redirectRows.findOne('clientUriKey', redirects.clientUriKey(clientId, normalized));
      if (!row || row.disabled) return null;
      return redirectView(row);
    },

    async touchRedirectUri(handle) {
      const row = await redirectRows.findOne('handle', String(handle || ''));
      if (row) await redirectRows.update(row._id, { lastUsedAt: BigInt(Date.now()) });
    },

    async removeRedirectUri(clientId, handle) {
      const row = await redirectRows.findOne('handle', String(handle || ''));
      if (!row || row.clientId !== clientId) {
        throw new AppError('not_found', 'Yönlendirme adresi bulunamadı', { httpStatus: 404 });
      }
      // Silmek yerine devre dışı bırakmak: aynı adres yeniden eklenirse aynı
      // tutamağı almalı, yoksa dışarıda dağıtılmış yapılandırmalar sessizce kırılır.
      await redirectRows.update(row._id, { disabled: true });
      return { removed: true };
    },

    // ---- istemciler ---------------------------------------------------------------------------

    async createClient({
      clientId, clientSecret, name, redirectUris, allowedScopes, firstParty, clientUri,
    }) {
      if (await clients.findOne('clientId', clientId)) {
        throw new AppError('client_exists', 'Bu clientId zaten kayıtlı', { httpStatus: 409 });
      }
      // Adresler İSTEMCİ KAYDINDAN ÖNCE doğrulanır. Sonra doğrulamak, geçersiz
      // bir adres yüzünden reddedilen bir kayıttan geriye yönlendirme adresi
      // olmayan yarım bir istemci bırakırdı.
      const validated = (redirectUris || []).map((value) => redirects.validateRedirectUri(value, { allowInsecureLocalhost }));
      if (validated.length === 0) {
        throw new AppError('invalid_request',
          'En az bir yönlendirme adresi gerekli: yönlendirme adresi olmayan bir istemci '
          + 'yetkilendirme kodu alamaz', { httpStatus: 400 });
      }

      const row = {
        clientId,
        clientSecret,
        name: name || clientId,
        redirectUris: '[]',
        allowedScopes: JSON.stringify(allowedScopes || []),
        firstParty: !!firstParty,
        clientUri: clientUri || '',
        createdAt: BigInt(Date.now()),
      };
      await clients.insert(row);
      const created = [];
      for (const value of validated) created.push(await addRedirect(clientId, value));
      return toView(row, created);
    },

    async updateClient(clientId, patch) {
      const row = await clients.findOne('clientId', clientId);
      if (!row) throw new AppError('not_found', 'Client bulunamadı', { httpStatus: 404 });
      const next = {};
      if (patch.name !== undefined) next.name = patch.name;
      if (patch.allowedScopes !== undefined) next.allowedScopes = JSON.stringify(patch.allowedScopes);
      if (patch.clientSecret !== undefined) next.clientSecret = patch.clientSecret;
      if (patch.firstParty !== undefined) next.firstParty = !!patch.firstParty;
      if (patch.clientUri !== undefined) next.clientUri = String(patch.clientUri || '');
      await clients.update(row._id, next);

      // Adresler ayrı uçlardan yönetiliyor (addRedirectUri/removeRedirectUri).
      // Toplu değiştirmeye izin vermek, bir listeyi yanlışlıkla boşaltan tek bir
      // PATCH'in bir uygulamanın girişini tamamen kapatmasına yol açardı.
      if (patch.redirectUris !== undefined) {
        throw new AppError('invalid_request',
          'Yönlendirme adresleri /admin/oauth-clients/redirects uçlarından tek tek yönetilir',
          { httpStatus: 400 });
      }
      return { updated: true };
    },

    async deleteClient(clientId) {
      const row = await clients.findOne('clientId', clientId);
      if (row) await clients.delete(row._id);
      for (const redirect of await redirectRows.find('clientId', clientId)) {
        await redirectRows.delete(redirect._id);
      }
      return { deleted: true };
    },
  };
}

// Testler/hızlı-demo için basit, statik (bellek-içi) client registry -- üretimde
// createDbClientStore kullanın (admin panelinden yönetilebilir).
//
// Yönlendirme tutamakları burada da üretiliyor. Testlerde adresleri düz metin
// karşılaştırmakla yetinmek, üretimde çalışan yolun (tutamak araması) testlerde
// hiç çalışmaması demek olurdu -- ve bu, bir test sahtesinin gerçekten daha
// güvenli olduğu her durumun kaynağıdır.
function createStaticClientStore(clients, { handleSecret = Buffer.alloc(32, 1), allowInsecureLocalhost = true } = {}) {
  const byId = new Map();
  const byHandle = new Map();
  const byUri = new Map();

  for (const client of clients) {
    const entries = (client.redirectUris || []).map((value) => {
      const redirectUri = redirects.validateRedirectUri(value, { allowInsecureLocalhost });
      const entry = {
        handle: redirects.deriveHandle({ clientId: client.clientId, redirectUri, secret: handleSecret }),
        redirectUri,
        label: '',
        createdAt: Date.now(),
        lastUsedAt: null,
        disabled: false,
      };
      byHandle.set(`${client.clientId}|${entry.handle}`, entry);
      byUri.set(`${client.clientId}|${redirectUri}`, entry);
      return entry;
    });
    byId.set(client.clientId, { ...client, redirects: entries });
  }

  return {
    async getClient(clientId) { return byId.get(clientId) || null; },
    async listRedirectUris(clientId) { return byId.get(clientId)?.redirects || []; },
    async resolveRedirectHandle(clientId, handle) { return byHandle.get(`${clientId}|${handle}`) || null; },
    async resolveRedirectUri(clientId, value) {
      let normalized;
      try { normalized = redirects.validateRedirectUri(value, { allowInsecureLocalhost }); }
      catch (_) { return null; }
      return byUri.get(`${clientId}|${normalized}`) || null;
    },
    async touchRedirectUri() { /* statik depoda kullanım izlenmiyor */ },
  };
}

module.exports = { OAuthService, createStaticClientStore, createDbClientStore };
