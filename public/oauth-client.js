'use strict';

// ============================================================================
// FitfakOAuth -- tarayıcı tarafı yardımcılar:
//   1) /auth/* ve /oauth/* uçlarına ince fetch() sarmalayıcıları (cookie'ler tarayıcı
//      tarafından OTOMATİK gönderilir/alınır -- access/refresh token'lar HttpOnly
//      olduğu için JS bunlara zaten erişemez, bu KASITLI bir güvenlik özelliğidir).
//   2) BidiBridgeClient -- core/bidi-bridge.js'in open/subscribe/send/close
//      protokolünü tüketen, tarayıcıda çalışan bir istemci (canlı oturum/güvenlik
//      olayı bildirimleri için, örn. /events/sessions).
// ============================================================================

(function initFitfakOAuth(global) {
  async function postJson(path, body) {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    return handleJsonResponse(res);
  }

  async function getJson(path) {
    const res = await fetch(path);
    return handleJsonResponse(res);
  }

  async function handleJsonResponse(res) {
    const json = await res.json().catch(() => null);
    if (!res.ok) {
      const err = new Error((json && json.error_description) || `İstek başarısız: HTTP ${res.status}`);
      err.code = json && json.error;
      err.status = res.status;
      throw err;
    }
    return json;
  }

  // ---------------------------------------------------------------------------
  // gRPC-Web-tarzı çerçeveleme -- core/http-transport.js'in encodeFrame/decodeFrames
  // ile BİT-BİT AYNI format (Node Buffer yerine DataView/Uint8Array kullanılıyor,
  // tarayıcıda Buffer yok).
  // ---------------------------------------------------------------------------
  function encodeFrame(obj) {
    const payloadBytes = new TextEncoder().encode(JSON.stringify(obj ?? null));
    const frame = new Uint8Array(5 + payloadBytes.length);
    new DataView(frame.buffer).setUint32(1, payloadBytes.length, false);
    frame.set(payloadBytes, 5);
    return frame;
  }

  function decodeFrames(buffer) {
    const frames = [];
    let offset = 0;
    while (buffer.length - offset >= 5) {
      const view = new DataView(buffer.buffer, buffer.byteOffset + offset, 5);
      const flags = view.getUint8(0);
      const len = view.getUint32(1, false);
      if (buffer.length - offset - 5 < len) break;
      const payloadBytes = buffer.subarray(offset + 5, offset + 5 + len);
      let value = null;
      try { value = JSON.parse(new TextDecoder().decode(payloadBytes)); } catch { /* bozuk çerçeve -- yoksay */ }
      frames.push({ trailer: !!(flags & 0x80), value });
      offset += 5 + len;
    }
    return { frames, rest: buffer.subarray(offset) };
  }

  function concatBytes(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  /**
   * core/bidi-bridge.js'in open/subscribe/send/close uçlarını tüketen tarayıcı
   * istemcisi. Gerçek çift-yönlü bir HTTP bağlantısı YOKTUR (tarayıcılar bunu
   * yapamaz) -- bu, ayrı iki sıradan HTTP isteğiyle (açık kalan bir GET +
   * mesaj-başına bir POST) aynı deneyimi taklit eder. Bkz. core/bidi-bridge.js
   * başlığındaki dürüstlük notu.
   *
   * KULLANIM:
   *   const bridge = new FitfakOAuth.BidiBridgeClient('/events/sessions');
   *   bridge.onMessage((msg) => console.log('sunucudan:', msg));
   *   bridge.onEnd(() => console.log('akış kapandı'));
   *   await bridge.open();
   *   await bridge.send({ type: 'subscribe_user', userId: 'u123' });
   *   // ... daha sonra:
   *   await bridge.close();
   */
  class BidiBridgeClient {
    constructor(pathPrefix) {
      this.pathPrefix = pathPrefix;
      this.bridgeSessionId = null;
      this._messageHandlers = [];
      this._endHandlers = [];
      this._errorHandlers = [];
    }

    onMessage(handler) { this._messageHandlers.push(handler); return this; }
    onEnd(handler) { this._endHandlers.push(handler); return this; }
    onError(handler) { this._errorHandlers.push(handler); return this; }

    async open() {
      const res = await fetch(`${this.pathPrefix}/open`, { method: 'POST' });
      const { bridgeSessionId } = await res.json();
      this.bridgeSessionId = bridgeSessionId;
      this._subscribe().catch((e) => this._errorHandlers.forEach((h) => h(e)));
      return bridgeSessionId;
    }

    async _subscribe() {
      const res = await fetch(`${this.pathPrefix}/subscribe?session=${this.bridgeSessionId}`);
      const reader = res.body.getReader();
      let buffer = new Uint8Array(0);
      for (;;) {
        // eslint-disable-next-line no-await-in-loop
        const { done, value } = await reader.read();
        if (done) break;
        buffer = concatBytes(buffer, value);
        const { frames, rest } = decodeFrames(buffer);
        buffer = rest;
        for (const f of frames) {
          if (f.trailer) {
            this._endHandlers.forEach((h) => h(f.value));
            return;
          }
          this._messageHandlers.forEach((h) => h(f.value));
        }
      }
    }

    async send(msg) {
      if (!this.bridgeSessionId) throw new Error('BidiBridgeClient: önce open() çağrılmalı');
      await fetch(`${this.pathPrefix}/send?session=${this.bridgeSessionId}`, { method: 'POST', body: encodeFrame(msg) });
    }

    async close() {
      if (!this.bridgeSessionId) return;
      await fetch(`${this.pathPrefix}/close?session=${this.bridgeSessionId}`, { method: 'POST' });
    }
  }

  global.FitfakOAuth = {
    // ---- kayıt / kimlik doğrulama ----
    register: (fields) => postJson('/auth/register', fields),
    resendVerificationEmail: (email) => postJson('/auth/verify-email/resend', { email }),
    confirmVerificationEmail: (email, code) => postJson('/auth/verify-email/confirm', { email, code }),
    loginWithPassword: (fields) => postJson('/auth/login/password', fields),
    completeLoginWithTotp: (mfaChallengeToken, code) => postJson('/auth/login/totp', { mfaChallengeToken, code }),
    logout: () => postJson('/auth/logout'),

    // ---- MFA kurulumu ----
    beginTotpEnrollment: (fields) => postJson('/auth/mfa/totp/begin', fields),
    finishTotpEnrollment: (fields) => postJson('/auth/mfa/totp/finish', fields),
    beginWebauthnRegistration: (fields) => postJson('/auth/webauthn/register/begin', fields),
    finishWebauthnRegistration: (fields) => postJson('/auth/webauthn/register/finish', fields),

    // ---- WebAuthn ile giriş ----
    beginWebauthnLogin: (fields) => postJson('/auth/webauthn/login/begin', fields),
    finishWebauthnLogin: (fields) => postJson('/auth/webauthn/login/finish', fields),

    // ---- oturum yönetimi ----
    listSessions: () => getJson('/auth/sessions'),
    revokeSession: (sessionId) => postJson('/auth/sessions/revoke', { sessionId }),

    // ---- çoklu hesap (Microsoft/Google tarzı hesap seçici) ----
    listAccounts: () => getJson('/auth/accounts'),
    switchAccount: (sessionId) => postJson('/auth/switch-account', { sessionId }),
    logoutAll: () => postJson('/auth/logout-all'),

    // ---- anti-bot ----
    fetchPowChallenge: () => postJson('/auth/pow-challenge'),

    // ---- device code (terminal/CLI girişi onay sayfası) ----
    getDeviceInfo: (userCode) => getJson(`/device/info?user_code=${encodeURIComponent(userCode)}`),
    approveDevice: (userCode) => postJson('/device/approve', { userCode }),
    denyDevice: (userCode) => postJson('/device/deny', { userCode }),

    // ---- canlı olaylar ----
    BidiBridgeClient,
  };
}(typeof window !== 'undefined' ? window : globalThis));
