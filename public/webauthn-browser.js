'use strict';

// ============================================================================
// FitfakWebAuthn -- tarayıcı tarafı WebAuthn/FIDO2 sarmalayıcısı.
//
// Sunucudan gelen /auth/webauthn/register/begin ve /auth/webauthn/login/begin
// yanıtları, challenge/user.id/credential id alanlarını base64url STRING olarak
// taşır (JSON'da ArrayBuffer olamayacağı için) -- navigator.credentials.create/get
// bunları GERÇEK ArrayBuffer bekler. Bu modül o dönüşümü iki yönde de yapar.
//
// KULLANIM (bkz. public/demo-login.html):
//   const beginResp = await fetch('/static/../auth/webauthn/register/begin', {...}).then(r => r.json());
//   const result = await FitfakWebAuthn.register(beginResp);
//   await fetch('/auth/webauthn/register/finish', { method: 'POST', body: JSON.stringify(result), ... });
// ============================================================================

(function initFitfakWebAuthn(global) {
  function base64urlEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function base64urlDecode(str) {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
    const binary = atob(base64 + pad);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function isSupported() {
    return typeof window !== 'undefined'
      && !!window.PublicKeyCredential
      && typeof navigator.credentials?.create === 'function'
      && typeof navigator.credentials?.get === 'function';
  }

  /**
   * `/auth/webauthn/register/begin` yanıtını alır, navigator.credentials.create()'i
   * çağırır, ve `/auth/webauthn/register/finish`'in beklediği { challengeId, credential }
   * şeklini döner.
   */
  async function register(beginResponse) {
    if (!isSupported()) throw new Error('Bu tarayıcı/cihaz WebAuthn (passkey) desteklemiyor');

    const publicKey = { ...beginResponse.publicKey };
    publicKey.challenge = base64urlDecode(publicKey.challenge);
    publicKey.user = { ...publicKey.user, id: base64urlDecode(publicKey.user.id) };
    if (Array.isArray(publicKey.excludeCredentials)) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map((c) => ({ ...c, id: base64urlDecode(c.id) }));
    }

    const credential = await navigator.credentials.create({ publicKey });
    if (!credential) throw new Error('Passkey oluşturma iptal edildi veya başarısız oldu');

    return {
      challengeId: beginResponse.challengeId,
      credential: {
        id: credential.id, // zaten base64url STRING (WebAuthn spec gereği) -- dönüşüm gerekmez
        response: {
          attestationObject: base64urlEncode(credential.response.attestationObject),
          clientDataJSON: base64urlEncode(credential.response.clientDataJSON),
        },
      },
    };
  }

  /**
   * `/auth/webauthn/login/begin` yanıtını alır, navigator.credentials.get()'i çağırır,
   * ve `/auth/webauthn/login/finish`'in beklediği { challengeId, credential } şeklini
   * döner.
   */
  async function authenticate(beginResponse) {
    if (!isSupported()) throw new Error('Bu tarayıcı/cihaz WebAuthn (passkey) desteklemiyor');

    const publicKey = { ...beginResponse.publicKey };
    publicKey.challenge = base64urlDecode(publicKey.challenge);
    if (Array.isArray(publicKey.allowCredentials)) {
      publicKey.allowCredentials = publicKey.allowCredentials.map((c) => ({ ...c, id: base64urlDecode(c.id) }));
    }

    const assertion = await navigator.credentials.get({ publicKey });
    if (!assertion) throw new Error('Passkey ile giriş iptal edildi veya başarısız oldu');

    return {
      challengeId: beginResponse.challengeId,
      credential: {
        id: assertion.id,
        response: {
          authenticatorData: base64urlEncode(assertion.response.authenticatorData),
          clientDataJSON: base64urlEncode(assertion.response.clientDataJSON),
          signature: base64urlEncode(assertion.response.signature),
        },
      },
    };
  }

  global.FitfakWebAuthn = {
    isSupported, register, authenticate, base64urlEncode, base64urlDecode,
  };
}(typeof window !== 'undefined' ? window : globalThis));
