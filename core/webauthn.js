'use strict';

const crypto = require('node:crypto');
const cbor = require('./cbor');
const base64url = require('./base64url');

const COSE_ALG = { ES256: -7, RS256: -257 };
const COSE_KTY = { OKP: 1, EC2: 2, RSA: 3, SYMMETRIC: 4 };
const COSE_CRV = { P256: 1 };

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

// ----------------------------------------------------------------------------
// authenticatorData ayrıştırma (WebAuthn spec §6.1)
//   rpIdHash (32) | flags (1) | signCount (4) | [varsa: attestedCredentialData] | [varsa: extensions]
// ----------------------------------------------------------------------------
function parseAuthenticatorData(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 37) throw new Error('webauthn: authData çok kısa (<37 byte)');

  const rpIdHash = buf.subarray(0, 32);
  const flagsByte = buf[32];
  const flags = {
    up: !!(flagsByte & 0x01), // User Present
    uv: !!(flagsByte & 0x04), // User Verified (biyometrik/PIN)
    at: !!(flagsByte & 0x40), // Attested credential data mevcut (sadece registration'da)
    ed: !!(flagsByte & 0x80), // Extension data mevcut
  };
  const signCount = buf.readUInt32BE(33);

  let offset = 37;
  let aaguid = null;
  let credentialId = null;
  let credentialPublicKeyJwk = null;
  let coseAlg = null;

  if (flags.at) {
    if (buf.length < offset + 18) throw new Error('webauthn: attestedCredentialData için authData çok kısa');
    aaguid = buf.subarray(offset, offset + 16); offset += 16;
    const credIdLen = buf.readUInt16BE(offset); offset += 2;
    if (buf.length < offset + credIdLen) throw new Error('webauthn: credentialId uzunluğu authData sınırını aşıyor');
    credentialId = buf.subarray(offset, offset + credIdLen); offset += credIdLen;

    const { value: coseKeyMap, bytesRead } = cbor.decode(buf.subarray(offset));
    offset += bytesRead;
    const converted = coseKeyToJwk(coseKeyMap);
    credentialPublicKeyJwk = converted.jwk;
    coseAlg = converted.alg;
  }
  // Not: flags.ed (extensions) burada ayrıştırılmıyor -- bu IdP hiçbir extension
  // çıktısına güvenmiyor. `offset` extension baytlarını içermeyebilir; bu sadece
  // authData'nın sonuna kadar tamamen tüketildiğini varsaymayan tek-geçişlik ayrıştırma
  // için önemli (imza doğrulaması zaten TÜM ham authData buffer'ı üzerinden yapılıyor,
  // offset'in tam sonunu bilmemize gerek yok).

  return { rpIdHash, flags, signCount, aaguid, credentialId, credentialPublicKeyJwk, coseAlg };
}

function coseKeyToJwk(map) {
  if (!(map instanceof Map)) throw new Error('webauthn: COSE_Key bir CBOR map olmalı');
  const kty = Number(map.get(1));
  const alg = Number(map.get(3));

  if (kty === COSE_KTY.EC2) {
    const crv = Number(map.get(-1));
    if (crv !== COSE_CRV.P256) throw new Error(`webauthn: desteklenmeyen EC2 eğrisi (${crv}); sadece P-256 destekleniyor`);
    const x = map.get(-2);
    const y = map.get(-3);
    if (!Buffer.isBuffer(x) || !Buffer.isBuffer(y)) throw new Error('webauthn: COSE EC2 anahtarında x/y eksik');
    return { jwk: { kty: 'EC', crv: 'P-256', x: base64url.encode(x), y: base64url.encode(y) }, alg };
  }
  if (kty === COSE_KTY.RSA) {
    const n = map.get(-1);
    const e = map.get(-2);
    if (!Buffer.isBuffer(n) || !Buffer.isBuffer(e)) throw new Error('webauthn: COSE RSA anahtarında n/e eksik');
    return { jwk: { kty: 'RSA', n: base64url.encode(n), e: base64url.encode(e) }, alg };
  }
  throw new Error(`webauthn: desteklenmeyen COSE key type (${kty}); sadece EC2 (P-256) ve RSA destekleniyor`);
}

function algToNodeHash(coseAlg) {
  if (coseAlg === COSE_ALG.ES256 || coseAlg === COSE_ALG.RS256) return 'sha256';
  throw new Error(`webauthn: desteklenmeyen COSE alg (${coseAlg}); sadece ES256/RS256 destekleniyor`);
}

function verifySignatureWithJwk(jwk, data, signature) {
  const keyObject = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  return crypto.verify('sha256', data, keyObject, signature);
}

class WebAuthnService {
  /**
   * @param {object} opts
   * @param {string} opts.rpId          - Relying Party ID, örn. 'fitfak.net' (SSO için üst domain;
   *                                       WebAuthn kuralı gereği rpId, origin'in eTLD+1'i ya da onun
   *                                       bir üst-domain süperseti olmalı -- 'session.fitfak.net'
   *                                       origin'inden 'fitfak.net' rpId'sine izin verilir, tersi olmaz).
   * @param {string} opts.rpName        - Kullanıcıya gösterilecek RP adı.
   * @param {string} opts.origin        - Beklenen tam origin, örn. 'https://session.fitfak.net'.
   * @param {Map}    [opts.challengeStore] - Bekleyen challenge'ların tutulduğu store (varsayılan:
   *                                       in-memory Map -- çoklu instance dağıtımda paylaşımlı bir
   *                                       store ile değiştirin, bkz. README "Ölçeklenirlik notları").
   */
  constructor({ rpId, rpName, origin, challengeStore }) {
    this.rpId = rpId;
    this.rpName = rpName;
    this.expectedOrigin = origin;
    this.challenges = challengeStore || new Map();
  }

  createRegistrationOptions({ userId, username, displayName, excludeCredentialIds = [] }) {
    const challenge = crypto.randomBytes(32);
    const challengeId = crypto.randomBytes(16).toString('hex');
    this.challenges.set(challengeId, { type: 'create', challenge, userId, expiresAt: Date.now() + 5 * 60_000 });

    return {
      challengeId,
      publicKey: {
        rp: { id: this.rpId, name: this.rpName },
        user: { id: base64url.encode(Buffer.from(String(userId))), name: username, displayName: displayName || username },
        challenge: base64url.encode(challenge),
        pubKeyCredParams: [
          { type: 'public-key', alg: COSE_ALG.ES256 },
          { type: 'public-key', alg: COSE_ALG.RS256 },
        ],
        timeout: 5 * 60_000,
        excludeCredentials: excludeCredentialIds.map((id) => ({ type: 'public-key', id })),
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
        attestation: 'none',
      },
    };
  }

  verifyRegistration({ challengeId, credential }) {
    const pending = this._consumeChallenge(challengeId, 'create');
    const clientData = this._parseAndVerifyClientData(credential.response.clientDataJSON, 'webauthn.create', pending.challenge);

    const attestationObjectBuf = base64url.decode(credential.response.attestationObject);
    const { value: attObj } = cbor.decode(attestationObjectBuf);
    const fmt = attObj.get('fmt');
    const authDataBuf = attObj.get('authData');
    const attStmt = attObj.get('attStmt');

    const authData = parseAuthenticatorData(authDataBuf);
    const expectedRpIdHash = sha256(Buffer.from(this.rpId));
    if (!crypto.timingSafeEqual(authData.rpIdHash, expectedRpIdHash)) throw new Error('webauthn: rpIdHash eşleşmedi');
    if (!authData.flags.up) throw new Error('webauthn: user presence (UP) bayrağı set değil');
    if (!authData.flags.at || !authData.credentialPublicKeyJwk) throw new Error('webauthn: attested credential data eksik');

    this._verifyAttestationStatement({ fmt, attStmt, authDataBuf, clientDataHash: clientData.hash, authData });

    return {
      credentialId: base64url.encode(authData.credentialId),
      publicKeyJwk: authData.credentialPublicKeyJwk,
      coseAlg: authData.coseAlg,
      signCount: authData.signCount,
      aaguid: authData.aaguid ? authData.aaguid.toString('hex') : null,
      userVerified: authData.flags.uv,
    };
  }

  createAuthenticationOptions({ allowCredentialIds = [], userVerification = 'preferred' } = {}) {
    const challenge = crypto.randomBytes(32);
    const challengeId = crypto.randomBytes(16).toString('hex');
    this.challenges.set(challengeId, { type: 'get', challenge, expiresAt: Date.now() + 5 * 60_000 });

    return {
      challengeId,
      publicKey: {
        rpId: this.rpId,
        challenge: base64url.encode(challenge),
        timeout: 5 * 60_000,
        userVerification,
        allowCredentials: allowCredentialIds.map((id) => ({ type: 'public-key', id })),
      },
    };
  }

  /**
   * @param {object} storedCredential - Veritabanından çekilen, daha önce kayıtta saklanan
   *   { publicKeyJwk, signCount } -- credentialId'ye göre çağıran (auth-service) tarafından
   *   önceden bulunmuş olmalı. WebAuthnService kasıtlı olarak veritabanını bilmez.
   */
  verifyAuthentication({ challengeId, credential, storedCredential }) {
    const pending = this._consumeChallenge(challengeId, 'get');
    const clientData = this._parseAndVerifyClientData(credential.response.clientDataJSON, 'webauthn.get', pending.challenge);

    const authDataBuf = base64url.decode(credential.response.authenticatorData);
    const authData = parseAuthenticatorData(authDataBuf);
    const expectedRpIdHash = sha256(Buffer.from(this.rpId));
    if (!crypto.timingSafeEqual(authData.rpIdHash, expectedRpIdHash)) throw new Error('webauthn: rpIdHash eşleşmedi');
    if (!authData.flags.up) throw new Error('webauthn: user presence (UP) bayrağı set değil');

    const signature = base64url.decode(credential.response.signature);
    const signedData = Buffer.concat([authDataBuf, clientData.hash]);
    const ok = verifySignatureWithJwk(storedCredential.publicKeyJwk, signedData, signature);
    if (!ok) throw new Error('webauthn: imza doğrulaması başarısız');

    // Klon edilmiş authenticator tespiti: signCount SADECE ileri gitmeli. İki tarafta da
    // sıfırsa (birçok platform authenticator'ı -- Touch ID/Windows Hello -- hiç saymaz)
    // karşılaştırma anlamsız, spec de bu durumda kontrolü atlamayı öneriyor.
    if (storedCredential.signCount > 0 && authData.signCount > 0 && authData.signCount <= storedCredential.signCount) {
      throw new Error('webauthn: signCount ilerlemedi (olası klonlanmış authenticator)');
    }

    return { newSignCount: authData.signCount, userVerified: authData.flags.uv };
  }

  _verifyAttestationStatement({ fmt, attStmt, authDataBuf, clientDataHash, authData }) {
    if (fmt === 'none') return; // en yaygın durum: gizlilik için authenticator marka/modeli ifşa edilmiyor

    if (fmt === 'packed') {
      const alg = Number(attStmt.get('alg'));
      const sig = attStmt.get('sig');
      const signedData = Buffer.concat([authDataBuf, clientDataHash]);
      const x5c = attStmt.get('x5c');

      if (x5c && x5c.length > 0) {
        // Tam (full) attestation: imza, attestation sertifikasının anahtarıyla doğrulanır.
        // NOT: sertifika ZİNCİRİ bir kök otoriteye (FIDO Metadata Service) karşı
        // DOĞRULANMIYOR -- bkz. README "Kapsam ve sınırlamalar". Bu, sadece imzanın
        // yapısal olarak geçerli olduğunu kanıtlar, authenticator'ın gerçekliğini değil.
        const cert = new crypto.X509Certificate(x5c[0]);
        const ok = crypto.verify(algToNodeHash(alg), signedData, cert.publicKey, sig);
        if (!ok) throw new Error('webauthn: packed attestation imzası geçersiz (x5c)');
        return;
      }
      // Self-attestation: imza doğrudan credential'ın kendi (az önce çıkarılan) public
      // key'i ile doğrulanır.
      const ok = verifySignatureWithJwk(authData.credentialPublicKeyJwk, signedData, sig);
      if (!ok) throw new Error('webauthn: self-attestation imzası geçersiz');
      return;
    }

    throw new Error(`webauthn: desteklenmeyen attestation format '${fmt}' (desteklenen: none, packed)`);
  }

  _parseAndVerifyClientData(clientDataJsonB64, expectedType, expectedChallenge) {
    const buf = base64url.decode(clientDataJsonB64);
    let clientData;
    try {
      clientData = JSON.parse(buf.toString('utf8'));
    } catch {
      throw new Error('webauthn: clientDataJSON JSON olarak çözülemedi');
    }
    if (clientData.type !== expectedType) throw new Error(`webauthn: beklenmeyen clientData.type '${clientData.type}'`);
    const gotChallenge = base64url.decode(clientData.challenge);
    if (gotChallenge.length !== expectedChallenge.length || !crypto.timingSafeEqual(gotChallenge, expectedChallenge)) {
      throw new Error('webauthn: challenge eşleşmedi');
    }
    if (clientData.origin !== this.expectedOrigin) throw new Error(`webauthn: origin eşleşmedi ('${clientData.origin}')`);
    return { clientData, hash: sha256(buf) };
  }

  _consumeChallenge(challengeId, expectedType) {
    const pending = this.challenges.get(challengeId);
    if (!pending) throw new Error('webauthn: bilinmeyen veya süresi dolmuş challenge');
    this.challenges.delete(challengeId); // tek kullanımlık -- sonuç ne olursa olsun tüket
    if (pending.type !== expectedType) throw new Error('webauthn: challenge tipi eşleşmedi');
    if (Date.now() > pending.expiresAt) throw new Error('webauthn: challenge süresi dolmuş');
    return pending;
  }
}

module.exports = { WebAuthnService, parseAuthenticatorData, coseKeyToJwk, COSE_ALG };
