'use strict';

// SADECE TEST içindir: gerçek bir donanım authenticator'ı/tarayıcı olmadan WebAuthn
// ceremony'lerini uçtan uca test edebilmek için node:crypto ile gerçek EC/RSA anahtarlar
// kullanan, gerçek CBOR-kodlu authenticatorData/attestationObject üreten sahte bir
// authenticator. webauthn-demo.js VE full-flow-demo.js tarafından paylaşılır.

const crypto = require('node:crypto');
const cbor = require('../core/cbor');
const base64url = require('../core/base64url');

class MockAuthenticator {
  constructor({ alg = 'ES256', rpId, origin } = {}) {
    if (!rpId) throw new Error('MockAuthenticator: rpId zorunlu');
    this.rpId = rpId;
    this.defaultOrigin = origin; // register()/authenticate() çağrılarında origin verilmezse kullanılır
    this.alg = alg;
    if (alg === 'ES256') {
      const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      this.privateKey = kp.privateKey; this.publicKey = kp.publicKey;
    } else if (alg === 'RS256') {
      const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      this.privateKey = kp.privateKey; this.publicKey = kp.publicKey;
    } else {
      throw new Error(`MockAuthenticator: bilinmeyen alg ${alg}`);
    }
    this.credentialId = crypto.randomBytes(16);
    this.signCount = 0;
  }

  _coseKeyMap() {
    if (this.alg === 'ES256') {
      const jwk = this.publicKey.export({ format: 'jwk' });
      return new Map([[1, 2], [3, -7], [-1, 1], [-2, base64url.decode(jwk.x)], [-3, base64url.decode(jwk.y)]]);
    }
    const jwk = this.publicKey.export({ format: 'jwk' });
    return new Map([[1, 3], [3, -257], [-1, base64url.decode(jwk.n)], [-2, base64url.decode(jwk.e)]]);
  }

  _buildAuthData({ withAttestedCredentialData, userVerified, signCountOverride }) {
    const rpIdHash = crypto.createHash('sha256').update(this.rpId).digest();
    const flags = 0x01 | (userVerified ? 0x04 : 0) | (withAttestedCredentialData ? 0x40 : 0);
    const signCount = Buffer.alloc(4);
    signCount.writeUInt32BE(signCountOverride !== undefined ? signCountOverride : this.signCount);
    const parts = [rpIdHash, Buffer.from([flags]), signCount];
    if (withAttestedCredentialData) {
      const aaguid = Buffer.alloc(16);
      const credIdLen = Buffer.alloc(2);
      credIdLen.writeUInt16BE(this.credentialId.length);
      parts.push(aaguid, credIdLen, this.credentialId, cbor.encode(this._coseKeyMap()));
    }
    return Buffer.concat(parts);
  }

  register({ challenge, origin, userVerified = true }) {
    const useOrigin = origin !== undefined ? origin : this.defaultOrigin;
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: base64url.encode(challenge), origin: useOrigin }));
    const authData = this._buildAuthData({ withAttestedCredentialData: true, userVerified });
    const attestationObject = cbor.encode(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    return {
      id: base64url.encode(this.credentialId),
      type: 'public-key',
      response: { clientDataJSON: base64url.encode(clientDataJSON), attestationObject: base64url.encode(attestationObject) },
    };
  }

  authenticate({ challenge, origin, userVerified = true, signCountOverride, corrupt = false }) {
    this.signCount += 1;
    const useOrigin = origin !== undefined ? origin : this.defaultOrigin;
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: base64url.encode(challenge), origin: useOrigin }));
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
    const authData = this._buildAuthData({ withAttestedCredentialData: false, userVerified, signCountOverride });
    const signedData = Buffer.concat([authData, clientDataHash]);
    const signature = crypto.sign('sha256', signedData, this.privateKey);
    if (corrupt) signature[0] ^= 0xff;
    return {
      id: base64url.encode(this.credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: base64url.encode(clientDataJSON),
        authenticatorData: base64url.encode(authData),
        signature: base64url.encode(signature),
      },
    };
  }
}

module.exports = { MockAuthenticator };
