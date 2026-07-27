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