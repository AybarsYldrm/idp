'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const { WebAuthnService } = require('../core/webauthn');
const base64url = require('../core/base64url');
const { MockAuthenticator } = require('./mock-authenticator');

const RP_ID = 'fitfak.net';
const ORIGIN = 'https://session.fitfak.net';

function runFullCycle(alg) {
  const service = new WebAuthnService({ rpId: RP_ID, rpName: 'Fitfak Kimlik', origin: ORIGIN });
  const authenticator = new MockAuthenticator({ alg, rpId: RP_ID, origin: ORIGIN });

  // ---- Kayıt (registration) ----
  const regOptions = service.createRegistrationOptions({ userId: 'u1', username: 'abuzer' });
  const regCredential = authenticator.register({ challenge: regOptions.publicKey.challenge && base64url.decode(regOptions.publicKey.challenge) });
  const regResult = service.verifyRegistration({ challengeId: regOptions.challengeId, credential: regCredential });
  assert.strictEqual(regResult.credentialId, base64url.encode(authenticator.credentialId));
  assert.strictEqual(regResult.coseAlg, alg === 'ES256' ? -7 : -257);
  assert.strictEqual(regResult.userVerified, true);
  console.log(`webauthn[${alg}]: kayıt (registration) doğrulaması OK, credentialId=${regResult.credentialId.slice(0, 12)}...`);

  const storedCredential = { publicKeyJwk: regResult.publicKeyJwk, signCount: regResult.signCount };

  // ---- Kimlik doğrulama (authentication) -- MUTLU YOL ----
  const authOptions = service.createAuthenticationOptions({ allowCredentialIds: [regResult.credentialId] });
  const authCredential = authenticator.authenticate({ challenge: base64url.decode(authOptions.publicKey.challenge) });
  const authResult = service.verifyAuthentication({ challengeId: authOptions.challengeId, credential: authCredential, storedCredential });
  assert.strictEqual(authResult.newSignCount, 1);
  storedCredential.signCount = authResult.newSignCount;
  console.log(`webauthn[${alg}]: kimlik doğrulama (authentication) OK, yeni signCount=${authResult.newSignCount}`);

  // ---- SALDIRI SENARYOLARI: hepsi reddedilmeli ----

  // 1) yanlış challenge (replay/CSRF girişimi)
  {
    const opts = service.createAuthenticationOptions({});
    const wrongChallenge = crypto.randomBytes(32); // gerçek challenge yerine rastgele
    const cred = authenticator.authenticate({ challenge: wrongChallenge });
    assert.throws(() => service.verifyAuthentication({ challengeId: opts.challengeId, credential: cred, storedCredential }), /challenge eşleşmedi/);
  }
  console.log(`webauthn[${alg}]: yanlış challenge doğru şekilde reddedildi`);

  // 2) yanlış origin (phishing sitesi simülasyonu)
  {
    const opts = service.createAuthenticationOptions({});
    const cred = authenticator.authenticate({ challenge: base64url.decode(opts.publicKey.challenge), origin: 'https://evil-phishing.example' });
    assert.throws(() => service.verifyAuthentication({ challengeId: opts.challengeId, credential: cred, storedCredential }), /origin eşleşmedi/);
  }
  console.log(`webauthn[${alg}]: yanlış origin (phishing) doğru şekilde reddedildi`);

  // 3) bozuk imza (MITM/kurcalama simülasyonu)
  {
    const opts = service.createAuthenticationOptions({});
    const cred = authenticator.authenticate({ challenge: base64url.decode(opts.publicKey.challenge), corrupt: true });
    assert.throws(() => service.verifyAuthentication({ challengeId: opts.challengeId, credential: cred, storedCredential }), /imza doğrulaması başarısız/);
  }
  console.log(`webauthn[${alg}]: bozuk imza doğru şekilde reddedildi`);

  // 4) signCount replay -- klonlanmış authenticator tespiti
  {
    const opts = service.createAuthenticationOptions({});
    // signCount'u kasıtlı olarak stored'dan DÜŞÜK/EŞİT bir değere sabitliyoruz
    const cred = authenticator.authenticate({ challenge: base64url.decode(opts.publicKey.challenge), signCountOverride: storedCredential.signCount });
    assert.throws(() => service.verifyAuthentication({ challengeId: opts.challengeId, credential: cred, storedCredential }), /klonlanmış/);
  }
  console.log(`webauthn[${alg}]: geriye gitmeyen/tekrar eden signCount (klon şüphesi) doğru şekilde reddedildi`);

  // 5) challenge tekrar kullanımı (aynı challengeId iki kez tüketilemez)
  {
    const opts = service.createAuthenticationOptions({});
    const cred = authenticator.authenticate({ challenge: base64url.decode(opts.publicKey.challenge) });
    service.verifyAuthentication({ challengeId: opts.challengeId, credential: cred, storedCredential });
    assert.throws(() => service.verifyAuthentication({ challengeId: opts.challengeId, credential: cred, storedCredential }), /bilinmeyen veya süresi dolmuş/);
  }
  console.log(`webauthn[${alg}]: challenge tek-kullanımlık (replay) kuralı doğru işliyor`);
}

function main() {
  runFullCycle('ES256');
  runFullCycle('RS256');
  console.log('\nALL WEBAUTHN CHECKS PASSED (ES256 + RS256, happy path + 5 saldırı senaryosu)');
}

main();
