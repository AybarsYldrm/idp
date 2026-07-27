'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// Basit, dosya-tabanlı anahtar kalıcılığı -- tek instance'lık kurulum/demo içindir.
//
// ÜRETİM NOTU: private key'i buradaki gibi düz dosyada tutmak yerine bir KMS/HSM/secret
// manager kullanın. Birden fazla IdP instance'ı (yatay ölçekleme) koşturuyorsanız hepsi
// AYNI private key materyaline erişebilmeli (paylaşımlı secret store) -- ya da her
// instance kendi anahtarını üretir ve JWKS'te `kid` ile ayrıştırılan BİRDEN FAZLA public
// key yayınlarsınız (kademeli rotasyon modeli). `kid` alanı tam olarak bunun için var.
function loadOrCreateSigningKeyPair(keyDir) {
  fs.mkdirSync(keyDir, { recursive: true });
  const privPath = path.join(keyDir, 'es256-private.pem');
  const pubPath = path.join(keyDir, 'es256-public.pem');
  const kidPath = path.join(keyDir, 'kid.txt');

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    const privateKey = crypto.createPrivateKey(fs.readFileSync(privPath));
    const publicKey = crypto.createPublicKey(fs.readFileSync(pubPath));
    const kid = fs.existsSync(kidPath) ? fs.readFileSync(kidPath, 'utf8').trim() : 'default';
    return { privateKey, publicKey, kid };
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const kid = crypto.randomBytes(8).toString('hex');
  fs.writeFileSync(privPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }));
  fs.writeFileSync(kidPath, kid);
  return { privateKey, publicKey, kid };
}

function publicKeyToJwks(publicKey, kid) {
  const jwk = publicKey.export({ format: 'jwk' }); // { kty:'EC', crv:'P-256', x, y }
  return { keys: [{ ...jwk, kid, use: 'sig', alg: 'ES256' }] };
}

module.exports = { loadOrCreateSigningKeyPair, publicKeyToJwks };
