'use strict';

const crypto = require('node:crypto');
const http = require('node:http');
const { generateCSR } = require('@fitfak/ssl/src/pki');
const { OIDs } = require('@fitfak/ssl/src/asn1');

// ACME Sunucun
const DIRECTORY_URL = 'https://trust.fitfak.net/acme/directory';
const DOMAIN = 'test.intranet.fitfak.net';
const CHALLENGE_PORT = 80; // ACME sunucusunun dışarıdan isteği atacağı port

// Base64Url Yardımcıları
const b64u = (buf) => (Buffer.isBuffer(buf) ? buf : Buffer.from(buf))
  .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

const b64uObj = (obj) => b64u(JSON.stringify(obj));

class CustomAcmeClient {
  constructor(directoryUrl) {
    this.directoryUrl = directoryUrl;
    this.nonce = null;
    this.kid = null; // Account URL'si
    this.endpoints = {};
    
    // ACME Hesabı için P-256 (ES256) Anahtar Çifti
    this.accountKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    this.jwk = this.accountKey.publicKey.export({ format: 'jwk' });
    delete this.jwk.ext;
    delete this.jwk.key_ops;
  }

  async init() {
    console.log('[ACME] Dizin (Directory) alınıyor...');
    const res = await fetch(this.directoryUrl);
    this.endpoints = await res.json();
    
    const nonceRes = await fetch(this.endpoints.newNonce, { method: 'HEAD' });
    this.nonce = nonceRes.headers.get('replay-nonce');
  }

  async signedRequest(url, payload) {
    const protectedHeader = {
      alg: 'ES256',
      nonce: this.nonce,
      url: url
    };

    if (this.kid) {
      protectedHeader.kid = this.kid;
    } else {
      protectedHeader.jwk = this.jwk;
    }

    const protectedB64 = b64uObj(protectedHeader);
    const payloadB64 = payload === '' ? '' : b64uObj(payload);
    
    const signData = Buffer.from(`${protectedB64}.${payloadB64}`);
    const signature = crypto.sign('SHA256', signData, { 
      key: this.accountKey.privateKey, 
      dsaEncoding: 'ieee-p1363'
    });

    const body = JSON.stringify({
      protected: protectedB64,
      payload: payloadB64,
      signature: b64u(signature)
    });

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/jose+json' },
      body: body
    });

    this.nonce = res.headers.get('replay-nonce') || this.nonce;

    const isJson = (res.headers.get('content-type') || '').includes('json');
    const data = isJson ? await res.json() : await res.text();
    
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${JSON.stringify(data)}`);
    return { data, headers: res.headers };
  }

  getThumbprint() {
    const canonicalJwk = `{"crv":"${this.jwk.crv}","kty":"${this.jwk.kty}","x":"${this.jwk.x}","y":"${this.jwk.y}"}`;
    const hash = crypto.createHash('sha256').update(canonicalJwk).digest();
    return b64u(hash);
  }
}

// Otomatik Challenge Sunucusu Başlatıcı
function startChallengeServer(token, content) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const expectedPath = `/.well-known/acme-challenge/${token}`;
      if (req.url === expectedPath) {
        console.log(`[HTTP-Server] ACME Doğrulama isteği yakalandı: ${req.url}`);
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(content);
      } else {
        res.writeHead(404);
        res.end('Not Found');
      }
    });

    server.listen(CHALLENGE_PORT,"31.58.245.241", () => {
      console.log(`[HTTP-Server] Port ${CHALLENGE_PORT} üzerinde otomatik challenge sunucusu aktif.`);
      resolve(server);
    });
  });
}

// ANA AKIŞ
async function runAcmeFlow() {
  const client = new CustomAcmeClient(DIRECTORY_URL);
  await client.init();

  console.log('[ACME] Hesap (Account) açılıyor...');
  const accountRes = await client.signedRequest(client.endpoints.newAccount, {
    termsOfServiceAgreed: true,
    contact: ['mailto:admin@fitfak.net']
  });
  client.kid = accountRes.headers.get('location');
  console.log(`[ACME] Hesap OK. KID: ${client.kid}`);

  console.log(`[ACME] ${DOMAIN} için sipariş (Order) veriliyor...`);
  const orderRes = await client.signedRequest(client.endpoints.newOrder, {
    identifiers: [{ type: 'dns', value: DOMAIN }]
  });
  const order = orderRes.data;
  const finalizeUrl = order.finalize;

  const authzUrl = order.authorizations[0];
  const authzRes = await client.signedRequest(authzUrl, '');
  const httpChallenge = authzRes.data.challenges.find(c => c.type === 'http-01');

  const thumbprint = client.getThumbprint();
  const keyAuthorization = `${httpChallenge.token}.${thumbprint}`;

  // 1. Otomatik HTTP Sunucusunu Başlat (Dosyayı elle koyma devri bitti)
  const challengeServer = await startChallengeServer(httpChallenge.token, keyAuthorization);

  console.log('[ACME] Sunucuya "Doğrula" emri gönderiliyor...');
  try {
    await client.signedRequest(httpChallenge.url, {});
    
    console.log('[ACME] Siparişin onaylanması bekleniyor...');
    await new Promise(r => setTimeout(r, 3000));
  } finally {
    // İşlem bitince port 80'deki geçici sunucuyu kapat
    challengeServer.close();
    console.log('[HTTP-Server] Challenge sunucusu kapatıldı.');
  }

  console.log('[ACME] Kendi PKI motorumuzla CSR üretiliyor...');
  const certKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const keyInfo = {
    keyType: 'ec',
    curveName: 'P-256',
    publicKeyBuf: certKey.publicKey.export({ type: 'spki', format: 'der' }),
    privateKey: certKey.privateKey.export({ type: 'sec1', format: 'der' })
  };
  
  const csrPem = generateCSR(keyInfo, [
    [OIDs.country, 'TR'],
    [OIDs.commonName, DOMAIN]
  ]);
  
  const csrDerB64 = csrPem.split('\n').filter(l => l && !l.startsWith('-----')).join('');
  const csrB64Url = csrDerB64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  console.log('[ACME] Sipariş Finalize ediliyor (CSR gönderiliyor)...');
  const finalizeRes = await client.signedRequest(finalizeUrl, { csr: csrB64Url });
  
  const certUrl = finalizeRes.data.certificate;
  if (!certUrl) {
    console.log('Sertifika henüz hazır değil, ACME sunucusu processing döndü.');
    return;
  }

  console.log('[ACME] Sertifika indiriliyor...');
  const certRes = await client.signedRequest(certUrl, '');
  console.log('\n🎉 SERTİFİKA ALINDI:\n');
  console.log(certRes.data);
}

runAcmeFlow().catch(console.error);