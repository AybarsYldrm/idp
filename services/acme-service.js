'use strict';

const crypto = require('node:crypto');
const http = require('node:http');
const dns = require('node:dns').promises;
const net = require('node:net');
const { AppError } = require('../core/errors');
const { verifyJws, jwkThumbprint, parseJws } = require('../core/acme-jws');

const ORDER_TTL_MS = 24 * 60 * 60 * 1000; // RFC 8555 önerisi: sipariş birkaç saat/gün içinde tamamlanmalı
const AUTHZ_TTL_MS = ORDER_TTL_MS;
const NONCE_TTL_MS = 5 * 60 * 1000;
const HTTP01_TIMEOUT_MS = 10 * 1000;

function randomId() { return crypto.randomBytes(16).toString('hex'); }
function base64urlToken() { return crypto.randomBytes(24).toString('base64url'); }

// ============================================================================
// SSRF (Server-Side Request Forgery) KORUMASI: http-01 doğrulaması, İSTEMCİNİN BEYAN
// ETTİĞİ (kanıtlanmamış) bir domain'e sunucu tarafından GERÇEK bir istek atar -- bu,
// klasik bir SSRF vektörüdür (ör. `identifier.value = '169.254.169.254'` vererek bulut
// metadata servisini, ya da `10.0.0.5` vererek iç ağdaki başka bir servisi sorgulatmak).
// Bu yüzden bağlanmadan ÖNCE domain'i çözümleyip, dönen HER IP'nin private/loopback/
// link-local/multicast aralıklarının DIŞINDA olduğunu doğruluyoruz.
//
// DNS REBINDING NOTU: sadece "doğrulama anında" kontrol etmek YETERLİ DEĞİLDİR -- bir
// saldırgan, DNS TTL'ini çok düşük tutup doğrulama ile bağlantı arasındaki milisaniyeler
// içinde kaydı değiştirebilir (DNS rebinding). Bunu kapatmak için domain'i BİR KEZ
// çözümleyip DOĞRULANMIŞ IP'ye doğrudan bağlanıyoruz (http.get'in `host` alanına IP
// veriyoruz, hostname'i TEKRAR ÇÖZÜMLETMİYORUZ) -- ama hedef sunucunun doğru virtual
// host'u görebilmesi için orijinal domain'i `Host` header'ında ayrıca gönderiyoruz.
// ============================================================================
function isBlockedIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 127) return true; // loopback (127.0.0.0/8)
    if (a === 10) return true; // RFC 1918
    if (a === 172 && b >= 16 && b <= 31) return true; // RFC 1918
    if (a === 192 && b === 168) return true; // RFC 1918
    if (a === 169 && b === 254) return true; // link-local -- BULUT METADATA (169.254.169.254) DAHİL
    if (a === 0) return true; // "bu ağ"
    if (a >= 224) return true; // multicast/rezerve (224-255)
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return true; // loopback / belirtilmemiş
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // fc00::/7 unique local
    if (/^fe[89ab]/.test(lower)) return true; // fe80::/10 link-local
    if (lower.startsWith('::ffff:')) { // IPv4-mapped IPv6 -- içindeki IPv4'ü de kontrol et
      const v4 = lower.split(':').pop();
      if (net.isIPv4(v4)) return isBlockedIp(v4);
    }
    return false;
  }
  return true; // tanınmayan biçim -- güvenli tarafta kal, ENGELLE
}

// SADECE yerel test/geliştirme İÇİN: gerçek http-01 doğrulamasını yerel bir sunucuya karşı
// test edebilmek için SSRF korumasını BİLEREK atlatan bir kaçış kapısı. ÜRETİMDE ASLA
// ayarlamayın -- ayarlarsanız private/loopback adreslere istek atılmasına izin verirsiniz.
const ALLOW_PRIVATE_IPS_FOR_TESTING = process.env.FITFAK_IDP_ACME_ALLOW_PRIVATE_IPS === '1';

async function resolveAndValidateHost(domain) {
  let addresses;
  try {
    addresses = await dns.lookup(domain, { all: true, verbatim: true });
  } catch (e) {
    throw new Error(`DNS çözümlemesi başarısız: ${e.message}`);
  }
  if (!addresses.length) throw new Error('DNS çözümlemesi hiç adres döndürmedi');
  const blocked = addresses.find((a) => isBlockedIp(a.address));
  if (blocked) {
    if (ALLOW_PRIVATE_IPS_FOR_TESTING) {
      // eslint-disable-next-line no-console
      console.warn(`[fitfak-idp] UYARI: FITFAK_IDP_ACME_ALLOW_PRIVATE_IPS=1 ile SSRF koruması BİLEREK atlatıldı (${blocked.address}) -- SADECE yerel test için, ÜRETİMDE ASLA kullanmayın.`);
    } else {
      throw new Error(`SSRF koruması: '${domain}' özel/yerel/rezerve bir IP'ye (${blocked.address}) çözümleniyor -- http-01 doğrulaması reddedildi`);
    }
  }
  return addresses[0].address;
}

/** RFC 8555 §8.3: http://<identifier>/.well-known/acme-challenge/<token> yoluna GERÇEK bir istek atar. */
async function fetchHttp01Response(domain, token, port = 80) {
  const validatedIp = await resolveAndValidateHost(domain);
  return new Promise((resolve, reject) => {
    const req = http.get({
      host: validatedIp, // DNS rebinding'i önlemek için DOĞRULANMIŞ IP'ye bağlan (hostname'i tekrar çözümletme)
      headers: { Host: domain }, // hedef sunucunun doğru virtual host'u görmesi için orijinal domain
      port,
      path: `/.well-known/acme-challenge/${token}`,
      timeout: HTTP01_TIMEOUT_MS,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        if (res.statusCode !== 200) { reject(new Error(`HTTP ${res.statusCode}`)); return; }
        resolve(Buffer.concat(chunks).toString('utf8'));
      });
    });
    req.on('timeout', () => req.destroy(new Error('zaman aşımı')));
    req.on('error', reject);
  });
}

class AcmeService {
  /**
   * @param {object} opts
   * @param {object} opts.db
   * @param {object} opts.pkiIssuer - core/pki-issuer.js PkiIssuer örneği
   * @param {object} opts.nonceStore - core/ephemeral-store.js arayüzü (tek-kullanımlık nonce'lar için)
   * @param {string} opts.issuer - örn. 'https://trust.fitfak.net'
   */
  constructor({
    db, pkiIssuer, nonceStore, issuer, http01Port,
  }) {
    this.db = db;
    this.pkiIssuer = pkiIssuer;
    this.nonceStore = nonceStore;
    this.issuer = issuer;
    this.http01Port = http01Port || 80;
  }

  directory() {
    return {
      newNonce: `${this.issuer}/acme/new-nonce`,
      newAccount: `${this.issuer}/acme/new-account`,
      newOrder: `${this.issuer}/acme/new-order`,
      revokeCert: `${this.issuer}/acme/revoke-cert`,
      keyChange: `${this.issuer}/acme/key-change`,
      meta: { termsOfService: `${this.issuer}/terms`, website: this.issuer },
    };
  }

  async issueNonce() {
    const nonce = crypto.randomBytes(16).toString('hex');
    await this.nonceStore.set(nonce, true, NONCE_TTL_MS);
    return nonce;
  }

  async _consumeNonce(nonce) {
    const valid = await this.nonceStore.get(nonce);
    if (!valid) throw new AppError('badNonce', 'Geçersiz ya da zaten kullanılmış nonce', { httpStatus: 400 });
    await this.nonceStore.delete(nonce);
  }

  /**
   * Her ACME POST isteğinin ORTAK doğrulama adımı: JWS imzasını çöz+doğrula, nonce'u
   * tüket (tek kullanımlık), `url` alanının GERÇEKTEN çağrılan uç noktayla eşleştiğini
   * kontrol et (MITM'in isteği başka bir uca yönlendirmesini engeller).
   */
  async _verifyRequest(jwsObj, expectedUrl, { requireExistingAccount = true } = {}) {
    const { protectedHeader } = parseJws(jwsObj);
    if (protectedHeader.url !== expectedUrl) {
      throw new AppError('unauthorized', "JWS 'url' alanı çağrılan uç noktayla eşleşmiyor", { httpStatus: 401 });
    }
    await this._consumeNonce(protectedHeader.nonce);

    let resolvedJwk;
    let account = null;
    if (protectedHeader.kid) {
      const accountId = protectedHeader.kid.split('/').pop();
      account = await this.db.collection('acme_accounts').findOne('accountId', accountId);
      if (!account) throw new AppError('accountDoesNotExist', 'Bilinmeyen hesap', { httpStatus: 400 });
      resolvedJwk = JSON.parse(account.jwkJson);
    } else if (requireExistingAccount) {
      throw new AppError('malformed', "JWS 'kid' alanı gerekli", { httpStatus: 400 });
    }

    const { payload, jwk } = verifyJws(jwsObj, { resolvedJwk });
    return { payload, jwk, account };
  }

  async newAccount(jwsObj) {
    const { payload, jwk } = await this._verifyRequest(jwsObj, `${this.issuer}/acme/new-account`, { requireExistingAccount: false });
    const thumbprint = jwkThumbprint(jwk);
    const accounts = this.db.collection('acme_accounts');

    const existing = await accounts.findOne('jwkThumbprint', thumbprint);
    if (existing) {
      return { accountId: existing.accountId, status: existing.status, isNew: false };
    }

    const accountId = randomId();
    await accounts.insert({
      accountId,
      jwkThumbprint: thumbprint,
      jwkJson: JSON.stringify(jwk),
      contact: JSON.stringify(payload?.contact || []),
      status: 'valid',
      createdAt: BigInt(Date.now()),
    });
    return { accountId, status: 'valid', isNew: true };
  }

  async newOrder(jwsObj) {
    const { payload, account } = await this._verifyRequest(jwsObj, `${this.issuer}/acme/new-order`);
    const identifiers = payload?.identifiers || [];
    if (!Array.isArray(identifiers) || identifiers.length === 0) {
      throw new AppError('malformed', 'En az bir identifier gerekli', { httpStatus: 400 });
    }

    const orderId = randomId();
    const authzIds = [];
    for (const ident of identifiers) {
        if (!ident.value.endsWith('.fitfak.net')) {
      throw new AppError('rejectedIdentifier', 'Sadece fitfak.net alt alan adlarına izin verilmektedir.', { httpStatus: 403 });
    }

      const authzId = randomId();
      const token = base64urlToken();
      // eslint-disable-next-line no-await-in-loop  
      await this.db.collection('acme_authorizations').insert({
        authzId,
        orderId,
        identifier: JSON.stringify(ident),
        status: 'pending',
        challengesJson: JSON.stringify([{ type: 'http-01', token, status: 'pending' }]),
        expiresAt: BigInt(Date.now() + AUTHZ_TTL_MS),
      });
      authzIds.push(authzId);
    }

    await this.db.collection('acme_orders').insert({
      orderId,
      accountId: account.accountId,
      status: 'pending',
      identifiersJson: JSON.stringify(identifiers),
      authorizationIdsJson: JSON.stringify(authzIds),
      certificateSerial: '',
      expiresAt: BigInt(Date.now() + ORDER_TTL_MS),
      createdAt: BigInt(Date.now()),
    });

    return this._orderView(orderId);
  }

  async _orderView(orderId) {
      const row = await this.db.collection('acme_orders').findOne('orderId', orderId);
      if (!row) return null;
      const authzIds = JSON.parse(row.authorizationIdsJson);
      const result = {
      orderId: row.orderId,
      status: row.status,
      identifiers: JSON.parse(row.identifiersJson),
      authorizations: authzIds.map(id => `${this.issuer}/acme/authz/${id}`),
      finalize: `${this.issuer}/acme/order/${row.orderId}/finalize`,
      expires: new Date(Number(row.expiresAt)).toISOString()
  };

  if (row.certificateSerial) {
      result.certificate = `${this.issuer}/acme/cert/${row.certificateSerial}`;
  }

  return result;
  }

  async getAuthorization(authzId) {
    const row = await this.db.collection('acme_authorizations').findOne('authzId', authzId);
    if (!row) throw new AppError('not_found', 'Authorization bulunamadı', { httpStatus: 404 });
    return {
      identifier: JSON.parse(row.identifier),
      status: row.status,
      expires: new Date(Number(row.expiresAt)).toISOString(),
      challenges: JSON.parse(row.challengesJson).map((c) => ({
        ...c, url: `${this.issuer}/acme/challenge/${row.authzId}`,
      })),
    };
  }

  /**
   * İstemci "meydan okumayı hazırladım, doğrula" der (JWS ile imzalanmış boş bir POST).
   * Sunucu GERÇEKTEN http-01 doğrulamasını burada yapar: identifier'ın .well-known/
   * acme-challenge/<token> yoluna gerçek bir HTTP isteği atıp, dönen içeriğin
   * `<token>.<hesabın jwk thumbprint'i>` olduğunu doğrular (RFC 8555 §8.3).
   */
  async respondToChallenge(authzId, jwsObj) {
    const { account } = await this._verifyRequest(jwsObj, `${this.issuer}/acme/challenge/${authzId}`);
    const authzRow = await this.db.collection('acme_authorizations').findOne('authzId', authzId);
    if (!authzRow) throw new AppError('not_found', 'Authorization bulunamadı', { httpStatus: 404 });

    const identifier = JSON.parse(authzRow.identifier);
    const challenges = JSON.parse(authzRow.challengesJson);
    const challenge = challenges.find((c) => c.type === 'http-01');

    const expectedKeyAuthorization = `${challenge.token}.${jwkThumbprint(JSON.parse(account.jwkJson))}`;
    let validated = false;
    let validationError = null;
    try {
      const actual = await fetchHttp01Response(identifier.value, challenge.token, this.http01Port);
      validated = actual.trim() === expectedKeyAuthorization;
      if (!validated) validationError = 'beklenen key authorization eşleşmedi';
    } catch (e) {
      validationError = e.message;
    }

    challenge.status = validated ? 'valid' : 'invalid';
    if (validationError) challenge.error = validationError;
    await this.db.collection('acme_authorizations').update(authzRow._id, {
      status: validated ? 'valid' : 'invalid',
      challengesJson: JSON.stringify(challenges),
    });

    if (!validated) {
      throw new AppError('unauthorized', `http-01 doğrulaması başarısız: ${validationError}`, { httpStatus: 403 });
    }
    return this.getAuthorization(authzId);
  }

  /** İstemci CSR'ı gönderir -- TÜM authorization'lar 'valid' ise sertifika üretilir. */
  async finalizeOrder(orderId, jwsObj) {
    const { payload } = await this._verifyRequest(jwsObj, `${this.issuer}/acme/order/${orderId}/finalize`);
    const orderRow = await this.db.collection('acme_orders').findOne('orderId', orderId);
    if (!orderRow) throw new AppError('not_found', 'Sipariş bulunamadı', { httpStatus: 404 });

    const authzIds = JSON.parse(orderRow.authorizationIdsJson);
    const authzRows = [];
    for (const id of authzIds) {
      // eslint-disable-next-line no-await-in-loop
      authzRows.push(await this.db.collection('acme_authorizations').findOne('authzId', id));
    }
    if (!authzRows.every((a) => a && a.status === 'valid')) {
      throw new AppError('orderNotReady', "Tüm authorization'lar henüz doğrulanmadı", { httpStatus: 403 });
    }

    const csrDer = Buffer.from(payload.csr, 'base64url');
    const csrPem = `-----BEGIN CERTIFICATE REQUEST-----\n${csrDer.toString('base64')}\n-----END CERTIFICATE REQUEST-----`;
    const identifiers = JSON.parse(orderRow.identifiersJson);

    // 🛡️ MÜKEMMEL GÜVENLİK (PERFECT FORWARD SECRECY) KONTROLÜ
    const {
      certPem, serialNumberHex, skidHex, notBefore, notAfter,
    } = await this.pkiIssuer.signCertificateFromCsr({
      csrPem, 
      profile: 'server-auth', 
      subjectOverride: { cn: identifiers[0]?.value },
      // pki.js motoru sertifika basmadan önce bu callback'i çağırır:
      checkKeyUniqueness: async (incomingSkidHex) => {
        // Bu parmak izine (Private Key) ait veritabanımızda başka sertifika var mı?
        const existing = await this.db.collection('certificates').findOne('skidHex', incomingSkidHex);
        return !!existing; // Varsa true döner ve pki.js hata fırlatıp sertifika vermeyi reddeder.
      }
    });

    await this.db.collection('certificates').insert({
      serialNumberHex,
      skidHex, // 🛡️ Parmak izi (SKID) daha sonra kontrol edilebilmesi için veritabanına yazılıyor
      userId: orderRow.accountId,
      subjectCn: identifiers[0]?.value || '',
      profile: 'server-auth',
      certPem,
      notBefore: BigInt(notBefore.getTime()),
      notAfter: BigInt(notAfter.getTime()),
      status: 'valid',
      revokedAt: 0n,
      revocationReason: '',
      createdAt: BigInt(Date.now()),
      issuedVia: 'acme',
    });

    await this.db.collection('acme_orders').update(orderRow._id, { status: 'valid', certificateSerial: serialNumberHex });
    return this._orderView(orderId);
  }

  async downloadCertificate(serialNumberHex) {
    const row = await this.db.collection('certificates').findOne('serialNumberHex', serialNumberHex);
    if (!row) throw new AppError('not_found', 'Sertifika bulunamadı', { httpStatus: 404 });
    return row.certPem;
  }
}

module.exports = { AcmeService, isBlockedIp };