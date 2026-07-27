'use strict';

const crypto = require('node:crypto');
const base64url = require('./base64url');

// ============================================================================
// NEDEN HMAC (server.js'teki gibi) DEĞİL DE ES256 (asimetrik)?
// ----------------------------------------------------------------------------
// Referans kodunuzdaki signAuthToken/verifyAuthToken tek bir paylaşılan HMAC sırrı
// kullanıyor -- tek bir monolitik servis kendi ürettiği token'ı kendi doğruladığı
// sürece bu gayet iyi çalışır. Ama bu yeni sistem BİR MERKEZİ IdP olacak ve
// dns.fitfak.net gibi tamamen ayrı servisler token'ları DOĞRULAYACAK. Paylaşılan bir
// HMAC sırrıyla bunu yapmak, o sırrı her ilişkili tarafa (relying party) dağıtmak
// anlamına gelir -- ki bu da HERHANGİ BİRİNİN ele geçirilmesi durumunda saldırganın
// TÜM diğer servisler için de geçerli token üretebilmesi (herkes adına oturum açabilmesi)
// demektir. ES256 (ECDSA P-256) ile IdP private key'i asla paylaşmaz; her relying party
// sadece /.well-known/jwks.json'daki PUBLIC key ile doğrulama yapar. Bir RP'nin
// içeriden sızdırılmış API sırrı, token SAHTECİLİĞİ için kullanılamaz.
// ============================================================================

function sign(payload, privateKeyObject, { kid, expiresInSeconds } = {}) {
  const header = { alg: 'ES256', typ: 'JWT' };
  if (kid) header.kid = kid;

  const now = Math.floor(Date.now() / 1000);
  const fullPayload = { iat: now, ...payload };
  if (expiresInSeconds) fullPayload.exp = now + expiresInSeconds;

  const headerB64 = base64url.encode(Buffer.from(JSON.stringify(header)));
  const payloadB64 = base64url.encode(Buffer.from(JSON.stringify(fullPayload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  // node:crypto EC imzaları varsayılan olarak DER (ASN.1) kodlar; JOSE/JWT spesifikasyonu
  // ise sabit genişlikli "R || S" ham formatını ister -- aşağıda dönüştürülüyor.
  const derSignature = crypto.sign('sha256', Buffer.from(signingInput), privateKeyObject);
  const joseSignature = derToJose(derSignature, 32); // P-256 -> 32 byte'lık R ve S

  return `${signingInput}.${base64url.encode(joseSignature)}`;
}

/**
 * @param {string} token
 * @param {import('crypto').KeyObject | ((header: object) => import('crypto').KeyObject)} publicKeyOrResolver
 *   Sabit bir public key VEYA header'a bakıp (örn. `kid` alanına göre) doğru anahtarı
 *   seçen bir fonksiyon -- anahtar rotasyonunu (JWKS'te birden çok key) desteklemek için.
 */
function verify(token, publicKeyOrResolver) {
  if (typeof token !== 'string' || token.split('.').length !== 3) {
    throw new Error('jwt.verify: bozuk token (3 parça bekleniyor)');
  }
  const [headerB64, payloadB64, sigB64] = token.split('.');

  let header;
  try {
    header = JSON.parse(base64url.decode(headerB64).toString('utf8'));
  } catch {
    throw new Error('jwt.verify: header JSON olarak çözülemedi');
  }
  if (header.alg !== 'ES256') throw new Error(`jwt.verify: desteklenmeyen alg '${header.alg}' (sadece ES256)`);

  const publicKeyObject = typeof publicKeyOrResolver === 'function'
    ? publicKeyOrResolver(header)
    : publicKeyOrResolver;
  if (!publicKeyObject) throw new Error('jwt.verify: doğrulama anahtarı bulunamadı (kid eşleşmedi olabilir)');

  const joseSignature = base64url.decode(sigB64);
  if (joseSignature.length !== 64) throw new Error('jwt.verify: imza uzunluğu P-256 için beklenmedik (64 byte olmalı)');
  const derSignature = joseToDer(joseSignature);

  const signingInput = `${headerB64}.${payloadB64}`;
  const ok = crypto.verify('sha256', Buffer.from(signingInput), publicKeyObject, derSignature);
  if (!ok) throw new Error('jwt.verify: imza doğrulaması başarısız');

  let payload;
  try {
    payload = JSON.parse(base64url.decode(payloadB64).toString('utf8'));
  } catch {
    throw new Error('jwt.verify: payload JSON olarak çözülemedi');
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && now >= payload.exp) throw new Error('jwt.verify: token süresi dolmuş');
  if (typeof payload.nbf === 'number' && now < payload.nbf) throw new Error('jwt.verify: token henüz geçerli değil');

  return { header, payload };
}

// ---- DER (ASN.1) <-> JOSE (ham R||S) ECDSA imza dönüşümü ----
//
// DER: 0x30 <seqLen> 0x02 <rLen> <R bytes> 0x02 <sLen> <S bytes>
// R/S, en yüksek biti 1 olan bir sayıysa DER'de önüne 0x00 eklenir (işaret belirsizliğini
// önlemek için); JOSE formatında ise her zaman TAM componentLength (P-256 için 32) byte,
// soldan sıfırla doldurulmuş ham büyük-endian tamsayı olarak beklenir.

function derToJose(der, componentLength) {
  let offset = 0;
  if (der[offset++] !== 0x30) throw new Error('jwt: geçersiz DER imza (SEQUENCE bekleniyor)');
  let seqLen = der[offset++];
  if (seqLen & 0x80) {
    const nBytes = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < nBytes; i++) seqLen = (seqLen << 8) | der[offset++];
  }
  if (der[offset++] !== 0x02) throw new Error('jwt: geçersiz DER imza (R INTEGER tag bekleniyor)');
  const rLen = der[offset++];
  let r = der.subarray(offset, offset + rLen); offset += rLen;
  if (der[offset++] !== 0x02) throw new Error('jwt: geçersiz DER imza (S INTEGER tag bekleniyor)');
  const sLen = der[offset++];
  let s = der.subarray(offset, offset + sLen); offset += sLen;

  r = stripLeadingZeros(r);
  s = stripLeadingZeros(s);
  if (r.length > componentLength || s.length > componentLength) {
    throw new Error('jwt: imza bileşeni beklenenden uzun (yanlış eğri?)');
  }

  const out = Buffer.alloc(componentLength * 2);
  r.copy(out, componentLength - r.length);
  s.copy(out, componentLength * 2 - s.length);
  return out;
}

function joseToDer(jose) {
  const componentLength = jose.length / 2;
  const r = toDerInteger(jose.subarray(0, componentLength));
  const s = toDerInteger(jose.subarray(componentLength));
  const body = Buffer.concat([
    Buffer.from([0x02, r.length]), r,
    Buffer.from([0x02, s.length]), s,
  ]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function stripLeadingZeros(buf) {
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0x00) i++;
  return buf.subarray(i);
}

function toDerInteger(buf) {
  let b = stripLeadingZeros(buf);
  if (b.length === 0) b = Buffer.from([0x00]);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]); // işaret biti belirsizliğini önle
  return b;
}

module.exports = { sign, verify };
