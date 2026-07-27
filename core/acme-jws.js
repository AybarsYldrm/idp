'use strict';

const crypto = require('node:crypto');
const base64url = require('./base64url');

// ============================================================================
// RFC 8555 (ACME) her POST isteğini bir JWS (JSON Web Signature) olarak taşır:
// { protected: base64url(header), payload: base64url(json), signature: base64url(sig) }
// header ya `jwk` (gömülü genel anahtar -- SADECE new-account için) ya da `kid`
// (hesap URL'i -- diğer tüm istekler için, anahtar zaten kayıtlı) içerir, artı `nonce`
// (tekrar oynatma/replay koruması) ve `url` (isteğin GERÇEKTEN hangi uç noktaya
// gönderildiğini de imzanın içine alarak bir MITM'in isteği başka bir uca
// yönlendirmesini engeller).
//
// Node'un YERLEŞİK JWK aktarımını (crypto.createPublicKey({key, format:'jwk'})) ve
// IEEE-P1363 ECDSA doğrulamasını (crypto.verify(..., {dsaEncoding:'ieee-p1363'}))
// kullanıyoruz -- bu, JOSE/JWS imzalarının DER değil ham r||s birleştirmesi
// kullanmasından dolayı gereklidir ve elle DER<->JOSE dönüşümü yazmaktan daha güvenli/
// az hataya açıktır (Node'un kendi test edilmiş kriptografi koduna dayanır).
//
// KAPSAM: SADECE ES256 (P-256 ECDSA) JWK'ları destekler -- certbot/acme.sh dahil çoğu
// modern ACME istemcisi `--key-type ecdsa` ile bunu destekler. RSA (RS256) JWK'ları
// BİLEREK desteklenmiyor (kapsam sınırlaması, README'de belirtilmiştir).
// ============================================================================

function jwkThumbprint(jwk) {
  // RFC 7638: alanlar alfabetik sırada, boşluksuz JSON -- EC anahtarları için {crv,kty,x,y}.
  const canonical = JSON.stringify({
    crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y,
  });
  return base64url.encode(crypto.createHash('sha256').update(canonical).digest());
}

function parseJws(jwsObj) {
  const protectedHeader = JSON.parse(base64url.decode(jwsObj.protected).toString('utf8'));
  const payload = jwsObj.payload ? JSON.parse(base64url.decode(jwsObj.payload).toString('utf8')) : null;
  return { protectedHeader, payload, rawPayloadB64: jwsObj.payload || '' };
}

/**
 * JWS'in imzasını, ya gömülü `jwk` (new-account) ya da verilen `resolvedJwk` (kid ile
 * çözülmüş, önceden kayıtlı hesap anahtarı) ile doğrular. Doğruysa {protectedHeader,
 * payload, jwk} döner; yanlışsa/desteklenmeyen bir algoritmaysa fırlatır.
 */
function verifyJws(jwsObj, { resolvedJwk } = {}) {
  const { protectedHeader, payload, rawPayloadB64 } = parseJws(jwsObj);

  if (protectedHeader.alg !== 'ES256') {
    throw new Error(`acme-jws: desteklenmeyen alg '${protectedHeader.alg}' (sadece ES256 destekleniyor)`);
  }

  const jwk = protectedHeader.jwk || resolvedJwk;
  if (!jwk) throw new Error('acme-jws: doğrulama için jwk/kid çözümlenemedi');
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error('acme-jws: sadece EC P-256 anahtarları destekleniyor');
  }

  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const signingInput = Buffer.from(`${jwsObj.protected}.${rawPayloadB64}`, 'ascii');
  const signature = base64url.decode(jwsObj.signature);

  const ok = crypto.verify(null, signingInput, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
  if (!ok) throw new Error('acme-jws: imza doğrulaması başarısız');

  return { protectedHeader, payload, jwk };
}

module.exports = { verifyJws, jwkThumbprint, parseJws };
