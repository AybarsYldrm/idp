'use strict';

const crypto = require('node:crypto');

// ============================================================================
// DÜRÜSTLÜK NOTU (lütfen okuyun): Ne sunucu tarafı ne de istemci tarafı fingerprinting
// SERT bir güvenlik sınırı değildir -- hiçbir zaman olmadı. Kararlı bir saldırgan
// user-agent'ı, canvas hash'ini, ekran çözünürlüğünü, hatta TLS parmak izini taklit
// edebilir. Bu modülün amacı kimlik KANITLAMAK değil; otomasyonun MALİYETİNİ artırmak ve
// rate limiter + PoW zorluk seviyesini besleyecek bir ANOMALİ/GÜVEN sinyali üretmektir.
// Üretimdeki her IdP'de (Google, GitHub, Cloudflare dahil) bu tam olarak böyle kullanılır:
// tek başına karar verici değil, çok katmanlı savunmanın bir katmanı.
// ============================================================================

function extractServerSignals(headers, socket) {
  headers = headers || {};
  socket = socket || {};
  const headerOrder = Object.keys(headers).join(',');
  return {
    userAgent: headers['user-agent'] || '',
    acceptLanguage: headers['accept-language'] || '',
    headerOrderHash: crypto.createHash('sha256').update(headerOrder).digest('hex').slice(0, 16),
    tlsCipher: typeof socket.getCipher === 'function' ? (socket.getCipher()?.name || '') : '',
    alpnProtocol: socket.alpnProtocol || '',
  };
}

/**
 * @param {object|null} clientFingerprint - public/anti-bot-client.js tarafından toplanan
 *   ve istemcinin gönderdiği ham sinyal objesi (bkz. o dosyadaki `collectFingerprint()`).
 *   `null`/`undefined` ise istemci JS'i hiç çalışmamış demektir -- bu TEK BAŞINA güçlü bir
 *   bot sinyalidir (gerçek bir tarayıcı bu script'i çalıştırmadan login formunu göndermez).
 */
function combine({ clientFingerprint, serverSignals }) {
  const material = JSON.stringify({
    cf: clientFingerprint || null,
    ua: serverSignals.userAgent,
    al: serverSignals.acceptLanguage,
    ho: serverSignals.headerOrderHash,
    tc: serverSignals.tlsCipher,
    ap: serverSignals.alpnProtocol,
  });
  const fingerprintId = crypto.createHash('sha256').update(material).digest('hex');

  let trust = 0.5;
  if (!clientFingerprint) trust -= 0.3;
  if (!serverSignals.userAgent) trust -= 0.2;
  if (clientFingerprint && clientFingerprint.webdriver === true) trust -= 0.4; // navigator.webdriver
  if (clientFingerprint && clientFingerprint.hasConsistentTimezone === false) trust -= 0.1;
  if (clientFingerprint && clientFingerprint.headless === true) trust -= 0.4;
  trust = Math.max(0, Math.min(1, trust));

  return { fingerprintId, trustScore: trust };
}

module.exports = { extractServerSignals, combine };
