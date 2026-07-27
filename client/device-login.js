'use strict';

const http = require('node:http');
const https = require('node:https');

// ============================================================================
// Terminal/CLI araçlarınız için hazır Device Authorization Grant (RFC 8628) istemcisi.
// Ekranı zengin bir tarayıcı barındıramayan/URL yönlendirmesi alamayan ortamlar (CLI,
// SSH oturumu, headless script) için: kullanıcıya bir kod + URL gösterir, kullanıcı
// BAŞKA bir cihazda (telefon/tarayıcı) onaylar, bu fonksiyon arka planda poll edip
// onaylanınca gerçek access+refresh token döner.
//
// KULLANIM:
//   const { deviceLogin } = require('@fitfak/idp-client/device-login');
//   const tokens = await deviceLogin({
//     baseUrl: 'https://session.fitfak.net',
//     clientId: 'benim-cli-aracim',
//   });
//   console.log('Giriş yapıldı:', tokens.accessToken);
// ============================================================================

function request(method, url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const payload = body ? Buffer.from(JSON.stringify(body)) : null;
    const req = lib.request(u, {
      method,
      headers: payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {},
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* boş yanıt olabilir */ }
        resolve({ status: res.statusCode, json });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

/**
 * @param {object} opts
 * @param {string} opts.baseUrl - örn. 'https://session.fitfak.net'
 * @param {string} opts.clientId
 * @param {string} [opts.scope]
 * @param {(info: {verificationUri: string, verificationUriComplete: string, userCode: string, expiresIn: number}) => void} [opts.onPrompt]
 *   Kullanıcıya kodu/URL'yi göstermek için çağrılır -- verilmezse konsola yazdırılır.
 * @param {number} [opts.timeoutMs] - opsiyonel; verilmezse sunucunun döndürdüğü expires_in kullanılır.
 * @returns {Promise<{accessToken: string, refreshToken: string, expiresIn: number}>}
 */
async function deviceLogin({
  baseUrl, clientId, scope, onPrompt, timeoutMs,
}) {
  const startResp = await request('POST', `${baseUrl}/oauth/device/code`, { client_id: clientId, scope });
  if (startResp.status !== 200) {
    throw new Error(`Device code isteği başarısız: ${startResp.json?.error_description || startResp.status}`);
  }
  const {
    device_code: deviceCode, user_code: userCode, verification_uri: verificationUri,
    verification_uri_complete: verificationUriComplete, expires_in: expiresIn, interval,
  } = startResp.json;

  if (onPrompt) {
    onPrompt({
      verificationUri, verificationUriComplete, userCode, expiresIn,
    });
  } else {
    // eslint-disable-next-line no-console
    console.log(`\nTarayıcında şu adresi aç: ${verificationUriComplete || verificationUri}`);
    // eslint-disable-next-line no-console
    console.log(`Kod: ${userCode}\n`);
  }

  const deadline = Date.now() + (timeoutMs || expiresIn * 1000);
  let pollIntervalMs = (interval || 5) * 1000;

  for (;;) {
    if (Date.now() > deadline) throw new Error('Cihaz onayı zaman aşımına uğradı -- işlemi tekrar başlatın');
    // eslint-disable-next-line no-await-in-loop
    await sleep(pollIntervalMs);
    // eslint-disable-next-line no-await-in-loop
    const tokenResp = await request('POST', `${baseUrl}/oauth/token`, {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: deviceCode, client_id: clientId,
    });
    if (tokenResp.status === 200) {
      return {
        accessToken: tokenResp.json.access_token,
        refreshToken: tokenResp.json.refresh_token,
        expiresIn: tokenResp.json.expires_in,
      };
    }
    const errCode = tokenResp.json?.error;
    if (errCode === 'authorization_pending') continue; // kullanıcı henüz onaylamadı -- beklemeye devam
    if (errCode === 'slow_down') { pollIntervalMs += 5000; continue; } // RFC 8628: istemci yavaşlamalı
    const err = new Error(`Device code değişimi başarısız: ${tokenResp.json?.error_description || errCode || tokenResp.status}`);
    err.code = errCode;
    throw err;
  }
}

module.exports = { deviceLogin };
