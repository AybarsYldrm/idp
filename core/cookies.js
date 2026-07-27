'use strict';

// ============================================================================
// __Host- ÖNEKİ NEDEN KULLANILMIYOR: `__Host-` önekli cookie'ler tarayıcı tarafından
// SADECE `Domain` niteliği HİÇ belirtilmemişse (ve Path=/ ise) kabul edilir. Bizim SSO
// senaryomuz tam tersini gerektiriyor: `Domain=.fitfak.net` ile session.fitfak.net'te
// kurulan cookie'nin dns.fitfak.net gibi TÜM alt alan adlarına da gitmesi gerekiyor. Bu
// yüzden `__Secure-` öneki kullanıyoruz -- bu önek sadece `Secure` niteliğini şart koşar,
// `Domain` ile uyumludur ve yine de cookie'nin sadece HTTPS üzerinden ayarlanabildiğini
// tarayıcı seviyesinde garanti eder (isim sahtekarlığına karşı ek bir katman).
// ============================================================================

function serializeCookie(name, value, {
  domain, path = '/', maxAgeSeconds, expires, httpOnly = true, secure = true, sameSite = 'Lax',
} = {}) {
  const parts = [`${name}=${value}`];
  if (domain) parts.push(`Domain=${domain}`);
  parts.push(`Path=${path}`);
  if (typeof maxAgeSeconds === 'number') parts.push(`Max-Age=${Math.floor(maxAgeSeconds)}`);
  if (expires) parts.push(`Expires=${expires.toUTCString()}`);
  if (httpOnly) parts.push('HttpOnly');
  if (secure) parts.push('Secure');
  if (sameSite) parts.push(`SameSite=${sameSite}`);
  return parts.join('; ');
}

function expireCookie(name, opts = {}) {
  return serializeCookie(name, '', { ...opts, maxAgeSeconds: 0, expires: new Date(0) });
}

module.exports = { serializeCookie, expireCookie };
