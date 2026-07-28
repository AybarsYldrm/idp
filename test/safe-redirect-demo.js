'use strict';

const { safeRedirect, assertSafeRedirect } = require('../core/safe-redirect');

// Açık yönlendirme (open redirect) zafiyetinin kapatıldığının doğrulanması.
//
// demo-login.html, `?return_to=` değerini doğrudan `location.href`'e yazıyordu.
// Sonuç: kullanıcı gerçek alan adında, gerçek sertifikayla, gerçek giriş
// formunda kimliğini doğruluyor ve hemen ardından saldırganın sayfasına
// iniyordu -- şüphelenmesi için hiçbir sebep olmadan.
//
// Aşağıdaki varyasyonların çoğu, "http ile başlıyor mu" ya da "/ ile başlıyor
// mu" gibi tek satırlık kontrolleri geçer. Bu yüzden izin verilenleri saymak
// (allow-list) dışında bir yaklaşım bu problemde güvenilir değildir.

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

const SELF = 'https://session.fitfak.net';

function rejects(target) {
  try { assertSafeRedirect(target, { selfOrigin: SELF }); return false; }
  catch (_) { return true; }
}

function main() {
  console.log('\n[1] Dış alan adına yönlendirme reddedilir');
  const external = [
    'https://evil.com',
    'http://evil.com/path',
    'https://evil.com@session.fitfak.net',      // userinfo ile gerçek host'u taklit
    'https://session.fitfak.net.evil.com',      // sondan ekleme
    'https://session.fitfak.net@evil.com',      // userinfo -- gerçek hedef evil.com
  ];
  for (const t of external) check(`reddedildi: ${t}`, rejects(t));

  console.log('\n[2] Protokol-göreli biçim -- en sık kaçırılan varyasyon');
  // Bunlar `/` ile başlar, yani "yerel yol mu?" kontrolünü geçer, ama tarayıcı
  // onları dış alan adı olarak çözer.
  for (const t of ['//evil.com', '//evil.com/path', '///evil.com', '/\\evil.com', '\\\\evil.com', '/\\/evil.com']) {
    check(`reddedildi: ${JSON.stringify(t)}`, rejects(t));
  }

  console.log('\n[3] Şema taşıyan yükler yönlendirme değil, kod çalıştırmadır');
  for (const t of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox', 'java\tscript:alert(1)', 'java\nscript:alert(1)', ' javascript:alert(1)']) {
    check(`reddedildi: ${JSON.stringify(t.slice(0, 28))}`, rejects(t));
  }

  console.log('\n[4] Yüzde-kodlu kaçışlar');
  for (const t of ['/%2f%2fevil.com', '/%2F%2Fevil.com', '/%252f%252fevil.com', '/%5c%5cevil.com']) {
    check(`reddedildi: ${t}`, rejects(t));
  }

  console.log('\n[5] Meşru yerel yollar kabul edilir');
  check('/portal', assertSafeRedirect('/portal', { selfOrigin: SELF }) === '/portal');
  check('sorgu dizesi korunur',
    assertSafeRedirect('/oauth/authorize?client_id=x&state=y', { selfOrigin: SELF })
      === '/oauth/authorize?client_id=x&state=y');
  check('fragment korunur',
    assertSafeRedirect('/portal#sessions', { selfOrigin: SELF }) === '/portal#sessions');
  check('kendi origin\'imize mutlak URL yola indirgenir',
    assertSafeRedirect(`${SELF}/portal?a=1`, { selfOrigin: SELF }) === '/portal?a=1');
  check('yol normalize edilir',
    assertSafeRedirect('/a/b/../../portal', { selfOrigin: SELF }) === '/portal');

  console.log('\n[6] Allow-list ile dış yönlendirme');
  const opts = { selfOrigin: SELF, allowedHosts: ['fitfak.net', '.apps.fitfak.net'] };
  check('tam eşleşen host kabul edilir',
    assertSafeRedirect('https://fitfak.net/welcome', opts) === 'https://fitfak.net/welcome');
  check('izin verilen alt alan adı kabul edilir',
    assertSafeRedirect('https://dns.apps.fitfak.net/x', opts) === 'https://dns.apps.fitfak.net/x');
  check('benzeyen ama farklı alan adı reddedilir',
    rejects('https://evil-fitfak.net') && (() => {
      try { assertSafeRedirect('https://evil-fitfak.net', opts); return false; } catch (_) { return true; }
    })());
  // 'evilfitfak.net' sonu 'fitfak.net' ile biter ama BAŞKA bir alan adıdır --
  // sadece endsWith kullanan bir kontrol burada yenilir.
  let suffixTrap = false;
  try { assertSafeRedirect('https://evilfitfak.net/x', opts); } catch (_) { suffixTrap = true; }
  check('sonek tuzağı (evilfitfak.net) reddedilir', suffixTrap);

  let httpExternal = false;
  try { assertSafeRedirect('http://fitfak.net/x', opts); } catch (_) { httpExternal = true; }
  check('dış yönlendirme https olmak zorunda', httpExternal);

  console.log('\n[7] safeRedirect her zaman güvenli bir değer döner');
  check('geçersiz girdi fallback\'e düşer',
    safeRedirect('https://evil.com', { fallback: '/portal', selfOrigin: SELF }) === '/portal');
  check('boş girdi fallback\'e düşer', safeRedirect('', { fallback: '/portal' }) === '/portal');
  check('null fallback\'e düşer', safeRedirect(null, { fallback: '/portal' }) === '/portal');
  check('undefined fallback\'e düşer', safeRedirect(undefined, { fallback: '/portal' }) === '/portal');
  check('geçerli girdi korunur',
    safeRedirect('/portal?x=1', { fallback: '/', selfOrigin: SELF }) === '/portal?x=1');

  console.log(`\nOK - güvenli yönlendirme: ${checks} kontrol geçti.`);
}

main();
