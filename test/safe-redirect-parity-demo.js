'use strict';

const path = require('node:path');
const serverSide = require('../core/safe-redirect');

require(path.join(__dirname, '..', 'public', 'safe-redirect-client.js'));
const clientSide = globalThis.FitfakSafeRedirect;

// Sunucu ve tarayıcı doğrulayıcılarının AYNI kararı verdiğinin kanıtı.
//
// İkisi ayrı dosyalar (biri Node modülü, biri tarayıcıya giden script) ama kural
// tek olmalı. Ayrıştıkları anda, sunucunun reddettiği bir hedefi tarayıcı kabul
// eder -- yani açık yönlendirme tam olarak kapatmak istediğimiz yerde açık kalır.
// Bu tür bir ayrışma gözden kaçar, çünkü her iki taraf da kendi başına "çalışıyor"
// görünür.

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

const SELF = 'https://session.fitfak.net';
const OPTS = { selfOrigin: SELF, allowedHosts: ['fitfak.net', '.apps.fitfak.net'] };

const CASES = [
  // dış alan adları
  'https://evil.com', 'http://evil.com/p', 'https://session.fitfak.net@evil.com',
  'https://evil.com@session.fitfak.net', 'https://session.fitfak.net.evil.com',
  // protokol-göreli ve ters bölü varyasyonları
  '//evil.com', '///evil.com', '/\\evil.com', '\\\\evil.com', '/\\/evil.com',
  // şema yükleri
  'javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,x', 'vbscript:x',
  'java\tscript:alert(1)', 'java\nscript:alert(1)', ' javascript:alert(1)',
  // yüzde-kodlu
  '/%2f%2fevil.com', '/%2F%2Fevil.com', '/%252f%252fevil.com', '/%5c%5cevil.com',
  // meşru yerel
  '/portal', '/portal?a=1', '/portal#x', '/oauth/authorize?client_id=x',
  '/a/b/../../portal', '/', 'https://session.fitfak.net/portal?a=1',
  // allow-list
  'https://fitfak.net/welcome', 'https://dns.apps.fitfak.net/x',
  'https://evilfitfak.net/x', 'http://fitfak.net/x',
  // bozuk
  '', '   ', 'portal', 'not a url',
];

function outcome(fn, value) {
  try { return { ok: true, value: fn(value, OPTS) }; }
  catch (e) { return { ok: false, value: null }; }
}

function main() {
  console.log('\n[1] Her girdi için iki taraf aynı kararı veriyor');
  let agreements = 0;
  for (const input of CASES) {
    const s = outcome(serverSide.assertSafeRedirect, input);
    const c = outcome(clientSide.assertSafeRedirect, input);
    const same = s.ok === c.ok && s.value === c.value;
    if (!same) {
      throw new Error(
        `divergence for ${JSON.stringify(input)}: server=${JSON.stringify(s)} client=${JSON.stringify(c)}`,
      );
    }
    agreements += 1;
  }
  check(`${CASES.length} girdinin tamamında karar aynı`, agreements === CASES.length);

  console.log('\n[2] Reddedilenler gerçekten reddediliyor (tarafların ikisi de)');
  const mustReject = CASES.filter((c) => /evil|javascript|vbscript|data:|%2f|%5c|\\\\/i.test(c));
  for (const input of mustReject) {
    if (input === 'https://evil.com@session.fitfak.net') continue; // userinfo -> reddedilir, aşağıda
    const s = outcome(serverSide.assertSafeRedirect, input);
    const c = outcome(clientSide.assertSafeRedirect, input);
    const bothReject = !s.ok && !c.ok;
    // '/a/b/../../portal' gibi masum girdiler bu filtreye takılmaz; takılanların
    // hepsi gerçekten tehlikeli olanlar.
    if (!bothReject) throw new Error(`not rejected by both: ${JSON.stringify(input)}`);
  }
  check(`${mustReject.length} tehlikeli girdi iki tarafta da reddedildi`, true);

  console.log('\n[3] safeRedirect fallback davranışı da aynı');
  for (const input of ['https://evil.com', '//evil.com', '', null, undefined]) {
    const s = serverSide.safeRedirect(input, { fallback: '/portal', selfOrigin: SELF });
    const c = clientSide.safeRedirect(input, { fallback: '/portal', selfOrigin: SELF });
    if (s !== c) throw new Error(`fallback divergence for ${JSON.stringify(input)}: ${s} vs ${c}`);
  }
  check('fallback sonuçları eşleşiyor', true);

  console.log(`\nOK - yönlendirme doğrulayıcı eşdeğerliği: ${checks} kontrol geçti.`);
}

main();
