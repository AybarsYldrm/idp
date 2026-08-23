'use strict';

const path = require('node:path');

const consent = require('../services/consent-service');

// BELGE KAPSAMLARI VE PAKET DIŞA AKTARIMLARI.
//
// Belge Stüdyosu ve posta sunucusu, kullanıcının belgelerine bu paket
// üzerinden erişiyor. İki şey doğru olmak zorunda ve ikisi de sessizce
// yanlış olabilir:
//
//   1. ONAY EKRANI NE VERİLDİĞİNİ SÖYLEMELİ. Katalogda olmayan bir kapsam
//      "sensitive" sayılıp "ne olduğu tanımlı değil" diye gösteriliyor --
//      doğru ama işe yaramaz. Kullanıcı `documents:write` onaylarken
//      belgelerinin silinebileceğini ve paylaşılabileceğini bilmeli.
//
//   2. İSTEMCİLER PAKETİ ÇÖZEBİLMELİ. `client/join-fitfak.js` bu deponun
//      dışından (@fitfak/workspace) çağrılıyor. `exports` haritasında
//      yoksa Node onu bulamaz ve çalışma alanı katmanı sessizce dosya
//      sürücüsüne düşer -- yani SPIFFE yerine tek makinelik bir depo.
//      "Çalışıyor ama yanlış yerde çalışıyor", bulunması en zor hâl.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

/* ── 1. kapsam kataloğu ────────────────────────────────────── */

const DOCUMENT_SCOPES = [
  'documents:read', 'documents:write', 'documents:sign', 'mail:read', 'mail:send',
];

for (const scope of DOCUMENT_SCOPES) {
  const described = consent.describeScope(scope);
  check(`${scope} katalogda tanımlı`,
    described.title !== scope && described.detail.length > 40);
}

// Yazma ve imzalama HASSAS: kullanıcıya onay ekranında ayırt edilebilir
// görünmeli. Okuma hassas değil ve öyle işaretlenmemeli -- her şeyi
// hassas saymak, hiçbir şeyi hassas saymamakla aynı sonucu verir.
check('documents:read hassas değil', consent.describeScope('documents:read').sensitive === false);
check('documents:write hassas', consent.describeScope('documents:write').sensitive === true);
check('documents:sign hassas', consent.describeScope('documents:sign').sensitive === true);
check('mail:read hassas', consent.describeScope('mail:read').sensitive === true);
check('mail:send hassas', consent.describeScope('mail:send').sensitive === true);

// İmza kapsamının açıklaması, ANAHTARIN VERİLMEDİĞİNİ söylemeli:
// kullanıcı "belgelerimi imzalayabilir" ile "anahtarımı alabilir"
// arasındaki farkı onay ekranından anlamalı.
check('documents:sign anahtarın tarayıcıda kaldığını söylüyor',
  /tarayıcı/i.test(consent.describeScope('documents:sign').detail));

/* ── 2. kapsam kısıtlaması gerçekten uygulanıyor ───────────── */

const client = { allowedScopes: ['openid', 'profile', 'documents:read'] };

check('izin verilen kapsam kabul ediliyor',
  consent.resolveRequestedScopes({ requested: 'openid documents:read', client })
    .includes('documents:read'));

let rejected = null;
try {
  consent.resolveRequestedScopes({ requested: 'openid documents:write', client });
} catch (err) { rejected = err.message; }
check('izin verilmeyen kapsam reddediliyor',
  rejected !== null && /documents:write/.test(rejected));

// Kapsam hiç istenmezse istemcinin kayıtlı listesi varsayılan (RFC 6749
// §3.3). Boş liste dönmek, bir uygulamanın hiçbir şey isteyemez hâle
// gelmesi demekti.
check('kapsam istenmediğinde kayıtlı liste varsayılan',
  consent.resolveRequestedScopes({ requested: '', client }).length === 3);

/* ── 3. paket dışa aktarımları ─────────────────────────────── */

const pkg = require('../package.json');
check('package.json exports haritası var', !!pkg.exports);

for (const [subpath, target] of Object.entries(pkg.exports)) {
  if (subpath === './package.json') continue;
  const resolved = path.join(__dirname, '..', target);
  check(`${subpath} -> ${target} çözülüyor`, (() => {
    try { require.resolve(resolved); return true; } catch { return false; }
  })());
}

// Çalışma alanı katmanının aradığı TAM yol.
const join = require('../client/join-fitfak');
check('join-fitfak joinFitfak dışa aktarıyor', typeof join.joinFitfak === 'function');
check('join-fitfak joinFitfakWhenReady dışa aktarıyor',
  typeof join.joinFitfakWhenReady === 'function');
check('exports haritası ./join yolunu içeriyor', pkg.exports['./join'] === './client/join-fitfak.js');

/* ── 4. belge stüdyosu iş yükü kaydı ───────────────────────── */

// WORKLOAD_REGISTRY oauth-server.js içinde ve sunucuyu ayağa kaldırmadan
// okunamıyor; kaynak metninden doğrulanıyor. Kaba ama doğru: kayıt
// eksikse Belge Stüdyosu veritabanına SPIFFE kimliğiyle bağlanamaz ve
// kayıt sırrını elle tutturmak zorunda kalır.
const fs = require('node:fs');
const serverSource = fs.readFileSync(path.join(__dirname, '..', 'oauth-server.js'), 'utf8');
check('belge-studio iş yükü kaydında',
  /'belge-studio':\s*\{\s*requiredScope:\s*'identity:workload'/.test(serverSource));

console.log(`\n${checks} kontrol geçti.`);
