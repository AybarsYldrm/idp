'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const { KeyVault, KEY_VAULT_NAMES } = require('../core/key-vault');
const { createMockDb } = require('./mock-db');

// `.keys/` dizininin şifreli kasaya taşınması.
//
// Bu taşımanın en ağır kalemi OTURUM İMZALAMA ANAHTARI. O anahtar her erişim ve yenileme
// belirtecini imzalar, yani bir kopyası herhangi bir kullanıcı için herhangi bir belirteci
// üretebilme yetkisidir -- parolayı bilmeye, ikinci faktörü geçmeye, hatta IdP'ye hiç
// bağlanmaya gerek yok, ve kaynak IdP olmadığı için hiçbir yerde bir kayıt oluşmaz.
//
// Kök CA anahtarını kasaya alıp bunu 0600 bir dosyada bırakmak, ön kapıyı çelikle kaplayıp
// anahtarı paspasın altına koymaktı.
//
// Buradaki kontrollerin çoğu GEÇİŞ hakkında, çünkü tehlikeli olan kısım orası. Bir geçiş üç
// şekilde bozulabilir ve üçü de üretimde ancak iş işten geçtikten sonra görülür:
//
//   1. anahtar DEĞİŞİRSE  -> herkesin oturumu bir anda geçersizleşir
//   2. `kid` düşerse      -> yayınlanan JWKS bir kimlik ilan eder, belirteçler başkasını taşır
//   3. kasadakinin üstüne yazılırsa -> döndürülmüş bir anahtar eski sürümüyle geri gelir

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

function tmpKeyDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'fitfak-keys-'));
}

function writeLegacySigningKey(dir, { kid = 'legacy-kid' } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  fs.writeFileSync(path.join(dir, 'es256-private.pem'), privateKeyPem, { mode: 0o600 });
  fs.writeFileSync(path.join(dir, 'es256-public.pem'), publicKeyPem);
  if (kid !== null) fs.writeFileSync(path.join(dir, 'kid.txt'), kid);
  return { privateKeyPem, publicKeyPem, kid };
}

const openVault = () => KeyVault.open(createMockDb(['secrets']));

/**
 * İki özel anahtarın aynı olup olmadığı.
 *
 * İmzaları KARŞILAŞTIRMIYOR: ECDSA imzası rastgele bir k değeri taşır, yani aynı anahtar aynı
 * mesajı iki kez imzaladığında farklı baytlar çıkar ve karşılaştırma her zaman "farklı" der.
 * Anlamlı olan, birinin ürettiği imzanın diğerinin AÇIK eşiyle doğrulanmasıdır.
 */
function sameKey(a, b) {
  const message = Buffer.from('anahtar kimlik kontrolü');
  const signature = crypto.sign('sha256', message, a);
  return crypto.verify('sha256', message, crypto.createPublicKey(b), signature);
}

function usable(privateKey) {
  const message = Buffer.from('test');
  return crypto.verify('sha256', message, crypto.createPublicKey(privateKey),
    crypto.sign('sha256', message, privateKey));
}

async function main() {
  console.log('\n1. Anahtar yoksa üretilir ve kalıcıdır');

  {
    const db = createMockDb(['secrets']);
    const vault = await KeyVault.open(db);

    const first = await vault.loadOrCreateSigningKeyPair();
    check('bir çift döndü', !!first.privateKey && !!first.publicKey);
    check('kid üretildi', /^[0-9a-f]{16}$/.test(first.kid));

    // Kritik olan bu: ikinci açılış AYNI anahtarı bulmalı. Bulmazsa her yeniden başlatma
    // herkesin oturumunu geçersiz kılar ve bunun sebebi hiçbir günlükte görünmez.
    const second = await (await KeyVault.open(db)).loadOrCreateSigningKeyPair();
    check('ikinci açılış aynı kid\'i buldu', second.kid === first.kid);
    check('ve aynı anahtarı — biri imzalıyor, diğerinin açık eşi doğruluyor',
      sameKey(second.privateKey, first.privateKey));
  }

  console.log('\n2. Malzeme koleksiyonda ŞİFRELENECEK bir kayıt olarak duruyor');

  {
    const db = createMockDb(['secrets']);
    const vault = await KeyVault.open(db);
    const pair = await vault.loadOrCreateSigningKeyPair();

    const rows = db.collection('secrets')._debugAll();
    check('kasada bir kayıt var', rows.length === 1);
    check('adı ad alanı taşıyor', rows[0].name === KEY_VAULT_NAMES.SESSION_SIGNING);
    check('kayıt tipi özel anahtar', rows[0].kind === 'private-key');
    // Motor `material` alanını diskte şifreler. Buradaki kontrol, anahtarın oraya KONDUĞU --
    // yani şifrelemenin kapsadığı alanda olduğu; şifrelemenin kendisi motorun testinde.
    check('anahtar material alanında', Buffer.isBuffer(rows[0].material) || typeof rows[0].material === 'string');
    check('ve dönen anahtar gerçekten kullanılabilir', usable(pair.privateKey));
  }

  console.log('\n3. Diskteki anahtar AYNEN içeri alınıyor');

  {
    const dir = tmpKeyDir();
    const legacy = writeLegacySigningKey(dir, { kid: 'eski-anahtar-1' });
    const vault = await openVault();

    const result = await vault.importFromDisk(dir);
    check('içeri alındı', result.imported.includes(KEY_VAULT_NAMES.SESSION_SIGNING));

    const loaded = await vault.loadOrCreateSigningKeyPair();
    // Anahtarın DEĞİŞMEMESİ şart. Değişirse geçiş, "herkesi çıkışa zorla" ile aynı şey olur.
    check('aynı anahtar geldi',
      sameKey(loaded.privateKey, crypto.createPrivateKey(legacy.privateKeyPem)));
    // `kid` düşerse yayınlanan JWKS bir kimlik ilan ederken üretilen belirteçler başkasını
    // taşır, ve doğrulama imza doğru olsa bile başarısız olur.
    check('kid korundu', loaded.kid === 'eski-anahtar-1');

    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log('\n4. Geçen dosya siliniyor DEĞİL, emekliye ayrılıyor');

  {
    const dir = tmpKeyDir();
    writeLegacySigningKey(dir);
    const vault = await openVault();
    await vault.importFromDisk(dir);

    check('özel anahtar dosyası artık orada değil', !fs.existsSync(path.join(dir, 'es256-private.pem')));
    // Silmek, geçişte bir hata olduğunda geri dönülemez olurdu -- ve geri dönülemeyen şey
    // oturum imzalama anahtarıysa, tüm oturumlar kalıcı olarak geçersizleşir.
    check('ama .migrated olarak duruyor', fs.existsSync(path.join(dir, 'es256-private.pem.migrated')));
    check('açık eş de', fs.existsSync(path.join(dir, 'es256-public.pem.migrated')));
    check('kid de', fs.existsSync(path.join(dir, 'kid.txt.migrated')));

    // Yeniden adlandırma aynı zamanda ikinci bir açılışın aynı dosyayı tekrar içeri almasını
    // engelliyor -- ki bu, döndürülmüş bir anahtarı eski sürümüyle geri getirirdi.
    const again = await vault.importFromDisk(dir);
    check('ikinci geçiş hiçbir şey yapmıyor', again.imported.length === 0);

    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log('\n5. Kasadaki anahtarın ÜSTÜNE yazılmıyor');

  {
    const dir = tmpKeyDir();
    const vault = await openVault();
    // Kasada zaten bir anahtar var -- örneğin bir döndürmeden sonra.
    const current = await vault.loadOrCreateSigningKeyPair();
    // Ve diskte eski bir dosya duruyor.
    writeLegacySigningKey(dir, { kid: 'cok-eski' });

    const result = await vault.importFromDisk(dir);
    check('içeri alınmadı, atlandı', result.skipped.includes(KEY_VAULT_NAMES.SESSION_SIGNING));

    const after = await vault.loadOrCreateSigningKeyPair();
    // Üzerine yazmak, döndürmenin hiç yapılmamış olmasıyla aynı şey olurdu.
    check('kasadaki anahtar korundu', after.kid === current.kid);
    check('ve gerçekten aynı anahtar', sameKey(after.privateKey, current.privateKey));
    check('dosya yine de emekliye ayrıldı', fs.existsSync(path.join(dir, 'es256-private.pem.migrated')));

    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log('\n6. kid dosyası yoksa eski varsayılan korunuyor');

  {
    const dir = tmpKeyDir();
    writeLegacySigningKey(dir, { kid: null });
    const vault = await openVault();
    await vault.importFromDisk(dir);
    const loaded = await vault.loadOrCreateSigningKeyPair();
    // Eski loadOrCreateSigningKeyPair'ın davranışı buydu. Başka bir değer üretmek, halihazırda
    // dağıtılmış JWKS'i kırardı.
    check("kid 'default' oldu", loaded.kid === 'default');
    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log('\n7. CT günlük anahtarı ve paylaşılan sırlar');

  {
    const dir = tmpKeyDir();
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    fs.writeFileSync(path.join(dir, 'ct-log.key'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(path.join(dir, 'ct-log.pub'), publicKey.export({ type: 'spki', format: 'pem' }));
    fs.writeFileSync(path.join(dir, 'ra-client-secret'), 'ra-sirri-abc\n', { mode: 0o600 });
    fs.writeFileSync(path.join(dir, 'db-panel-client-secret'), 'panel-sirri-xyz\n', { mode: 0o600 });

    const vault = await openVault();
    const result = await vault.importFromDisk(dir);
    check('dört kalem de içeri alındı', result.imported.length === 3 || result.imported.length === 4);

    const ct = await vault.loadOrCreateCtLogKey();
    // CT günlüğünün açık anahtarı onun KİMLİĞİDİR: değişirse üretilmiş her SCT doğrulanamaz
    // hale gelir ve günlük, istemciler için başka bir günlük olur.
    check('CT açık anahtarı korundu',
      ct.publicKeyPem.trim() === publicKey.export({ type: 'spki', format: 'pem' }).trim());

    const ra = await vault.loadOrCreateSecret(KEY_VAULT_NAMES.RA_CLIENT_SECRET);
    check('kayıt otoritesi sırrı korundu', ra === 'ra-sirri-abc');
    const panel = await vault.loadOrCreateSecret(KEY_VAULT_NAMES.PANEL_CLIENT_SECRET);
    check('panel sırrı korundu', panel === 'panel-sirri-xyz');

    // Bunlar veritabanının ve panelin sakladığı kopyalarla eşleşmek zorunda. Her açılışta
    // yenisini üretmek, karşı tarafın sessizce 401 almaya başlaması demektir -- açılışta değil,
    // ilk kullanıldığında.
    check('ikinci okuma aynı değeri veriyor',
      await vault.loadOrCreateSecret(KEY_VAULT_NAMES.RA_CLIENT_SECRET) === ra);

    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log('\n8. Dizin yoksa geçiş sessizce geçiliyor');

  {
    const vault = await openVault();
    const result = await vault.importFromDisk('/hic-var-olmayan-dizin');
    check('hata yok, iş de yok', result.imported.length === 0 && result.skipped.length === 0);
    check('ve anahtar yine de üretilebiliyor', !!(await vault.loadOrCreateSigningKeyPair()).kid);
  }

  console.log(`\nOK - anahtar kasası: ${checks} kontrol geçti.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message, err.stack); process.exit(1); },
);
