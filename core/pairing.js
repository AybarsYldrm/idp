'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

// İki süreci birbirine bağlayan değerlerin taşındığı yer.
//
// Bu dosya var, çünkü elle yapılandırma çalışmıyordu. Bir IdP'yi veritabanına bağlamak şunları
// gerektiriyordu: denetim düzlemi sırrını veritabanının stdout'undan kopyala, hedef adresi yaz,
// önyükleme parmak izini yaz, kayıt otoritesi istemci kimliğini ve sırrını üret ve İKİ tarafa da
// gir. Beş değer, iki süreç, ikisi de yanlış yazıldığında anlaşılmaz bir TLS hatası veriyor.
//
// Şimdi tek bir dizin var. Veritabanı açılışta ne bildiğini oraya yazar, IdP okur; IdP kendi
// tarafını yazar, veritabanı okur. Ayarlanacak tek değer dizinin kendisi ve onun bir varsayılanı
// var.
//
//
// BU BİR SIR DEPOSU DEĞİL
//
// Dizin iki sır taşıyor: veritabanının denetim düzlemi sırrı ve kayıt otoritesinin istemci
// sırrı. İkisi de ZATEN diskte duruyordu (`.db-state/control-plane-secret` ve IdP'nin ortam
// değişkeni), yani bu yeni bir açıklık sınıfı değil -- aynı sırlar, üzerinde anlaşılmış bir
// yerde. Kazanç, artık kimsenin onları terminalden kopyalamıyor olması.
//
// Kazanç olmayan şey: bu dizini okuyabilen bir süreç veritabanının sunucu kimliğini
// değiştirebilir. O yüzden dizin 0700, dosyalar 0600 ve izinler her okumada kontrol ediliyor --
// fazla açık olduğunda sessizce devam etmek yerine yüksek sesle uyarılıyor.
//
// KÖK CA ANAHTARI BURAYA ASLA YAZILMAZ. O şifreli kasada durur ve oradan çıkmaz; buraya
// yazılan tek PKI verisi kökün SERTİFİKASI ve parmak izidir, ikisi de açık veridir.

const DATABASE_FILE = 'database.json';
const IDP_FILE = 'idp.json';

/**
 * Eşleştirme dizininin yeri.
 *
 * Sıra: açık ayar, sonra sistem geneli yol, sonra kullanıcı ev dizini. Sonuncusu geliştirme
 * içindir ve tek kullanıcılı bir makinede doğru cevaptır; üretimde iki servis genelde farklı
 * kullanıcılar olarak koşar ve o zaman ortak bir dizin açıkça verilir.
 */
function pairingDir(explicit = null) {
  if (explicit) return explicit;
  if (process.env.FITFAK_PAIRING_DIR) return process.env.FITFAK_PAIRING_DIR;
  if (fs.existsSync('/var/lib/fitfak')) return '/var/lib/fitfak/pairing';
  return path.join(os.homedir(), '.fitfak', 'pairing');
}

async function ensureDir(dir) {
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  // mkdir'in mode'u umask ile maskelenir, yani 0700 istemek 0700 almak değildir. Sonradan
  // chmod etmek tek güvenilir yol.
  await fsp.chmod(dir, 0o700).catch(() => {});
  return dir;
}

/**
 * İzinleri kontrol eder ve fazla açıksa uyarır.
 *
 * Reddetmiyor, uyarıyor. Bir dağıtımın bu dizini paylaşılan bir gruba açması meşru bir tercih
 * olabilir; sessizce kabul etmek ise değil. Fark, operatörün bunu SEÇMİŞ olup olmadığıdır ve
 * uyarı o soruyu sorar.
 */
async function checkPermissions(file, logger) {
  try {
    const stat = await fsp.stat(file);
    const mode = stat.mode & 0o777;
    if (mode & 0o077) {
      logger?.warn?.({
        file,
        mode: mode.toString(8),
        msg: 'eşleştirme dosyası sahibi dışındakilere açık — bu dosyayı okuyabilen bir süreç '
          + 'veritabanının sunucu kimliğini değiştirebilir',
      });
    }
  } catch (_) { /* yoksa okuyan taraf zaten fark eder */ }
}

async function writeJson(dir, name, payload, logger) {
  await ensureDir(dir);
  const file = path.join(dir, name);
  const tmp = `${file}.tmp`;
  // 0600 ve önce geçici dosyaya, sonra rename. Doğrudan yazmak, süreç yazarken ölürse yarım
  // bir dosya bırakır ve karşı taraf onu "var ama bozuk" olarak bulur.
  await fsp.writeFile(tmp, JSON.stringify({ ...payload, writtenAt: Date.now() }, null, 2), { mode: 0o600 });
  await fsp.chmod(tmp, 0o600).catch(() => {});
  await fsp.rename(tmp, file);
  logger?.debug?.({ file, msg: 'eşleştirme dosyası yazıldı' });
  return file;
}

async function readJson(dir, name, logger) {
  const file = path.join(dir, name);
  if (!fs.existsSync(file)) return null;
  await checkPermissions(file, logger);
  try {
    return JSON.parse(await fsp.readFile(file, 'utf8'));
  } catch (err) {
    logger?.warn?.({ file, error: err.message, msg: 'eşleştirme dosyası okunamadı' });
    return null;
  }
}

/** Veritabanının yazdığı: nereye bağlanılacağı ve denetim düzleminin sırrı. */
async function publishDatabase({ dir, target, controlSecret, bootstrapFingerprint, trustDomain, logger }) {
  return writeJson(pairingDir(dir), DATABASE_FILE, {
    target,
    controlSecret: Buffer.isBuffer(controlSecret) ? controlSecret.toString('base64') : controlSecret,
    bootstrapFingerprint,
    trustDomain,
  }, logger);
}

async function readDatabase({ dir, logger } = {}) {
  const raw = await readJson(pairingDir(dir), DATABASE_FILE, logger);
  if (!raw) return null;
  return {
    ...raw,
    controlSecret: raw.controlSecret ? Buffer.from(raw.controlSecret, 'base64') : null,
  };
}

/**
 * IdP'nin yazdığı: veritabanının kayıt otoritesi olarak IdP'ye başvurmak için ihtiyaç duyduğu
 * her şey, artı güven çıpası, artı yönetim panelinin giriş için kullanacağı OAuth istemcisi.
 *
 * İKİ AYRI İSTEMCİ, ve bu bir özen meselesi değil.
 *
 *   raClient*      "bu CSR şu kimlikle imzalansın" demeye yetkilidir
 *   panelClient*   "şu kişi giriş yapıyor, kim ve yönetici mi" diye sormaya yetkilidir
 *
 * Tek bir istemciyi ikisi için de kullanmak, panelin giriş sırrını ele geçiren birine sertifika
 * imzalatma yetkisi vermek olurdu. Ayrı olduklarında birinin sızması diğerini vermez.
 *
 * Sırlar buraya yazılıyor. Alternatif, operatörün onları üretip iki yere girmesiydi -- yani tam
 * olarak çalışmadığı görülen şey.
 */
async function publishIdp({
  dir, issuer, issuanceUrl, anchorsUrl, raClientId, raClientSecret,
  panelClientId, panelClientSecret, rootFingerprint, rootCertPem, trustDomain, logger,
}) {
  return writeJson(pairingDir(dir), IDP_FILE, {
    issuer,
    issuanceUrl,
    anchorsUrl,
    raClientId,
    raClientSecret,
    panelClientId,
    panelClientSecret,
    rootFingerprint,
    rootCertPem,
    trustDomain,
  }, logger);
}

async function readIdp({ dir, logger } = {}) {
  return readJson(pairingDir(dir), IDP_FILE, logger);
}

module.exports = {
  pairingDir,
  publishDatabase,
  readDatabase,
  publishIdp,
  readIdp,
  DATABASE_FILE,
  IDP_FILE,
};
