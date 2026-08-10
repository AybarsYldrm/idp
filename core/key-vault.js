'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

// `.keys/` dizininin sonu.
//
// CA anahtarları core/ca-vault.js ile şifreli sır deposuna taşınmıştı. Geriye dosyada duran
// üç şey kaldı ve hepsi aynı gerekçeyle oraya ait:
//
//     .keys/es256-private.pem      OTURUM İMZALAMA ANAHTARI                        0600
//     .keys/es256-public.pem       (açık eş, jwks.json'da yayınlanıyor)
//     .keys/kid.txt                (anahtar kimliği)
//     .keys/ct-log.key             CT günlüğünün imzalama anahtarı                 0600
//     .keys/ct-log.pub             (açık eş, günlüğün kimliği)
//     .keys/ra-client-secret       veritabanının kayıt otoritesi istemci sırrı     0600
//     .keys/db-panel-client-secret veritabanı panelinin OAuth istemci sırrı        0600
//
// 0600 korumanın TAMAMIYDI. O kullanıcı olarak dosya sistemini okuyabilen her şey bunları okur:
// bir yedekleme işi, bir konteyner imaj katmanı, fazla geniş bir glob ile çalışan bir log
// toplayıcı, `docker cp`, süreçteki başka bir yerdeki dizin-aşımı hatası.
//
// VE BUNLARIN İLKİ EN AĞIRI. `es256-private.pem` her erişim ve yenileme belirtecini imzalayan
// anahtardır: onun bir kopyası, herhangi bir kullanıcı için herhangi bir belirteci üretebilme
// yetkisidir. Parolayı bilmeye, ikinci faktörü geçmeye, hatta IdP'ye hiç bağlanmaya gerek yok --
// ve kaynak IdP olmadığı için hiçbir yerde bir kayıt oluşmaz. Kök CA anahtarını kasaya alıp bunu
// dosyada bırakmak, ön kapıyı çelikle kaplayıp anahtarı paspasın altına koymaktı.
//
// Artık üçü de `secrets` koleksiyonunda: motorun DDK'sından türetilmiş bir anahtarla diskte
// şifreli, sürümlü, ve CA malzemesiyle aynı denetim izine tabi.
//
//
// NEDEN CA DEPOSUNDA (uzak veritabanında değil)
//
// Aynı kilit: uzak veritabanı, IdP ona bir sunucu sertifikası verene kadar mühürlü bekler ve o
// sertifikayı üretmek için CA gerekir. Oturum imzalama anahtarı da açılışın ilk adımlarında
// lazım. İkisi de IdP'nin YANINDAKİ gömülü depoda -- aynı şifreleme, ağ yok, bağımlılık yok.
//
//
// GEÇİŞ TEK YÖNLÜ
//
// Dosya varsa içeri alınır ve `.migrated` uzantısıyla yeniden adlandırılır; silinmez. Silmek,
// geçişte bir hata olduğunda geri dönülemez olurdu -- ve geri dönülemeyen şey oturum imzalama
// anahtarıysa, tüm oturumlar geçersizleşir. Yeniden adlandırmak, bir sonraki açılışın aynı
// dosyayı ikinci kez içeri almasını da engeller.

const { SecretStore, SECRET_KINDS } = require('@fitfak/database');

// İsimler kasada bir ad alanı altında: CA malzemesi 'pki/' altında duruyor, bunlar 'idp/'.
// Ayrı olmaları, "kasada ne var" sorusunun cevabını okunur tutuyor.
const NAMES = Object.freeze({
  SESSION_SIGNING: 'idp/session-signing-key',
  CT_LOG: 'idp/ct-log-key',
  RA_CLIENT_SECRET: 'idp/ra-client-secret',
  PANEL_CLIENT_SECRET: 'idp/db-panel-client-secret',
});

class KeyVault {
  constructor({ secrets, logger = null }) {
    this.secrets = secrets;
    this._log = logger;
  }

  static async open(db, { logger = null } = {}) {
    const secrets = await SecretStore.open(db, { collection: 'secrets' });
    return new KeyVault({ secrets, logger });
  }

  // ---- oturum imzalama anahtarı ---------------------------------------------------------------

  /**
   * ES256 oturum imzalama çifti.
   *
   * `kid` üretilip malzemeyle birlikte saklanıyor. Ayrı bir dosyada tutulsaydı (eskiden öyleydi)
   * anahtarla kimliğinin ayrı düşmesi mümkün olurdu: yayınlanan JWKS bir `kid` ilan ederken
   * imzalanan belirteçler başkasını taşır ve doğrulama, imza doğru olsa bile başarısız olur.
   */
  async loadOrCreateSigningKeyPair() {
    const existing = await this.secrets.getActive(NAMES.SESSION_SIGNING);
    if (existing) {
      const stored = JSON.parse((await this.secrets.getMaterial(NAMES.SESSION_SIGNING)).toString('utf8'));
      return {
        privateKey: crypto.createPrivateKey(stored.privateKeyPem),
        publicKey: crypto.createPublicKey(stored.publicKeyPem),
        kid: stored.kid,
      };
    }

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const kid = crypto.randomBytes(8).toString('hex');
    await this._store(NAMES.SESSION_SIGNING, {
      privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
      kid,
    }, SECRET_KINDS.PRIVATE_KEY);
    this._log?.warn?.({ kid, msg: 'yeni oturum imzalama anahtarı üretildi — mevcut tüm belirteçler geçersiz' });
    return { privateKey, publicKey, kid };
  }

  // ---- CT günlüğü -------------------------------------------------------------------------------

  async loadOrCreateCtLogKey() {
    const existing = await this.secrets.getActive(NAMES.CT_LOG);
    if (existing) {
      return JSON.parse((await this.secrets.getMaterial(NAMES.CT_LOG)).toString('utf8'));
    }
    // P-256/SHA-256: RFC 6962'nin izin verdiği iki imza algoritmasından biri (diğeri RSA).
    // Tüm CT istemcileri ikisini de destekler.
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const pair = {
      privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    };
    await this._store(NAMES.CT_LOG, pair, SECRET_KINDS.PRIVATE_KEY);
    this._log?.warn?.({ msg: 'yeni CT günlük anahtarı üretildi — günlüğün kimliği değişti' });
    return pair;
  }

  // ---- paylaşılan sırlar --------------------------------------------------------------------------

  /**
   * Rastgele bir sır okur ya da üretir.
   *
   * Üretilen ama saklanmayan bir sır her yeniden başlatmada değişir ve bunu fark ettiren şey
   * genelde başka bir servisin sessizce 401 almaya başlaması olur -- açılışta değil, saatler
   * sonra, ilk kullanıldığında.
   */
  async loadOrCreateSecret(name, { bytes = 32 } = {}) {
    const existing = await this.secrets.getActive(name);
    if (existing) return (await this.secrets.getText(name)).trim();
    const value = crypto.randomBytes(bytes).toString('base64');
    await this.secrets.put({
      name, material: Buffer.from(value, 'utf8'),
      kind: SECRET_KINDS.API_TOKEN, contentType: 'text/plain',
    });
    return value;
  }

  async _store(name, payload, kind) {
    await this.secrets.put({
      name,
      material: Buffer.from(JSON.stringify(payload), 'utf8'),
      kind,
      contentType: 'application/json',
    });
  }

  // ---- diskten geçiş -------------------------------------------------------------------------------

  /**
   * `.keys/` içindeki dosyaları kasaya alır ve `.migrated` olarak yeniden adlandırır.
   *
   * Kasada ZATEN bir kayıt varsa dosya İÇERİ ALINMAZ, yalnızca yeniden adlandırılır. Üzerine
   * yazmak, bir kez döndürülmüş bir anahtarın eski dosya sürümüyle geri gelmesi demek olurdu --
   * ve oturum imzalama anahtarında bu, döndürmenin hiç yapılmamış olmasıyla aynı şey.
   *
   * @returns {{ imported: string[], skipped: string[] }}
   */
  async importFromDisk(keyDir) {
    const result = { imported: [], skipped: [] };
    if (!keyDir || !fs.existsSync(keyDir)) return result;

    const readIf = async (file) => {
      const full = path.join(keyDir, file);
      if (!fs.existsSync(full)) return null;
      return (await fsp.readFile(full, 'utf8'));
    };
    const retire = async (...files) => {
      for (const file of files) {
        const full = path.join(keyDir, file);
        if (fs.existsSync(full)) await fsp.rename(full, `${full}.migrated`).catch(() => {});
      }
    };

    // ---- oturum imzalama çifti ----
    const priv = await readIf('es256-private.pem');
    const pub = await readIf('es256-public.pem');
    if (priv && pub) {
      if (await this.secrets.getActive(NAMES.SESSION_SIGNING)) {
        result.skipped.push(NAMES.SESSION_SIGNING);
      } else {
        const kidFile = await readIf('kid.txt');
        await this._store(NAMES.SESSION_SIGNING, {
          privateKeyPem: priv,
          publicKeyPem: pub,
          // Eksikse 'default' -- eski loadOrCreateSigningKeyPair'ın davranışı buydu ve
          // değiştirmek, halihazırda dağıtılmış JWKS'i kırardı.
          kid: (kidFile || 'default').trim(),
        }, SECRET_KINDS.PRIVATE_KEY);
        result.imported.push(NAMES.SESSION_SIGNING);
      }
      await retire('es256-private.pem', 'es256-public.pem', 'kid.txt');
    }

    // ---- CT günlüğü ----
    const ctPriv = await readIf('ct-log.key');
    const ctPub = await readIf('ct-log.pub');
    if (ctPriv && ctPub) {
      if (await this.secrets.getActive(NAMES.CT_LOG)) {
        result.skipped.push(NAMES.CT_LOG);
      } else {
        await this._store(NAMES.CT_LOG, { privateKeyPem: ctPriv, publicKeyPem: ctPub }, SECRET_KINDS.PRIVATE_KEY);
        result.imported.push(NAMES.CT_LOG);
      }
      await retire('ct-log.key', 'ct-log.pub');
    }

    // ---- paylaşılan sırlar ----
    for (const [file, name] of [
      ['ra-client-secret', NAMES.RA_CLIENT_SECRET],
      ['db-panel-client-secret', NAMES.PANEL_CLIENT_SECRET],
    ]) {
      const value = await readIf(file);
      if (!value) continue;
      if (await this.secrets.getActive(name)) {
        result.skipped.push(name);
      } else {
        await this.secrets.put({
          name, material: Buffer.from(value.trim(), 'utf8'),
          kind: SECRET_KINDS.API_TOKEN, contentType: 'text/plain',
        });
        result.imported.push(name);
      }
      await retire(file);
    }

    if (result.imported.length) {
      this._log?.warn?.({
        imported: result.imported,
        keyDir,
        msg: 'anahtarlar dosyadan şifreli kasaya taşındı — dosyalar .migrated olarak duruyor, '
          + 'geçişin doğruluğunu doğruladıktan sonra silin',
      });
    }
    return result;
  }
}

module.exports = { KeyVault, KEY_VAULT_NAMES: NAMES };
