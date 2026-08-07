'use strict';

const fs = require('node:fs');
const path = require('node:path');

// trust.fitfak.net'in anahtarlarının DURDUĞU yer.
//
// Önceki hâli dört dosyaydı:
//
//     .certs/root_ca.key   0600
//     .certs/root_ca.crt
//     .certs/sub_ca.key    0600
//     .certs/sub_ca.crt
//
// Bu izinler korumanın TAMAMIYDI. O kullanıcı olarak dosya sistemini okuyabilen
// her şey kök anahtarı okur: bir yedekleme işi, bir konteyner imaj katmanı, bir
// yan konteynere bağlanmış birim, fazla geniş bir glob ile çalışan bir log
// toplayıcı, `docker cp`, süreçteki BAŞKA bir yerdeki dizin-aşımı hatası. Ve
// dosya otoritenin KENDİSİ olduğu için, onun bir kopyası otoritenin bir
// kopyasıdır -- üstelik bunun olduğunu anlamanın bir yolu yoktur.
//
// Artık aynı malzeme veritabanındaki `secrets` koleksiyonunda bir kayıt: motorun
// DDK'sından türetilmiş bir anahtarla DİSKTE ŞİFRELİ, okunması diğer her kayıtla
// aynı kimlik doğrulamalı yoldan geçiyor, aynı ACL'lere ve aynı denetim izine
// tabi. Veri dizininin bir kopyası kök sır olmadan işe yaramaz.
//
// DÜRÜST OLMAK GEREKİRSE bu bir HSM değildir: anahtar imzalarken bu sürecin
// belleğinde çözülür, tıpkı diğer her kayıt gibi. Canlı bir sürecin belleğini
// okuyabilen bir saldırganı tehdit modeline dahil ediyorsanız cevap, anahtarı
// hiç dışarı vermeyen bir imzalayıcıdır (TPM/PKCS#11/KMS) -- bunun daha zayıf
// bir sürümü değil. Buradaki kazanç, çok daha yaygın olan başarısızlığı ortadan
// kaldırmasıdır: anahtarın, kimsenin fark etmeden kopyalanabileceği bir dosyada
// DURUYOR olması.
//
//
// NEDEN BİRDEN FAZLA ARA CA
//
// Kök yalnızca tek bir şey imzalar: ara CA'ları. Geri kalan her şeyi bir ara CA
// imzalar ve her AMAÇ için ayrı bir ara CA vardır -- TLS sunucuları, iş yükü
// kimlikleri, insan istemci sertifikaları, S/MIME, kod imzalama.
//
// Bu bürokrasi değil. Bir CA kısıtlanabilir (isim kısıtları, EKU kısıtları, yol
// uzunluğu) ve kısıtlar ancak kısıtladıkları şey darsa bir anlam ifade eder. Her
// şeyi imzalayan tek bir ara CA hiçbir şeye kısıtlanamaz. Ayrıca ele geçirilme
// sınırlanmış olur: iş yükü ara CA'sını emekliye ayırmak iş yükü sertifikalarını
// geçersiz kılar ve e-posta sertifikalarına dokunmaz. Kaybedilmesi telafi
// edilemeyecek tek şey olan kök ise yalnızca yeni bir ara CA imzalamak için
// ortaya çıkar.

const { PkiVault, PKI_PURPOSES } = require('@fitfak/database');

const STATUS_BASE = process.env.FITFAK_TRUST_STATUS_URL || 'http://status.trust.fitfak.net';

/**
 * Bu dağıtımın varsayılan ara CA'ları. Admin panelinden başkaları eklenebilir
 * (bkz. /admin/pki/authorities), ama bunlar olmadan sistem hiçbir sertifika
 * üretemez, o yüzden açılışta yoklarsa oluşturulurlar.
 *
 * `purposes` bir ara CA'nın hangi taleplere cevap verebileceğini belirler ve
 * her amaç için TAM OLARAK BİR ara CA olmalıdır -- iki tane olsaydı aynı türden
 * iki talep farklı zincirlere bağlanır ve birinin iptali nüfusun yarısını
 * kapsardı.
 */
const DEFAULT_AUTHORITIES = [
  {
    name: 'workload-ca',
    commonName: 'FITFAK Workload Issuing CA G1',
    purposes: [PKI_PURPOSES.WORKLOAD],
  },
  {
    name: 'client-ca',
    commonName: 'FITFAK Client Authentication CA G1',
    purposes: [PKI_PURPOSES.TLS_CLIENT],
  },
  {
    name: 'server-ca',
    commonName: 'FITFAK TLS Server Issuing CA G1',
    purposes: [PKI_PURPOSES.TLS_SERVER],
  },
  {
    name: 'email-ca',
    commonName: 'FITFAK Secure Email CA G1',
    purposes: [PKI_PURPOSES.EMAIL],
  },
  {
    name: 'signing-ca',
    commonName: 'FITFAK Code and Document Signing CA G1',
    purposes: [PKI_PURPOSES.CODE_SIGNING, PKI_PURPOSES.TIMESTAMPING, PKI_PURPOSES.OCSP],
  },
];

const LEGACY_FILES = {
  root: { key: 'root_ca.key', cert: 'root_ca.crt' },
  intermediate: { key: 'sub_ca.key', cert: 'sub_ca.crt' },
};

/**
 * Kasayı açar; gerekiyorsa diskteki eski malzemeyi içeri alır ve eksik
 * otoriteleri üretir.
 *
 * @param {object}  opts
 * @param {object}  opts.db        açık veritabanı (gömülü ya da uzak -- ikisi de olur)
 * @param {string} [opts.caDir]    eski dosyaların aranacağı dizin
 * @param {object} [opts.ssl]      @fitfak/ssl
 * @param {string} [opts.trustDomain]
 */
async function openCaVault({ db, caDir = null, ssl = null, trustDomain = 'fitfak.net', logger = console }) {
  const vault = await PkiVault.open(db, { ssl, namespace: 'pki' });

  const imported = caDir ? await importLegacyFiles({ vault, caDir, trustDomain, logger }) : [];

  let root = await vault.getAuthority('root');
  if (!root) {
    root = await vault.createRoot({
      commonName: 'FITFAK Global Trust Network Root CA G1',
      trustDomain,
    });
    logger?.warn?.(
      `[pki] Yeni KÖK CA üretildi ve kasaya yazıldı (${root.fingerprint}).\n`
      + '  Bu, bu dağıtımın güven çıpasıdır. Parmak izini dağıtın ve YEDEKLEYİN:\n'
      + '  veritabanı kök sırrını kaybetmek, bu anahtarı kaybetmektir.',
    );
  }

  const created = [];
  for (const definition of DEFAULT_AUTHORITIES) {
    if (await vault.getAuthority(definition.name)) continue;
    await vault.createIntermediate({
      ...definition,
      parent: 'root',
      trustDomain,
      // Zincirin her halkası KENDİ yayıncısının iptal bilgisini gösterir. Uç
      // sertifikalarınki ara CA'nınkine, ara CA'nınki kökünkine. Bir ara CA'nın
      // CRL'ini köke göstermek, "ara sertifika iptal edilirse altındaki her şey
      // düşer" davranışının doğrulayıcı tarafında sessizce çalışmamasına yol açar.
      ocspUrl: `${STATUS_BASE}/ocsp`,
      caIssuersUrl: `${STATUS_BASE}/root.crt`,
      crlUrls: [`${STATUS_BASE}/crl/root`],
    });
    created.push(definition.name);
  }
  if (created.length) logger?.warn?.(`[pki] Ara CA'lar üretildi: ${created.join(', ')}`);

  return { vault, root, imported, created };
}

/**
 * Diskte duran eski kök/ara CA'yı kasaya taşır.
 *
 * Dosyaları SİLMEZ. İçe aktarmanın çalıştığını kimse doğrulamadan bir kök
 * anahtarın tek kopyasını silen bir göç, bir PKI'yı kaybedebilen bir göçtür.
 * Silmek ayrı, elle yapılan, geri alınabilir bir adım -- ve mesaj bunu söylüyor.
 */
async function importLegacyFiles({ vault, caDir, trustDomain, logger }) {
  const imported = [];
  const read = (name) => {
    const file = path.join(caDir, name);
    return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
  };

  for (const [role, files] of Object.entries(LEGACY_FILES)) {
    const certPem = read(files.cert);
    const privateKeyPem = read(files.key);
    if (!certPem || !privateKeyPem) continue;

    const name = role === 'root' ? 'root' : 'legacy-sub-ca';
    const result = await vault.importAuthority({
      name,
      certPem,
      privateKeyPem,
      role,
      parent: role === 'root' ? null : 'root',
      // Eski ara CA HER ŞEYİ imzalıyordu. Kasaya girerken bir amaç ATANMIYOR:
      // hâlâ geçerli olan sertifikaları doğrulanabilir kalsın diye zincirde
      // duruyor, ama yeni talepler amaca göre ayrılmış yeni ara CA'lara gidiyor.
      // Ona eski geniş yetkisini vermek, ayrımı ilk günden anlamsız kılardı.
      purposes: [],
      trustDomain,
    });
    if (result.imported) {
      imported.push(name);
      logger?.warn?.(
        `[pki] ${files.key} + ${files.cert} kasaya alındı ('${name}').\n`
        + `  Dosyalar SİLİNMEDİ. Kasadan okunduğunu doğruladıktan sonra elle kaldırın:\n`
        + `    shred -u ${path.join(caDir, files.key)}\n`
        + `  Silmeden önce veritabanı kök sırrının yedeğinin olduğundan emin olun --\n`
        + '  o sır olmadan kasadaki anahtar da okunamaz.',
      );
    }
  }
  return imported;
}

module.exports = { openCaVault, DEFAULT_AUTHORITIES, STATUS_BASE, PKI_PURPOSES };
