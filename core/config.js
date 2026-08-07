'use strict';

const path = require('node:path');

// Tek yapılandırma noktası.
//
// Önceki hâlde oauth-server.js açılışta `process.env.X = "..."` diyerek kendi
// ortamını eziyordu ve bu satırların içinde CANLI sırlar vardı: veritabanı kök
// sırrı, SMTP parolası, bir kasa kimliği. Bunlar depoya işlendiği için artık
// git geçmişindedirler -- kodda düzeltmek onları geçmişten silmez, bu yüzden
// ilgili kimlik bilgilerinin DÖNDÜRÜLMESİ gerekir (bkz. README, "Sır rotasyonu").
//
// Buradaki kural: sır yalnızca ortamdan gelir, varsayılanı yoktur ve eksikse
// süreç AÇILIŞTA durur. Sessiz bir varsayılan (boş dize, 'changeme') en kötü
// sonucu verir -- sistem çalışır görünür ve gerçekte korumasızdır.

class ConfigError extends Error {
  constructor(message) { super(message); this.name = 'ConfigError'; }
}

const isProduction = () => (process.env.NODE_ENV || 'production') === 'production';

function required(name, { hint } = {}) {
  const value = process.env[name];
  if (value === undefined || value === '') {
    throw new ConfigError(
      `[fitfak-idp] Zorunlu ortam değişkeni eksik: ${name}`
      + (hint ? `\n  ${hint}` : ''),
    );
  }
  return value;
}

function optional(name, fallback = undefined) {
  const value = process.env[name];
  return (value === undefined || value === '') ? fallback : value;
}

function bool(name, fallback = false) {
  const value = optional(name);
  if (value === undefined) return fallback;
  return /^(1|true|yes|on)$/i.test(value);
}

function int(name, fallback) {
  const value = optional(name);
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isFinite(n)) throw new ConfigError(`[fitfak-idp] ${name} sayı olmalı, '${value}' alındı`);
  return n;
}

/**
 * Base64 kodlu, en az 32 baytlık bir sır okur.
 *
 * Uzunluk kontrolü şart: 32 bayttan kısa bir değer sessizce kabul edilip
 * padlenirse (eski davranış `padEnd(32,'0')` yapıyordu) anahtar uzayı, girilen
 * dizgenin uzunluğuna düşer -- 8 karakterlik bir "sır" 32 baytlık bir anahtar
 * gibi görünür ama öyle değildir.
 */
function secret(name, { minBytes = 32, hint } = {}) {
  const raw = required(name, { hint });
  let buf;
  try { buf = Buffer.from(raw, 'base64'); }
  catch { throw new ConfigError(`[fitfak-idp] ${name} base64 olmalı`); }
  if (buf.length < minBytes) {
    throw new ConfigError(
      `[fitfak-idp] ${name} çözüldüğünde en az ${minBytes} bayt olmalı (şu an ${buf.length}).`
      + `\n  Üretmek için: node -e "console.log(require('crypto').randomBytes(${minBytes}).toString('base64'))"`,
    );
  }
  return buf;
}

function load() {
  const root = path.join(__dirname, '..');

  const cfg = {
    env: process.env.NODE_ENV || 'production',
    isProduction: isProduction(),

    // ---- kimlikler / adresler -------------------------------------------------------------
    issuer: optional('FITFAK_IDP_ISSUER', 'https://session.fitfak.net'),
    rpId: optional('FITFAK_IDP_RP_ID', 'fitfak.net'),
    cookieDomain: optional('FITFAK_IDP_COOKIE_DOMAIN', '.fitfak.net'),
    trustHost: optional('FITFAK_IDP_TRUST_HOST', 'trust.fitfak.net'),
    adminHost: optional('FITFAK_IDP_ADMIN_HOST', 'one.fitfak.net'),

    // Tek yönetici. Rol alanı ya da isAdmin bayrağı DEĞİL, tek ve değişmez bir
    // adres: yetkinin nereden geldiği tek satırda okunabilir olmalı.
    adminEmail: optional('FITFAK_IDP_ADMIN_EMAIL', 'aybarsyildirim.mail@gmail.com').toLowerCase(),

    // SPIFFE güven alanı. Bu dağıtımda üretilen her iş yükü kimliğinin
    // `spiffe://<buradaki değer>/...` biçiminde olması ve BAŞKA bir alan için
    // sertifika üretilmemesi bu değere bağlı -- başka bir güven alanı için
    // imzalamak, o alanın PKI'sını taklit etmektir.
    trustDomain: optional('FITFAK_TRUST_DOMAIN', 'fitfak.net'),

    // ---- dinleme yüzeyleri ----------------------------------------------------------------
    // Her mantıksal host kendi IP'sine bağlanır. Ayrım Host header'ıyla değil
    // soket seviyesinde yapılır: Host header'ı istemcinin yazdığı bir dizedir,
    // yerel adres değildir.
    port: int('PORT', 80),
    bind: {
      idp: optional('FITFAK_IDP_BIND_IDP', '127.0.0.1'),      // session.fitfak.net
      trust: optional('FITFAK_IDP_BIND_TRUST', '127.0.0.2'),  // trust.fitfak.net
      admin: optional('FITFAK_IDP_BIND_ADMIN', '127.0.0.3'),  // one.fitfak.net
      // status.trust.fitfak.net / time.trust.fitfak.net.
      //
      // Varsayılan olarak trust adresine düşer, üretimdeki genel IP'ye DEĞİL.
      // Makineye özgü bir adresi koda varsayılan yazmak, o makine dışındaki her
      // çalıştırmayı EADDRNOTAVAIL ile düşürür -- geliştirme, test, CI dahil.
      // Üretimde açıkça verilir: FITFAK_IDP_BIND_STATUS=31.58.245.241
      status: optional('FITFAK_IDP_BIND_STATUS', optional('FITFAK_IDP_BIND_TRUST', '127.0.0.2')),
    },

    keyDir: optional('FITFAK_IDP_KEY_DIR', path.join(root, '.keys')),
    // ESKİ CA dizini. Artık yalnızca oradaki root_ca.key/sub_ca.key dosyalarını
    // bir kereliğine şifreli kasaya almak için okunuyor; yeni malzeme buraya
    // yazılmıyor. İçe aktarma doğrulandıktan sonra dosyalar elle silinebilir.
    caDir: optional('FITFAK_IDP_CA_DIR', path.join(root, '.certs')),
    // Kök ve ara CA'ların durduğu YEREL gömülü fitdb örneği.
    //
    // Uzak veritabanında olamaz: veritabanı mühürlü açılır ve sunucu
    // sertifikasını IdP'den bekler, IdP de onu üretmek için CA'sına ihtiyaç
    // duyar. Ayrıntı core/db-bootstrap.js'in başında.
    caStoreDir: optional('FITFAK_IDP_CA_STORE_DIR', path.join(root, '.ca-store')),
    dataDir: optional('FITFAK_IDP_DB_DIR', path.join(root, '.data')),

    // ---- veritabanı -----------------------------------------------------------------------
    db: {
      // Uzak gRPC veritabanı. Ayarlanmazsa gömülü motor kullanılır.
      remoteTarget: optional('FITFAK_IDP_DB_TARGET'),
      dbId: optional('FITFAK_IDP_DB_ID'),
      ownerId: optional('FITFAK_IDP_DB_OWNER_ID', 'fitfak-idp-service'),
      serviceName: optional('FITFAK_IDP_DB_SERVICE_NAME', 'idp-service'),
      // Enrolment yoluyla mTLS kimliği alınırken kullanılan tek kullanımlık sır.
      enrolmentSecret: optional('FITFAK_IDP_DB_ENROLMENT_SECRET'),
      // Sunucuyu ilk temasta doğrulamak için: CA parmak izi (tercih edilen) ya
      // da CA bundle yolu. İkisi de yoksa enrolment reddedilir -- kimliğini
      // doğrulayamadığın bir sunucuya enrolment kanıtı göndermek, o kanıtı
      // dinleyen herkese vermektir.
      caFingerprint: optional('FITFAK_IDP_DB_CA_FINGERPRINT'),
      caPath: optional('FITFAK_IDP_DB_CA_PATH'),
      identityDir: optional('FITFAK_IDP_DB_IDENTITY_DIR', path.join(root, '.identity')),

      // Veritabanı için üretilecek sunucu sertifikasının adları. Bu adlar
      // sertifikanın SAN'ına yazılır ve IdP bağlanırken doğruladığı şeydir --
      // yanlış olursa bağlantı, anlaşılması zor bir TLS hatasıyla düşer.
      serverNames: (optional('FITFAK_IDP_DB_SERVER_NAMES', 'localhost,db.fitfak.net,127.0.0.1'))
        .split(',').map((s) => s.trim()).filter(Boolean),
      // Mühürlü veritabanının geçici bootstrap sertifikasının parmak izi.
      // İSTEĞE BAĞLI: denetim düzlemi zaten iki yönlü kimlik doğrular, bu
      // yalnızca ek bir katman. Her açılışta değiştiği için otomasyonda
      // genellikle boş bırakılır.
      bootstrapFingerprints: (optional('FITFAK_IDP_DB_BOOTSTRAP_FINGERPRINTS', ''))
        .split(',').map((s) => s.trim()).filter(Boolean),
      // IdP'nin veritabanına bağlanırken kullandığı kendi sertifikasının ömrü.
      // Saatlerle ölçülür, dakikalarla değil: yenileme başarısız olursa geri
      // dönmek için zaman gerekir ve beş dakika, tek bir yavaş adımı bir
      // kesintiye çevirir.
      identityValiditySeconds: int('FITFAK_IDP_DB_IDENTITY_TTL_S', 3600),
    },

    // ---- SMTP -----------------------------------------------------------------------------
    smtp: {
      host: optional('SMTP_HOST'),
      port: int('SMTP_PORT', 465),
      username: optional('SMTP_USER'),
      password: optional('SMTP_PASS'),
      from: optional('SMTP_FROM'),
    },

    // ---- davranış -------------------------------------------------------------------------
    devMockDb: bool('FITFAK_IDP_DEV_DB', false),
    trustedIpHeader: optional('FITFAK_IDP_TRUSTED_IP_HEADER', 'cf-connecting-ip').toLowerCase(),
    postLoginUrl: optional('FITFAK_IDP_POST_LOGIN_URL', '/portal'),
    devicePollIntervalS: int('FITFAK_IDP_DEVICE_POLL_INTERVAL_S', 5),
  };

  // Veritabanı kök sırrı: gömülü motorda ZORUNLU. Uzak modda veritabanını açmak
  // için yine gerekir, ama oradaki kimlik doğrulaması mTLS ile yapılır.
  cfg.db.rootSecret = cfg.devMockDb
    ? null
    : secret('FITFAK_IDP_DB_SECRET', {
      hint: 'Veritabanı kök sırrı. Bunu kaybetmek verinin tamamını kaybetmektir; '
          + 'sızdırmak ise disk kopyasının tek başına yeterli olması demektir.',
    });

  // Veritabanının SUNUCU KİMLİĞİNİ kurmak için kullanılan denetim düzlemi sırrı.
  //
  // Veritabanı mühürlü açılır: kendi CA'sı yoktur, kendi sertifikasını üretmez ve
  // IdP ona bir sunucu sertifikası + anahtar + güven çıpası verene kadar hiç
  // kimseye hizmet etmez. Bu sır, o devrin İKİ YÖNLÜ kimlik doğrulamasını sağlar
  // -- IdP veritabanına, veritabanı da IdP'ye kendini kanıtlar. İkinci yön
  // hayatidir: o olmadan araya giren biri, IdP'nin veritabanı için ürettiği
  // ÖZEL ANAHTARI teslim alır.
  //
  // Yalnızca uzak veritabanı modunda gerekli: gömülü motorda ağ yok, devir yok.
  cfg.db.controlSecret = cfg.db.remoteTarget && !cfg.devMockDb
    ? secret('FITFAK_IDP_DB_CONTROL_SECRET', {
      hint: 'Veritabanının denetim düzlemi sırrı. db-server.js açılışta yazdırır. '
          + 'Enrolment sırrından AYRI olmalı: bu sır, veritabanının sunucu anahtarını '
          + 'değiştirme yetkisidir; enrolment sırrı yalnızca bir istemci sertifikası alma yetkisi.',
    })
    : null;

  // Yönlendirme tutamaklarının türetildiği sır.
  //
  // Bir sır olmasının sebebi gizlilik değil KARARLILIK: aynı istemci + aynı adres
  // her zaman aynı tutamağı almalı, ki bir uygulamanın dağıtılmış yapılandırması
  // IdP yeniden başladığında kırılmasın. Değiştirmek TÜM tutamakları değiştirir.
  cfg.redirectHandleSecret = cfg.devMockDb
    ? Buffer.alloc(32, 1)
    : secret('FITFAK_IDP_REDIRECT_HANDLE_SECRET', {
      hint: 'Yönlendirme tutamaklarının türetildiği sır. Değiştirmek, kayıtlı her '
          + 'uygulamanın tutamağını değiştirir -- imzalama anahtarı gibi muamele edin.',
    });

  if (cfg.isProduction && !cfg.devMockDb) {
    if (cfg.db.remoteTarget && !cfg.db.caFingerprint && !cfg.db.caPath) {
      throw new ConfigError(
        '[fitfak-idp] FITFAK_IDP_DB_TARGET verildi ama FITFAK_IDP_DB_CA_FINGERPRINT '
        + 've FITFAK_IDP_DB_CA_PATH ikisi de yok.\n'
        + '  Sunucuyu ilk temasta doğrulayamadan enrolment yapmak, kanıtı ortadaki '
        + 'herkese vermek demektir.',
      );
    }
  }

  if (cfg.smtp.host && !cfg.smtp.password) {
    throw new ConfigError('[fitfak-idp] SMTP_HOST verildi ama SMTP_PASS yok');
  }

  return cfg;
}

module.exports = { load, ConfigError, required, optional, secret, bool, int };
