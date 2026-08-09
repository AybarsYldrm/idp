'use strict';

const ssl = require('@fitfak/ssl');
const { policyForProfile } = require('./pki-policy');
const { AppError } = require('./errors');
const spiffe = require('./spiffe');
const { openCaVault, STATUS_BASE } = require('./ca-vault');
const {
  PROFILE_MAP, PKI_PURPOSES, MIN_SHORT_LIVED_SECONDS, MAX_SHORT_LIVED_SECONDS, BACKDATE_SECONDS,
} = require('./certificate-profiles');

// trust.fitfak.net'in imzalama tarafı.
//
// Bu dosya yalnızca POLİTİKA kurar: hangi profil ne kadar yaşar, hangi ara CA
// tarafından imzalanır, hangi politika OID'ini taşır, hangi adresleri gösterir,
// kimliği nereye yazar. Baytların üretimi @fitfak/ssl'in işi, anahtarların
// saklanması core/ca-vault.js'in işi.
//
// İki şey değişti ve ikisi de mimari:
//
//   1. ANAHTARLAR DOSYADA DEĞİL. Kök ve ara CA'lar veritabanının şifreli sır
//      deposunda duruyor (core/ca-vault.js). Bu dosya artık hiçbir şey okumuyor
//      ya da yazmıyor; kasadan bir imzalayıcı istiyor.
//
//   2. KISA ÖMÜRLÜ SERTİFİKALAR VAR. Google BeyondCorp modelinde bir iş yükü
//      sertifikası dakikalarla ölçülür ve KENDİ SÜRESİNİN DOLMASI iptal
//      mekanizmasıdır -- çünkü bir iptalin yayılmasından daha hızlı geçersizleşir.
//      Bu, CRL/OCSP'yi gereksiz kılmaz ama nadir kılar: normal işleyişte hiçbir
//      şey iptal edilmez, yalnızca yenilenmez.

const OCSP_URL = `${STATUS_BASE}/ocsp`;
const CA_ISSUERS_URL = `${STATUS_BASE}/intermediate.crt`;
const CRL_URL = `${STATUS_BASE}/crl`;

class ProductionPkiIssuer {
  constructor({ vault, ctLog = null, trustDomain = spiffe.TRUST_DOMAIN }) {
    this.vault = vault;
    this.ctLog = ctLog;
    this.trustDomain = trustDomain;
    // Zincirler amaca göre önbelleklenir. Kısa ömürlü sertifikaların ima ettiği
    // üretim hızında (her iş yükü, ömrün yarısında bir) her imzalamada zinciri
    // yeniden kurmak, kasadan okuma başına bir tur demektir.
    this._chains = new Map();
  }

  /**
   * Kasayı açar, eksik otoriteleri üretir, diskteki eski malzemeyi içeri alır.
   *
   * Eski `new ProductionPkiIssuer(caDir)` biçimi kasıtlı olarak KALDIRILDI: o
   * imza senkron çalışıyordu ve dosyadan okuyordu; ikisi de artık doğru değil ve
   * geriye dönük bir sarmalayıcı bırakmak, hangi kurulumun anahtarı nereden
   * aldığını belirsiz kılardı.
   */
  static async open({ db, caDir = null, ctLog = null, trustDomain = spiffe.TRUST_DOMAIN, logger = console }) {
    const { vault } = await openCaVault({ db, caDir, ssl, trustDomain, logger });
    const issuer = new ProductionPkiIssuer({ vault, ctLog, trustDomain });
    await issuer._loadPublicViews();
    return issuer;
  }

  /**
   * `rootCA` ve `subCA`: SENKRON okunabilen, ÖZEL ANAHTAR İÇERMEYEN görünümler.
   *
   * OCSP ve CRL servisleri ile durum sunucusu bir sertifikanın PEM'ine ve SKID'ine
   * senkron erişmek istiyor -- "bu sorgu ara CA hakkında mı, uç sertifika hakkında
   * mı" gibi kararlar için. Onlara kasadan tam bir imzalayıcı vermek, kök ve ara
   * CA özel anahtarlarını süreç boyunca sıcak tutmak demek olurdu; oysa kasanın
   * bütün amacı, o anahtarların yalnızca imzalanırken çözülmesi.
   *
   * Buradaki nesnelerde `privateKey` YOKTUR ve olmaması bilinçlidir: bunlarla
   * yanlışlıkla bir şey imzalamak mümkün değil. İmzalamak isteyen
   * `vault.loadSigner(...)` çağırmak zorunda ve o çağrı, denetlenmesi gereken tek
   * yerdir.
   */
  async _loadPublicViews() {
    const root = await this.vault.getAuthority('root');
    const leafIssuer = await this.vault.findIssuerForPurpose(PKI_PURPOSES.TLS_CLIENT);

    const view = (authority) => ({
      name: authority.name,
      certPem: authority.certPem,
      subject: authority.subject,
      fingerprint: authority.fingerprint,
      notAfter: authority.notAfter,
      skid: skidOf(authority.certPem),
    });

    this.rootCA = view(root);
    this.subCA = view(leafIssuer);
    return this;
  }

  /** Bir amaç için istemcilere dağıtılacak zincir (ara + kök). */
  async getChainPem(purpose = PKI_PURPOSES.TLS_CLIENT) {
    if (this._chains.has(purpose)) return this._chains.get(purpose);
    const issuer = await this.vault.findIssuerForPurpose(purpose);
    const chain = (await this.vault.getChainPem(issuer.name)).map((pem) => pem.trim()).join('\n');
    const value = `${chain}\n`;
    this._chains.set(purpose, value);
    return value;
  }

  /** Yalnızca kök(ler): bir eşin sabitlediği ya da güven çıpası olarak kurduğu şey. */
  async getTrustAnchorsPem() { return this.vault.getTrustAnchorsPem(); }

  async getRootPem() { return (await this.vault.getAuthority('root')).certPem; }

  /**
   * Bir CSR'den uç sertifika üretir.
   *
   * Subject, CSR'den DEĞİL, `subjectOverride` ile verilen doğrulanmış hesap
   * bilgisinden kurulur. Sertifikada yazan kimlik, başvuranın yazdığı değil,
   * IdP'nin doğruladığı kimliktir -- CSR'ye istenen her şey yazılabilir.
   *
   * @param {object}  opts
   * @param {string}  opts.csrPem
   * @param {string}  opts.profile
   * @param {object} [opts.subjectOverride]  { cn, email, sans }
   * @param {string} [opts.spiffeId]         SAN'a URI olarak yazılacak iş yükü kimliği
   * @param {number} [opts.validitySeconds]  profilin varsayılanını daraltır (uzatamaz)
   */
  async signCertificateFromCsr({
    csrPem, profile = 'client-auth', subjectOverride = {}, spiffeId = null, validitySeconds = null,
    checkKeyUniqueness = null,
  }) {
    const mapping = PROFILE_MAP[profile];
    if (!mapping) {
      throw new AppError('unknown_profile',
        `Bilinmeyen sertifika profili '${profile}'. Kullanılabilir: ${Object.keys(PROFILE_MAP).join(', ')}`,
        { httpStatus: 400 });
    }

    // CSR baytları İSTEMCİDEN gelir. Ayrıştırma hatası bir SUNUCU hatası değil,
    // bir istek hatasıdır: 500 dönmek, istemcinin gönderdiği bozuk baytı bizim
    // arızamız gibi gösterir ve arayan taraf düzeltebileceği bir şey olduğunu
    // anlayamaz.
    let csr;
    try {
      csr = ssl.parseCSR(csrPem);
    } catch (err) {
      throw new AppError('invalid_csr', `CSR okunamadı: ${err.message}`, { httpStatus: 400 });
    }
    if (!ssl.verifyCSR(csr)) {
      throw new AppError('invalid_csr',
        'CSR öz-imzası geçersiz -- anahtar sahipliği kanıtlanamadı', { httpStatus: 400 });
    }

    const parsedSpiffeId = this._resolveSpiffeId({ mapping, profile, spiffeId });

    // Anahtar tekilliği, İMZALAMADAN ÖNCE.
    //
    // Bu kontrol daha önce bir seçenek olarak GEÇİLİYOR ama hiç OKUNMUYORDU:
    // ACME servisi `checkKeyUniqueness` callback'ini yolluyor, yanındaki yorum
    // "pki.js motoru sertifika basmadan önce bu callback'i çağırır" diyor ve
    // imzalayıcı onu sessizce yok sayıyordu. Hiç çalışmayan bir kontrol,
    // olmayan bir kontrolden daha kötüdür: koruma gibi okunur.
    //
    // SKID, CSR'nin açık anahtarından imzalamadan ÖNCE hesaplanabilir -- zaten
    // sertifikaya da oradan yazılır -- yani kontrolün burada olması için bir
    // engel yoktu.
    if (typeof checkKeyUniqueness === 'function') {
      const candidateSkid = skidOfPublicKeyPem(csr.publicKeyPem || ssl.parseCSR(csrPem).publicKeyPem);
      if (await checkKeyUniqueness(candidateSkid.toString('hex'))) {
        throw new AppError('key_already_certified',
          'Bu açık anahtar için zaten bir sertifika üretilmiş. Yeni bir anahtar çifti ve CSR oluşturun.',
          { httpStatus: 409 });
      }
    }

    const email = subjectOverride.email || null;
    const commonName = subjectOverride.cn || email || 'FITFAK Unified Endpoint';

    const subject = { C: 'TR', O: 'FITFAK Global Trust Network', CN: commonName };
    if (email) subject.emailAddress = email;

    // SAN: kimliğin GERÇEKTEN taşındığı yer.
    //
    // CSR'nin kendi SAN'ları BİLEREK taşınmıyor -- taşınsaydı başvuran, kendi
    // seçtiği bir alan adını ya da kendi seçtiği bir SPIFFE kimliğini sertifikaya
    // yazdırabilirdi ve bu tam olarak kaçınmak istediğimiz şey.
    const sans = [];
    if (parsedSpiffeId) sans.push(spiffe.toSanEntry(parsedSpiffeId));
    if (email) sans.push({ type: 'email', value: email });
    for (const extra of subjectOverride.sans || []) sans.push(extra);

    const { notBefore, notAfter } = this._validityWindow({ mapping, validitySeconds });
    const serialNumberHex = ssl.newSerial();
    const issuer = await this.vault.loadSigner(
      (await this.vault.findIssuerForPurpose(mapping.purpose)).name,
    );

    const baseOptions = {
      profile: mapping.sslProfile,
      subjectOverride: subject,
      includeCsrSans: false,
      sans,
      serialNum: serialNumberHex,
      notBefore,
      notAfter,
      policies: policyForProfile(profile),
      ocspUrl: OCSP_URL,
      caIssuersUrl: CA_ISSUERS_URL,
      // Hem OCSP hem CRL veriliyor. OCSP tazedir ama tek bir servise bağlıdır;
      // CRL bayattır ama önbelleklenebilir ve responder ulaşılamazken de çalışır.
      // Yalnızca birini vermek, o biri düştüğünde doğrulayıcıyı "iptal durumu
      // bilinmiyor" ile baş başa bırakır.
      crlUrls: [CRL_URL],
    };

    const sctExtension = mapping.shortLived ? null : await this._maybeLogToCt(csr, issuer, baseOptions);

    const issued = ssl.issueCertificateFromCSR(csr, issuer, {
      ...baseOptions,
      ...(sctExtension ? { extraExtensions: [sctExtension] } : {}),
    });

    const skid = issued.skid;
    return {
      certPem: `${issued.pem.trim()}\n${await this.getChainPem(mapping.purpose)}`,
      leafPem: issued.pem,
      chainPem: await this.getChainPem(mapping.purpose),
      serialNumberHex: typeof serialNumberHex === 'bigint' ? serialNumberHex.toString(16) : String(serialNumberHex),
      skidHex: Buffer.isBuffer(skid) ? skid.toString('hex') : String(skid),
      spiffeId: parsedSpiffeId ? parsedSpiffeId.uri : null,
      profile,
      shortLived: !!mapping.shortLived,
      notBefore,
      notAfter,
    };
  }

  _resolveSpiffeId({ mapping, profile, spiffeId }) {
    if (!spiffeId) {
      if (mapping.requiresSpiffeId) {
        // Kimliğini SAN'da taşıyan bir profil, SAN'ı olmadan üretilirse ortaya
        // doğrulanabilir hiçbir kimlik taşımayan bir sertifika çıkar -- ve SPIFFE
        // kimliğine bakan bir doğrulayıcı için o sertifika işe yaramaz, CN'e geri
        // düşen biri içinse yetkilendirmeyi taşıyan alanı düşürmüş çalışan bir
        // kimlik bilgisi olur.
        throw new AppError('spiffe_id_required',
          `'${profile}' profili kimliğini SAN'daki URI'de taşır; spiffeId zorunludur`,
          { httpStatus: 400 });
      }
      return null;
    }

    const parsed = spiffe.parse(spiffeId);
    if (parsed.trustDomain !== this.trustDomain) {
      // Başka bir güven alanı için sertifika üretmek, o alanın PKI'sını taklit
      // etmektir. Federasyon bir karardır ve kimse bakmadığı için gerçekleşen
      // federasyon, federasyon değildir.
      throw new AppError('foreign_trust_domain',
        `'${parsed}' '${parsed.trustDomain}' güven alanına ait; bu otorite yalnızca '${this.trustDomain}' için imzalar`,
        { httpStatus: 403 });
    }
    return parsed;
  }

  _validityWindow({ mapping, validitySeconds }) {
    const notBefore = new Date(Date.now() - BACKDATE_SECONDS * 1000);

    if (!mapping.seconds) {
      return { notBefore, notAfter: new Date(Date.now() + mapping.days * 86400000) };
    }

    let seconds = mapping.seconds;
    if (validitySeconds) {
      // Çağıran ömrü yalnızca DARALTABİLİR. Uzatabilseydi, profilin ömrü bir
      // varsayılan olurdu; kısa ömürlülüğün tek anlamı ise onun bir SINIR olması.
      seconds = Math.min(Number(validitySeconds), mapping.seconds);
    }
    seconds = Math.max(MIN_SHORT_LIVED_SECONDS, Math.min(MAX_SHORT_LIVED_SECONDS, seconds));

    return { notBefore, notAfter: new Date(Date.now() + seconds * 1000) };
  }

  /**
   * Certificate Transparency (RFC 6962).
   *
   * SCT sertifikanın İÇİNE yazılır, ama SCT'yi almak için sertifikayı log'a
   * göndermek gerekir. RFC 6962 bu döngüyü ÖNSERTİFİKA ile kırar: aynı seri ve
   * aynı içerikle, ama "poison" uzantısıyla (kritik ve hiçbir istemcinin
   * tanımadığı, dolayısıyla hiçbir yerde geçerli sayılmayan) bir sertifika
   * imzalanır, log onu kabul edip SCT döner, sonra AYNI TBS poison yerine SCT
   * listesiyle yeniden imzalanır.
   *
   * KISA ÖMÜRLÜ SERTİFİKALAR LOG'A YAZILMAZ. İki nedeni var ve ikisi de pratik:
   * beş dakikalık bir sertifika log'a yazıldığında zaten süresi dolmak üzeredir,
   * yani izleyicilere hiçbir şey söylemez; ve önsertifika turu, üretim gecikmesini
   * ikiye katlar -- ömrün yarısında bir yenilenen bir filoda bu, sürekli bir yük.
   * CT'nin çözdüğü sorun (bir CA'nın sessizce yanlış sertifika üretmesi) burada
   * sertifikanın kendisinin dakikalar içinde yok olmasıyla sınırlanır.
   */
  async _maybeLogToCt(csr, issuer, baseOptions) {
    if (!this.ctLog) return null;

    const precert = ssl.issueCertificateFromCSR(csr, issuer, {
      ...baseOptions,
      extraExtensions: [ssl.buildPoisonExtension()],
    });
    const issuerSpkiDer = new (require('node:crypto').X509Certificate)(issuer.certPem)
      .publicKey.export({ type: 'spki', format: 'der' });
    const sct = await this.ctLog.add({ certDer: precert.der, issuerSpkiDer, precert: true });
    return ssl.buildSctListExtension([sct]);
  }

  /**
   * OCSP yanıtı üretir. Yanıt, uç sertifikaları imzalayan ara CA ile imzalanır --
   * OCSP yanıtını imzalayan anahtar, sorulan sertifikanın YAYINCISI olmalıdır
   * (RFC 6960 §4.2.2.2), aksi halde istemci yanıtı "unauthorized" sayar.
   */
  async generateOcspResponse({ ocspRequestDer, statusLookup, purpose = PKI_PURPOSES.TLS_CLIENT }) {
    const pki = require('@fitfak/ssl/src/pki');
    const ocspRequest = pki.parseOcspRequest(ocspRequestDer);
    const issuerName = (await this.vault.findIssuerForPurpose(purpose)).name;
    const issuer = await this.vault.loadSigner(issuerName);
    const responderCertDer = ssl.certInfoFromPem(issuer.certPem).certDer;

    const statusMap = statusLookup instanceof Map
      ? statusLookup
      : new Map(Object.entries(statusLookup || {}));

    return pki.generateOcspResponse(ocspRequest, issuer, issuer, responderCertDer, statusMap);
  }

  /**
   * İki ayrı CRL üretilir ve bu ayrım anlamlıdır:
   *
   *   scope 'leaf' -> ara CA tarafından imzalanır, uç sertifikaların iptallerini taşır
   *   scope 'root' -> kök CA tarafından imzalanır, ARA CA'ların iptallerini taşır
   *
   * Bir CRL yalnızca KENDİ yayıncısının verdiği sertifikalar hakkında konuşabilir.
   * Uç sertifikaların iptallerini kök anahtarıyla imzalamak, kök o sertifikaların
   * yayıncısı olmadığı için doğrulayıcılar tarafından geçerli sayılmaz -- iptal
   * sessizce etkisiz kalır.
   */
  async signCrl({ revokedCerts, scope = 'leaf', purpose = PKI_PURPOSES.TLS_CLIENT }) {
    const pki = require('@fitfak/ssl/src/pki');
    const signerName = scope === 'root'
      ? 'root'
      : (await this.vault.findIssuerForPurpose(purpose)).name;
    const signer = await this.vault.loadSigner(signerName);

    const revokedList = (revokedCerts || []).map((cert) => ({
      serial: typeof cert.serialNumberHex === 'bigint'
        ? cert.serialNumberHex
        : BigInt(`0x${String(cert.serialNumberHex).replace(/^0x/, '')}`),
      date: cert.revokedAt ? new Date(Number(cert.revokedAt)) : new Date(),
      reason: cert.reasonCode || 0,
    }));

    const crlPem = pki.generateCRL(signer, revokedList);
    return Buffer.from(
      crlPem.split('\n').filter((l) => l && !l.startsWith('-----')).join(''),
      'base64',
    );
  }
}

/**
 * Bir sertifikanın Subject Key Identifier'ı.
 *
 * RFC 5280 §4.2.1.2 (yöntem 1) SKID'i subjectPublicKey BIT STRING'inin SHA-1'i
 * olarak tanımlar -- yani HAM anahtar baytlarının, tüm SubjectPublicKeyInfo
 * yapısının değil. EC için bu, sıkıştırılmamış nokta: 0x04 || X || Y.
 *
 * SPKI DER'i geçirmek sessizce BAŞKA bir değer üretir; ve o değer hiçbir yerde
 * hata vermez, yalnızca "bu OCSP sorgusu ara CA hakkında mı" gibi
 * karşılaştırmaların hiçbir zaman eşleşmemesine yol açar.
 */
function skidOf(certPem) {
  return skidFromJwk(new (require('node:crypto').X509Certificate)(certPem)
    .publicKey.export({ format: 'jwk' }));
}

/** Aynı hesap, bir sertifika yerine bir açık anahtar PEM'inden. */
function skidOfPublicKeyPem(publicKeyPem) {
  if (!publicKeyPem) {
    throw new AppError('invalid_csr',
      'CSR\'nin açık anahtarı okunamadı; anahtar tekilliği kontrol edilemez', { httpStatus: 400 });
  }
  return skidFromJwk(require('node:crypto').createPublicKey(publicKeyPem).export({ format: 'jwk' }));
}

function skidFromJwk(jwk) {
  const point = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(jwk.x, 'base64url'),
    Buffer.from(jwk.y, 'base64url'),
  ]);
  return ssl.asn1.computeEcSKID(point);
}

module.exports = {
  ProductionPkiIssuer,
  skidOf,
  skidOfPublicKeyPem,
  PROFILE_MAP,
  PKI_PURPOSES,
  STATUS_BASE,
  OCSP_URL,
  CRL_URL,
  CA_ISSUERS_URL,
  MIN_SHORT_LIVED_SECONDS,
  MAX_SHORT_LIVED_SECONDS,
  BACKDATE_SECONDS,
};
