'use strict';

const fs = require('node:fs');
const path = require('node:path');
const ssl = require('@fitfak/ssl');
const { policyForProfile } = require('./pki-policy');
const { AppError } = require('./errors');

// trust.fitfak.net'in imzalama tarafı.
//
// Önceki sürüm CSR'yi elle DER gezerek ayrıştırıyor, SKID'i tüm
// SubjectPublicKeyInfo üzerinden hesaplıyor (RFC 5280 subjectPublicKey BIT
// STRING'ini ister) ve EKU/policy OID'lerini elle hex olarak yazıyordu. Üçü de
// @fitfak/ssl'de zaten doğru şekilde mevcut; kopyası burada tutulduğu sürece
// ikisi sessizce ayrışabilir. Bu dosya artık yalnızca POLİTİKA kurar:
// hangi profil ne kadar yaşar, hangi politika OID'ini taşır, hangi adresleri
// gösterir. Baytların üretimi kütüphanenin işi.

const STATUS_BASE = process.env.FITFAK_TRUST_STATUS_URL || 'http://status.trust.fitfak.net';
const OCSP_URL = `${STATUS_BASE}/ocsp`;
const CA_ISSUERS_URL = `${STATUS_BASE}/intermediate.crt`;
const CRL_URL = `${STATUS_BASE}/crl`;

// Profil -> @fitfak/ssl profili + ömür.
//
// Ömürler amaca göre ayrışır: bir TLS sunucu sertifikası kısa yaşamalı (iptal
// yayılmadan da kendiliğinden geçersizleşsin), bir belge imzalama sertifikası
// uzun (imza, sertifika süresi dolduktan sonra da doğrulanabilir olmalı).
const PROFILE_MAP = {
  'client-auth':      { sslProfile: 'tls-client',     days: 365 },
  'server-auth':      { sslProfile: 'tls-server',     days: 90  },
  smime:              { sslProfile: 'email',          days: 730 },
  timestamping:       { sslProfile: 'tsa',            days: 1095 },
  'code-signing':     { sslProfile: 'code-signing',   days: 1095 },
  'document-signing': { sslProfile: 'code-signing',   days: 1095 },
  'ocsp-responder':   { sslProfile: 'ocsp-responder', days: 365 },
};

function loadOrCreateCa(caDir) {
  if (!fs.existsSync(caDir)) fs.mkdirSync(caDir, { recursive: true, mode: 0o700 });

  const p = (n) => path.join(caDir, n);
  const readCa = (keyPath, crtPath) => {
    const keyInfo = ssl.pemToEcPriv(fs.readFileSync(keyPath, 'utf8'));
    const certPem = fs.readFileSync(crtPath, 'utf8');
    return {
      keyType: 'ec',
      curveName: keyInfo.curveName,
      hashAlg: 'sha256',
      privateKey: keyInfo.privateKey,
      publicKeyBuf: keyInfo.publicKeyBuf,
      name: ssl.certInfoFromPem(certPem).subjectNameDer,
      skid: ssl.asn1.computeEcSKID(keyInfo.publicKeyBuf),
      certPem,
    };
  };

  let rootCA;
  if (fs.existsSync(p('root_ca.key')) && fs.existsSync(p('root_ca.crt'))) {
    rootCA = readCa(p('root_ca.key'), p('root_ca.crt'));
  } else {
    rootCA = ssl.generateEcRootCA({
      curveName: 'P-256',
      commonName: 'FITFAK Global Trust Network Root CA G1',
      organization: 'FITFAK',
      country: 'TR',
      verbose: false,
    });
    // Kök CA'nın özel anahtarı yalnızca ara CA'yı imzalamak için gerekir; günlük
    // işleyişte kullanılmaz. 0600 ile yazılıyor -- varsayılan umask'a bırakmak
    // bu dosyayı okunabilir bırakabilirdi.
    fs.writeFileSync(p('root_ca.key'), ssl.ecPrivToPem(rootCA), { mode: 0o600 });
    fs.writeFileSync(p('root_ca.crt'), rootCA.certPem);
  }

  let subCA;
  if (fs.existsSync(p('sub_ca.key')) && fs.existsSync(p('sub_ca.crt'))) {
    subCA = readCa(p('sub_ca.key'), p('sub_ca.crt'));
  } else {
    subCA = ssl.generateEcIntermediateCA(rootCA, {
      curveName: 'P-256',
      commonName: 'FITFAK Authority Core Sub-CA G1',
      organization: 'FITFAK',
      country: 'TR',
      verbose: false,
      // Ara CA'nın KENDİ iptal bilgisi kökün CRL'ine bakar; uç sertifikalarınki
      // ara CA'nınkine. Zincirin her halkasının kendi yayıncısını göstermesi,
      // "ara sertifika iptal edilirse altındaki her şey düşer" davranışının
      // doğrulayıcı tarafında gerçekten işlemesinin ön koşuludur.
      ocspUrl: OCSP_URL,
      caIssuersUrl: `${STATUS_BASE}/root.crt`,
      crlUrls: [`${STATUS_BASE}/crl/root`],
    });
    fs.writeFileSync(p('sub_ca.key'), ssl.ecPrivToPem(subCA), { mode: 0o600 });
    fs.writeFileSync(p('sub_ca.crt'), subCA.certPem);
  }

  return { rootCA, subCA };
}

class ProductionPkiIssuer {
  /**
   * @param {string} caDir
   * @param {object} [opts]
   * @param {object} [opts.ctLog]  RFC 6962 log'u. Verilirse her uç sertifika
   *   önce ÖNSERTİFİKA olarak log'a yazılır ve dönen SCT sertifikaya gömülür.
   */
  constructor(caDir, { ctLog = null } = {}) {
    this.caDir = caDir;
    const { rootCA, subCA } = loadOrCreateCa(caDir);
    this.rootCA = rootCA;
    this.subCA = subCA;
    this.ctLog = ctLog;
  }

  /** İstemcilere dağıtılacak zincir (ara + kök). */
  getChainPem() {
    return `${this.subCA.certPem.trim()}\n${this.rootCA.certPem.trim()}\n`;
  }

  /**
   * Bir CSR'den uç sertifika üretir.
   *
   * Subject, CSR'den DEĞİL, `subjectOverride` ile verilen doğrulanmış hesap
   * bilgisinden kurulur. Sertifikada yazan kimlik, başvuranın yazdığı değil,
   * IdP'nin doğruladığı kimliktir -- CSR'ye istenen her şey yazılabilir.
   *
   * Kimlik e-postaya dayanır (hesabın doğrulanmış adresi): CN insan tarafından
   * okunabilir ad, e-posta ise hem DN'de hem SAN'da rfc822Name olarak taşınır.
   * S/MIME istemcileri SAN'daki rfc822Name'e bakar, DN'deki emailAddress'e
   * değil -- ikisini birden yazmak eski ve yeni istemcileri aynı anda memnun eder.
   */
  async signCertificateFromCsr({ csrPem, profile = 'client-auth', subjectOverride = {} }) {
    const mapping = PROFILE_MAP[profile];
    if (!mapping) {
      throw new Error(`Bilinmeyen sertifika profili '${profile}'. Kullanılabilir: ${Object.keys(PROFILE_MAP).join(', ')}`);
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
      throw new AppError(
        'invalid_csr',
        'CSR öz-imzası geçersiz -- anahtar sahipliği kanıtlanamadı',
        { httpStatus: 400 },
      );
    }

    const email = subjectOverride.email || null;
    const commonName = subjectOverride.cn || email || 'FITFAK Unified Endpoint';

    const subject = { C: 'TR', O: 'FITFAK Global Trust Network', CN: commonName };
    if (email) subject.emailAddress = email;

    // SAN: e-posta tabanlı profillerde rfc822Name şart. CSR'nin kendi SAN'ları
    // BİLEREK taşınmıyor -- taşınsaydı başvuran, kendi seçtiği bir alan adını
    // sertifikaya yazdırabilirdi ve bu tam olarak kaçınmak istediğimiz şey.
    const sans = [];
    if (email) sans.push({ type: 'email', value: email });
    for (const extra of subjectOverride.sans || []) sans.push(extra);

    const notBefore = new Date();
    const notAfter = new Date(notBefore.getTime() + mapping.days * 86400000);
    const serialNumberHex = ssl.newSerial();

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
      // CRL bayattır ama önbelleklenebilir ve responder ulaşılamazken de
      // çalışır. Yalnızca birini vermek, o biri düştüğünde doğrulayıcıyı
      // "iptal durumu bilinmiyor" ile baş başa bırakır.
      crlUrls: [CRL_URL],
    };

    // ---- Certificate Transparency ------------------------------------------
    //
    // SCT sertifikanın İÇİNE yazılır, ama SCT'yi almak için sertifikayı log'a
    // göndermek gerekir. RFC 6962 bu döngüyü ÖNSERTİFİKA ile kırar: aynı seri
    // ve aynı içerikle, ama "poison" uzantısıyla (kritik ve hiçbir istemcinin
    // tanımadığı, dolayısıyla hiçbir yerde geçerli sayılmayan) bir sertifika
    // imzalanır, log onu kabul edip SCT döner, sonra AYNI TBS poison yerine
    // SCT listesiyle yeniden imzalanır.
    //
    // İki sertifikanın aynı seriyi taşıması kasıtlıdır: izleyiciler log'daki
    // önsertifika ile sahada gördükleri sertifikayı böyle eşleştirir.
    let sctExtension = null;
    if (this.ctLog) {
      const precert = ssl.issueCertificateFromCSR(csr, this.subCA, {
        ...baseOptions,
        extraExtensions: [ssl.buildPoisonExtension()],
      });
      const issuerSpkiDer = new (require('node:crypto').X509Certificate)(this.subCA.certPem)
        .publicKey.export({ type: 'spki', format: 'der' });
      const sct = await this.ctLog.add({
        certDer: precert.der, issuerSpkiDer, precert: true,
      });
      sctExtension = ssl.buildSctListExtension([sct]);
    }

    const issued = ssl.issueCertificateFromCSR(csr, this.subCA, {
      ...baseOptions,
      ...(sctExtension ? { extraExtensions: [sctExtension] } : {}),
    });

    const skid = issued.skid;
    return {
      certPem: `${issued.pem.trim()}\n${this.subCA.certPem.trim()}\n`,
      leafPem: issued.pem,
      serialNumberHex: typeof serialNumberHex === 'bigint' ? serialNumberHex.toString(16) : String(serialNumberHex),
      skidHex: Buffer.isBuffer(skid) ? skid.toString('hex') : String(skid),
      notBefore,
      notAfter,
    };
  }

  /**
   * OCSP yanıtı üretir. Yanıt, uç sertifikaları imzalayan ara CA ile imzalanır --
   * OCSP yanıtını imzalayan anahtar, sorulan sertifikanın YAYINCISI olmalıdır
   * (RFC 6960 §4.2.2.2), aksi halde istemci yanıtı "unauthorized" sayar.
   */
  async generateOcspResponse({ ocspRequestDer, statusLookup }) {
    const pki = require('@fitfak/ssl/src/pki');
    const ocspRequest = pki.parseOcspRequest(ocspRequestDer);
    const responderCertDer = ssl.certInfoFromPem(this.subCA.certPem).certDer;

    const statusMap = statusLookup instanceof Map
      ? statusLookup
      : new Map(Object.entries(statusLookup || {}));

    return pki.generateOcspResponse(ocspRequest, this.subCA, this.subCA, responderCertDer, statusMap);
  }

  /**
   * İki ayrı CRL üretilir ve bu ayrım anlamlıdır:
   *
   *   scope 'leaf' -> ara CA tarafından imzalanır, uç sertifikaların iptallerini taşır
   *   scope 'root' -> kök CA tarafından imzalanır, ARA CA'ların iptallerini taşır
   *
   * Bir CRL yalnızca KENDİ yayıncısının verdiği sertifikalar hakkında konuşabilir.
   * Önceki sürüm uç sertifikaların iptallerini kök anahtarıyla imzalıyordu; kök,
   * o sertifikaların yayıncısı olmadığı için doğrulayıcılar bu CRL'i uç
   * sertifikalar için geçerli saymaz -- iptal sessizce etkisiz kalırdı.
   */
  async signCrl({ revokedCerts, scope = 'leaf' }) {
    const pki = require('@fitfak/ssl/src/pki');
    const signer = scope === 'root' ? this.rootCA : this.subCA;

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

module.exports = { ProductionPkiIssuer, PROFILE_MAP, STATUS_BASE, OCSP_URL, CRL_URL, CA_ISSUERS_URL };
