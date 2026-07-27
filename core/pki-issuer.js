'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ssl = require('@fitfak/ssl');
const asn1 = ssl.asn1;
const pki = require('@fitfak/ssl/src/pki');

class ProductionPkiIssuer {
  constructor(caDir) {
    this.caDir = caDir;
    if (!fs.existsSync(caDir)) fs.mkdirSync(caDir, { recursive: true });

    const rootKeyPath = path.join(caDir, 'root_ca.key');
    const rootCrtPath = path.join(caDir, 'root_ca.crt');
    const subKeyPath = path.join(caDir, 'sub_ca.key');
    const subCrtPath = path.join(caDir, 'sub_ca.crt');

    // ========================================================================
    // 1. ROOT CA (KÖK SERTİFİKA) YÖNETİMİ
    // ========================================================================
    let rootCA;
    if (fs.existsSync(rootKeyPath) && fs.existsSync(rootCrtPath)) {
      console.log("[PKI] Mevcut Kök Sertifika (Root CA) yükleniyor...");
      const rootKeyPem = fs.readFileSync(rootKeyPath, 'utf8');
      const rootCrtPem = fs.readFileSync(rootCrtPath, 'utf8');

      const rootKeyInfo = ssl.pemToEcPriv(rootKeyPem);
      const rootCertInfo = ssl.certInfoFromPem(rootCrtPem);

      rootCA = {
        keyType: 'ec',
        curveName: rootKeyInfo.curveName,
        hashAlg: 'sha256',
        privateKey: rootKeyInfo.privateKey,
        publicKeyBuf: rootKeyInfo.publicKeyBuf,
        name: rootCertInfo.subjectNameDer,
        skid: asn1.computeEcSKID(rootKeyInfo.publicKeyBuf),
        certPem: rootCrtPem
      };
    } else {
      console.log("[PKI] YENİ EC Kök Sertifika (Root CA) üretiliyor...");
      rootCA = ssl.generateEcRootCA({ curveName: 'P-256', verbose: false });
      fs.writeFileSync(rootKeyPath, ssl.ecPrivToPem(rootCA));
      fs.writeFileSync(rootCrtPath, rootCA.certPem);
    }

    // CRL'i Root CA anahtarıyla imzalayabilmek için Root CA'i sınıfın içine kaydediyoruz.
    this.rootCA = rootCA;

    // ========================================================================
    // 2. SUB-CA (ALT SERTİFİKA / INTERMEDIATE) YÖNETİMİ
    // ========================================================================
    if (fs.existsSync(subKeyPath) && fs.existsSync(subCrtPath)) {
      console.log("[PKI] Mevcut Alt Sertifika (Sub-CA) yükleniyor...");
      const subKeyPem = fs.readFileSync(subKeyPath, 'utf8');
      const subCrtPem = fs.readFileSync(subCrtPath, 'utf8');
      
      const subKeyInfo = ssl.pemToEcPriv(subKeyPem);
      const subCertInfo = ssl.certInfoFromPem(subCrtPem);
      
      this.subCA = {
        keyType: 'ec',
        curveName: subKeyInfo.curveName,
        hashAlg: 'sha256',
        privateKey: subKeyInfo.privateKey,
        publicKeyBuf: subKeyInfo.publicKeyBuf,
        name: subCertInfo.subjectNameDer,
        skid: asn1.computeEcSKID(subKeyInfo.publicKeyBuf),
        certPem: subCrtPem
      };
    } else {
      console.log("[PKI] YENİ EC Alt Sertifika (Sub-CA) üretiliyor...");
      const baseUrl = 'http://status.trust.fitfak.net';
      
      this.subCA = ssl.generateEcIntermediateCA(rootCA, {
        curveName: 'P-256',
        commonName: 'FITFAK Authority Core Sub-CA G1', 
        verbose: false,
        ocspUrl: baseUrl, 
        aiaUrl: baseUrl,
        crlUrl: baseUrl   
      });
      fs.writeFileSync(subKeyPath, ssl.ecPrivToPem(this.subCA));
      fs.writeFileSync(subCrtPath, this.subCA.certPem);
    }
  }

  // ========================================================================
  // 3. UÇ SERTİFİKA (LEAF) İMZALAMA VE PROFİL YÖNETİMİ
  // ========================================================================
  async signCertificateFromCsr({ csrPem, profile, subjectOverride, checkKeyUniqueness }) {
    let spkiBuf;
    try {
      const csrDer = Buffer.from(
        csrPem.split('\n').filter(l => l && !l.startsWith('-----')).join(''),
        'base64'
      );
      const top = asn1.readTLV(csrDer, 0);
      const csrChildren = asn1.readChildren(top.content);
      const reqInfo = csrChildren[0];
      const reqInfoChildren = asn1.readChildren(reqInfo.content);
      
      const spkiNode = reqInfoChildren[2];
      spkiBuf = reqInfo.content.subarray(
        spkiNode.contentOff - spkiNode.headerLen,
        spkiNode.contentOff - spkiNode.headerLen + spkiNode.totalLen
      );
    } catch (e) {
      throw new Error('Geçersiz CSR biçimi: ' + e.message);
    }

    // Açık anahtarın parmak izini hesapla (Subject Key Identifier)
    const skidBuf = asn1.computeEcSKID(spkiBuf);
    const skidHex = Buffer.isBuffer(skidBuf) ? skidBuf.toString('hex') : skidBuf;

    // 🛡️ GÜVENLİK KONTROLÜ (Perfect Forward Secrecy): Anahtar (Public Key) daha önce kullanılmış mı?
    if (typeof checkKeyUniqueness === 'function') {
      const isKeyAlreadyUsed = await checkKeyUniqueness(skidHex);
      if (isKeyAlreadyUsed) {
        throw new Error('Güvenlik İhlali: Bu gizli anahtar (Private Key) daha önce kullanılmış. Lütfen yeni bir anahtar çifti ve CSR oluşturun.');
      }
    }

    const serialNumberHex = ssl.newSerial();
    
    // Kurumsal kimlik (Subject) yapılandırması
    const cn = subjectOverride?.cn || 'FITFAK Unified Endpoint';
    const subjectName = asn1.buildName([
      [asn1.OIDs.country, 'TR'],
      [asn1.OIDs.orgName, 'FITFAK Global Trust Network'], 
      [asn1.OIDs.commonName, cn]
    ]);

    const now = new Date();
    
    // Profillere göre geçerlilik süreleri (Örn: PAdES 3 yıl, Web Sunucu 90 gün)
    let daysValid = 365;
    if (profile === 'server-auth') daysValid = 90;
    if (profile === 'document-signing' || profile === 'code-signing') daysValid = 1095;
    
    const exp = new Date(now.getTime() + daysValid * 86400000);

    // Uç sertifikalarda CRL (extCDP) kesinlikle yok, sadece OCSP ve Issuer adresi var.
    const ocspUrl = 'http://status.trust.fitfak.net/ocsp';
    const caIssuersUrl = 'http://status.trust.fitfak.net/intermediate.crt';

    const extensions = [
      asn1.extBasicConstraints(false), // Uç sertifika olduğunu belirtir
      asn1.extSKID(skidBuf),
      asn1.extAKID(this.subCA.skid),
      asn1.extAIA(ocspUrl, caIssuersUrl)
    ];

    // PROFİL TABANLI YETKİLENDİRME (Key Usage & Extended Key Usage)
    switch (profile) {
      case 'server-auth':
        extensions.push(asn1.extKeyUsage([asn1.KU.digitalSignature, asn1.KU.keyEncipherment]));
        extensions.push(asn1.extEKU(['2b06010505070301'])); // serverAuth
        extensions.push(asn1.extCertificatePolicies([{oid: '2b0601040183fc6d0101', cps: 'https://fitfak.net/pki/cps'}]));
        break;
      case 'document-signing':
        extensions.push(asn1.extKeyUsage([asn1.KU.digitalSignature, asn1.KU.nonRepudiation]));
        extensions.push(asn1.extEKU(['2b0601040182370a030c', '2b06010505070304'])); // MS Document Signing & Email Protection
        extensions.push(asn1.extCertificatePolicies([{oid: '2b0601040183fc6d0101', cps: 'https://fitfak.net/pki/cps'}]));
        break;
      case 'timestamping':
        extensions.push(asn1.extKeyUsage([asn1.KU.digitalSignature]));
        extensions.push(asn1.extEKU(['2b06010505070308'], true)); // timestamping (critical)
        extensions.push(asn1.extCertificatePolicies([{oid: '2b0601040183fc6d0104', cps: 'https://fitfak.net/pki/cps'}]));
        break;
      case 'smime':
        extensions.push(asn1.extKeyUsage([asn1.KU.digitalSignature, asn1.KU.nonRepudiation, asn1.KU.keyEncipherment]));
        extensions.push(asn1.extEKU(['2b06010505070304'])); // emailProtection
        extensions.push(asn1.extCertificatePolicies([{oid: '2b0601040183fc6d0101', cps: 'https://fitfak.net/pki/cps'}]));
        break;
      case 'code-signing':
        extensions.push(asn1.extKeyUsage([asn1.KU.digitalSignature]));
        extensions.push(asn1.extEKU(['2b06010505070303'])); // codeSigning
        extensions.push(asn1.extCertificatePolicies([{oid: '2b0601040183fc6d0101', cps: 'https://fitfak.net/pki/cps'}]));
        break;
      case 'client-auth':
      default:
        extensions.push(asn1.extKeyUsage([asn1.KU.digitalSignature]));
        extensions.push(asn1.extEKU(['2b06010505070302'])); // clientAuth
        extensions.push(asn1.extCertificatePolicies([{oid: '2b0601040183fc6d0101', cps: 'https://fitfak.net/pki/cps'}]));
        break;
    }

    // Sertifikayı İnşa Et
    const cert = pki.buildCert({
      serialNum: serialNumberHex,
      issuerName: this.subCA.name,
      subjectName: subjectName,
      notBefore: now,
      notAfter: exp,
      spki: spkiBuf,
      extensions: extensions,
      signerKey: {
        keyType: 'ec',
        curveName: this.subCA.curveName,
        hashAlg: this.subCA.hashAlg,
        privateKey: this.subCA.privateKey
      }
    });

    const subCaPem = this.subCA.pem || this.subCA.certPem; 
    const fullChainPem = `${cert.pem.trim()}\n${subCaPem.trim()}\n`;

    return {
      certPem: fullChainPem,
      serialNumberHex: typeof serialNumberHex === 'bigint' ? serialNumberHex.toString(16) : serialNumberHex,
      skidHex: skidHex, // Veritabanına kaydetmen ve kontrol etmen için dışa aktarılıyor
      notBefore: now,
      notAfter: exp
    };
  }

  // ========================================================================
  // 4. OCSP VE CRL SERVISLERI
  // ========================================================================
  async generateOcspResponse({ ocspRequestDer, statusLookup }) {
    const ocspRequest = pki.parseOcspRequest(ocspRequestDer);
    const subCaCertInfo = ssl.certInfoFromPem(this.subCA.certPem);
    const activeResponderCertDer = subCaCertInfo.certDer;

    const statusMap = new Map();
    if (statusLookup) {
      if (statusLookup instanceof Map) {
        for (const [k, v] of statusLookup.entries()) statusMap.set(k, v);
      } else {
        for (const key of Object.keys(statusLookup)) {
          statusMap.set(key, statusLookup[key]);
        }
      }
    }

    return pki.generateOcspResponse(
      ocspRequest,
      this.subCA,
      this.subCA,
      activeResponderCertDer,
      statusMap
    );
  }

  async signCrl({ revokedCerts }) {
    const revokedList = (revokedCerts || []).map(cert => ({
      serial: BigInt('0x' + cert.serialNumberHex),
      date: cert.revokedAt ? new Date(Number(cert.revokedAt)) : new Date(),
      reason: cert.reasonCode || 0
    }));

    // CRL, Adobe Acrobat vb. yazılımların kriptografik zinciri doğrulayabilmesi için Root CA anahtarıyla imzalanıyor!
    const crlPem = pki.generateCRL(this.rootCA, revokedList);

    const base64Der = crlPem
      .split('\n')
      .filter(line => line && !line.startsWith('-----'))
      .join('');
      
    return Buffer.from(base64Der, 'base64');
  }
}

module.exports = { ProductionPkiIssuer };