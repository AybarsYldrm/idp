'use strict';

const crypto = require('node:crypto');

// ============================================================================
// PKCS#10 (RFC 2986) CertificationRequest ayrıştırıcısı -- SADECE ihtiyacımız olan
// alanları (subject Name DER, SubjectPublicKeyInfo DER) çıkarır + CSR'ın KENDİ
// imzasını (proof-of-possession -- istemcinin gerçekten bu özel anahtara sahip
// olduğunun kanıtı) Node'un YERLEŞİK crypto'suyla doğrular. Harici ASN.1 kütüphanesi
// YOK -- sadece temel TLV (tag-length-value) okuma.
//
// CertificationRequest ::= SEQUENCE {
//   certificationRequestInfo CertificationRequestInfo,
//   signatureAlgorithm       AlgorithmIdentifier,
//   signature                BIT STRING
// }
// CertificationRequestInfo ::= SEQUENCE {
//   version       INTEGER,
//   subject       Name,
//   subjectPKInfo SubjectPublicKeyInfo,
//   attributes    [0] IMPLICIT Attributes
// }
// ============================================================================

function readTLV(buf, offset) {
  const tag = buf[offset];
  const lenByte = buf[offset + 1];
  let lenOfLen = 0;
  let length;
  if (lenByte & 0x80) {
    lenOfLen = lenByte & 0x7f;
    length = 0;
    for (let i = 0; i < lenOfLen; i++) length = (length << 8) | buf[offset + 2 + i];
  } else {
    length = lenByte;
  }
  const hdrLen = 2 + lenOfLen;
  const start = offset + hdrLen;
  const end = start + length;
  return {
    tag, length, start, end, next: end, hdr: hdrLen,
  };
}

function oidBytesToDotted(bytes) {
  const first = bytes[0];
  const arcs = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = (value << 7) | (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) { arcs.push(value); value = 0; }
  }
  return arcs.join('.');
}

/**
 * @param {Buffer|string} csrPemOrDer
 * @returns {{ subjectNameDer: Buffer, spkiDer: Buffer, signatureValid: boolean }}
 */
function parseCsr(csrPemOrDer) {
  let der = csrPemOrDer;
  const looksLikePem = typeof csrPemOrDer === 'string'
    || (Buffer.isBuffer(csrPemOrDer) && csrPemOrDer.slice(0, 5).toString('ascii') === '-----');
  if (looksLikePem) {
    const pemStr = csrPemOrDer.toString('utf8');
    const b64 = pemStr.replace(/-----BEGIN [^-]+-----/, '').replace(/-----END [^-]+-----/, '').replace(/\s+/g, '');
    der = Buffer.from(b64, 'base64');
  }

  const outer = readTLV(der, 0); // CertificationRequest SEQUENCE
  const certReqInfo = readTLV(der, outer.start); // CertificationRequestInfo SEQUENCE
  const certReqInfoDer = der.slice(certReqInfo.start - certReqInfo.hdr, certReqInfo.end); // imza doğrulaması için TAM DER

  let p = certReqInfo.start;
  p = readTLV(der, p).next; // version INTEGER -- atla

  const subject = readTLV(der, p);
  const subjectNameDer = der.slice(subject.start - subject.hdr, subject.end); // tag+len DAHİL
  p = subject.next;

  const spki = readTLV(der, p); // SubjectPublicKeyInfo SEQUENCE
  const spkiDer = der.slice(spki.start - spki.hdr, spki.end); // tag+len DAHİL

  const afterCertReqInfo = certReqInfo.next;
  const sigAlg = readTLV(der, afterCertReqInfo);
  const sigAlgOidTlv = readTLV(der, sigAlg.start);
  const sigAlgOid = oidBytesToDotted(der.slice(sigAlgOidTlv.start, sigAlgOidTlv.end));
  const sigBitString = readTLV(der, sigAlg.next);
  // BIT STRING'in ilk baytı "kullanılmayan bit sayısı"dır -- imza baytları ondan sonra başlar.
  const signatureBytes = der.slice(sigBitString.start + 1, sigBitString.end);

  let signatureValid = false;
  try {
    const publicKey = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    // NOT: basitleştirme -- CSR imza algoritması OID'sinden (sigAlgOid) bağımsız olarak
    // SHA-256 varsayıyoruz (ecdsa-with-SHA256 / sha256WithRSAEncryption en yaygın
    // durumlardır). Farklı bir hash algoritması bekliyorsanız burayı genişletin.
    signatureValid = crypto.verify('sha256', certReqInfoDer, publicKey, signatureBytes);
  } catch {
    signatureValid = false;
  }

  return { subjectNameDer, spkiDer, signatureValid };
}

module.exports = { parseCsr };
