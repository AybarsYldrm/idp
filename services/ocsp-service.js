'use strict';

// RFC 6960 OCSP yanıtlayıcısı.
//
// İki şey burada kasıtlı olarak farklı yapılıyor.
//
// 1) SORULAN SERİLER ARANIR, TÜM KOLEKSİYON TARANMAZ.
//    Önceki sürüm her OCSP isteğinde `certificates` koleksiyonunun TAMAMINI
//    tarayıp bellekte bir durum haritası kuruyordu. OCSP, TLS el sıkışma
//    hızında sorgulanan bir uçtur; her sorguda O(n) kayıt çözmek, sertifika
//    sayısı arttıkça responder'ı sistemin en yavaş parçası yapar -- ve bir
//    responder yavaşladığında istemciler iptal kontrolünü atlamaya başlar,
//    yani yük sorunu sessizce bir güvenlik sorununa dönüşür.
//    Seri numarası zaten indeksli; sorulan 1-2 seriyi indeksden okumak O(1)'dir.
//
// 2) İPTAL BİR ZİNCİRDİR.
//    Bir ara CA iptal edildiğinde, altındaki her uç sertifika da geçersizdir.
//    Zinciri baştan sona doğrulayan bir istemci bunu ara sertifikayı ayrıca
//    sorgulayarak görür -- ama hepsi bunu yapmaz. Bu yüzden bir uç sertifikanın
//    durumu, KENDİ kaydı 'valid' olsa bile, yayıncısı iptal edilmişse 'revoked'
//    olarak yanıtlanır. Yanlış tarafa hata yapmak burada ucuz.

const CA_COMPROMISE = 2; // RFC 5280 CRLReason: cACompromise

// RFC 5280 CRLReason kodları. Veritabanında sebep serbest metin olarak
// tutuluyor; OCSP/CRL ise sayısal kod ister.
const REASON_CODES = {
  unspecified: 0,
  keyCompromise: 1,
  cACompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  certificateHold: 6,
  privilegeWithdrawn: 9,
  aACompromise: 10,
};

function reasonCodeOf(value) {
  if (typeof value === 'number') return value;
  return REASON_CODES[String(value || '').trim()] ?? REASON_CODES.unspecified;
}

/**
 * Bir serinin OCSP durumunu üretir. Kayıt yoksa 'unknown' döner -- 'good'
 * DEĞİL: bu CA'nın hiç üretmediği bir seri için "iptal edilmemiş" demek,
 * uydurma seri taşıyan bir sertifikaya olumlu cevap vermektir.
 */
async function statusForSerial(certs, serialHex, { issuerRevoked }) {
  if (issuerRevoked) {
    return {
      status: 'revoked',
      revokedAt: issuerRevoked.revokedAt,
      reason: CA_COMPROMISE,
    };
  }

  const row = await certs.findOne('serialNumberHex', serialHex);
  if (!row) return { status: 'unknown' };

  if (row.status === 'revoked') {
    return {
      status: 'revoked',
      revokedAt: new Date(Number(row.revokedAt) || Date.now()),
      reason: reasonCodeOf(row.revocationReason),
    };
  }
  return { status: 'good' };
}

/**
 * Ara CA'nın kendisi iptal edilmiş mi? Edilmişse altındaki HER sertifika
 * geçersizdir ve tek tek sorulmalarına gerek kalmadan öyle yanıtlanır.
 */
async function findRevokedIssuer(certs, pkiIssuer) {
  const skid = pkiIssuer.subCA?.skid;
  if (!skid) return null;
  const skidHex = Buffer.isBuffer(skid) ? skid.toString('hex') : String(skid);
  const row = await certs.findOne('skidHex', skidHex);
  if (!row || row.status !== 'revoked') return null;
  return { revokedAt: new Date(Number(row.revokedAt) || Date.now()) };
}

async function handleOcspRequest({ db, pkiIssuer, ocspRequestDer }) {
  const pki = require('@fitfak/ssl/src/pki');
  const certs = db.collection('certificates');

  // İsteği önce ayrıştır: hangi serilerin sorulduğunu bilmeden hangi kayıtları
  // okuyacağımızı da bilemeyiz.
  //
  // Ayrıştırılamayan bir istek HTTP 500 ile CEVAPLANMAZ. 500, "responder
  // bozuk" demektir; istemciler bunu geçici bir arıza sayar, yeniden dener ve
  // bir noktada iptal kontrolünü tamamen atlar -- yani başkasının gönderdiği
  // bozuk bayt, bizim iptal altyapımızı devre dışı bırakmış olur. RFC 6960
  // bunun için imzasız bir `malformedRequest` yanıtı tanımlar (§4.2.1):
  // düzeltmesi gereken tarafı doğru gösterir.
  let request;
  try {
    request = pki.parseOcspRequest(ocspRequestDer);
  } catch (err) {
    return pki.buildOcspErrorResponse('malformedRequest');
  }
  if (!request || !Array.isArray(request.requests) || request.requests.length === 0) {
    return pki.buildOcspErrorResponse('malformedRequest');
  }

  const issuerRevoked = await findRevokedIssuer(certs, pkiIssuer);

  const statusMap = new Map();
  for (const entry of request.requests) {
    // @fitfak/ssl haritada seriyi `BigInt#toString(16)` biçiminde arar:
    // baştaki sıfırlar olmadan, küçük harf. Veritabanındaki değer başka bir
    // biçimde yazılmış olabileceğinden, aramayı kanonik biçim üzerinden yapıp
    // haritaya da o biçimle koyuyoruz -- önceki sürümdeki "her varyasyonu
    // haritaya göm" yaklaşımı, biçimin hiçbir yerde sabitlenmemiş olmasının
    // belirtisiydi.
    const canonical = entry.serialNumber.toString(16);
    const candidates = new Set([
      canonical,
      canonical.toUpperCase(),
      canonical.padStart(canonical.length + (canonical.length % 2), '0'),
    ]);

    let resolved = { status: 'unknown' };
    for (const candidate of candidates) {
      const found = await statusForSerial(certs, candidate, { issuerRevoked });
      if (found.status !== 'unknown') { resolved = found; break; }
    }
    statusMap.set(canonical, resolved);
  }

  return pkiIssuer.generateOcspResponse({ ocspRequestDer, statusLookup: statusMap });
}

module.exports = { handleOcspRequest, REASON_CODES, reasonCodeOf };
