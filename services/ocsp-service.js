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

/** Bulunmuş bir kaydın OCSP durumu. */
async function statusForRow(row, { issuerRevoked }) {
  if (issuerRevoked) {
    return {
      status: 'revoked',
      revokedAt: issuerRevoked.revokedAt,
      reason: CA_COMPROMISE,
    };
  }

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
 * Bu ara CA'nın kendisi iptal edilmiş mi? Edilmişse altındaki HER sertifika
 * geçersizdir ve tek tek sorulmalarına gerek kalmadan öyle yanıtlanır.
 *
 * SKID, SORULAN sertifikanın yayıncısından geliyor -- her zaman varsayılan ara CA'dan değil.
 * Sabit bir yayıncıya bakmak, beş ara CA'nın olduğu bir kurulumda iki yönde birden yanılırdı:
 * iptal edilmiş bir CA'nın altındaki sertifikalar 'good' görünür, ya da geçerli bir CA'nın
 * altındakiler başka birinin iptali yüzünden 'revoked' ilan edilirdi.
 */
async function findRevokedIssuer(certs, pkiIssuer, authorityName) {
  const skidHex = authorityName
    ? await pkiIssuer.getAuthoritySkidHex(authorityName)
    : (() => {
      const skid = pkiIssuer.subCA?.skid;
      return skid ? (Buffer.isBuffer(skid) ? skid.toString('hex') : String(skid)) : null;
    })();
  if (!skidHex) return null;
  const row = await certs.findOne('skidHex', skidHex);
  if (!row || row.status !== 'revoked') return null;
  return { revokedAt: new Date(Number(row.revokedAt) || Date.now()) };
}

/**
 * Sorulan serilerin kayıtlarını, kanonik biçimleriyle birlikte bulur.
 *
 * Biçim denemesi burada toplandı, çünkü artık kayıt İKİ şey için gerekiyor: durumu ve
 * yayıncısı. İki ayrı yerde aramak, ikisinin farklı kayıt bulabilmesi demek olurdu.
 */
/**
 * Yanıtı hangi anahtarın imzalayacağı.
 *
 * RFC 6960 §4.2.2.2: bir OCSP yanıtını imzalayan anahtar, sorulan sertifikanın YAYINCISI
 * olmalıdır. Beş ara CA varken sabit bir imzalayıcı, dördünün verdiği sertifikalar için
 * istemcinin yanıtı 'unauthorized' sayması demektir -- ve o noktada iptal kontrolü cevap
 * alınamadığı için tamamen atlanır.
 *
 * Yayıncı, sorulan sertifikanın KAYDINDAN geliyor: istek yalnızca seriyi taşır ve hangi CA'nın
 * imzaladığını bilen tek yer kayıttır. Bir istek birden fazla yayıncının sertifikasını
 * sorabilir (RFC bunu yasaklamaz) ve tek bir yanıt hepsi için yetkili olamaz -- o durumda ilk
 * bulunanın yayıncısı seçilir ve geri kalanlar 'unknown' olarak yanıtlanır, ki istemci doğru
 * responder'a gitsin.
 *
 * Ayrı bir fonksiyon, çünkü sınanması gereken karar bu ve @fitfak/ssl'e ihtiyaç duymadan
 * sınanabilmeli.
 */
function chooseResponder(resolved, fallback) {
  const found = resolved.find((entry) => entry.row && entry.authority);
  return found ? found.authority : fallback;
}

async function resolveRequested(certs, requests, defaultAuthority = null) {
  const out = [];
  for (const entry of requests) {
    // @fitfak/ssl haritada seriyi `BigInt#toString(16)` biçiminde arar: baştaki sıfırlar
    // olmadan, küçük harf. Veritabanındaki değer başka bir biçimde yazılmış olabileceğinden
    // aramayı kanonik biçim üzerinden yapıp haritaya da o biçimle koyuyoruz.
    const canonical = entry.serialNumber.toString(16);
    const candidates = [
      canonical,
      canonical.toUpperCase(),
      canonical.padStart(canonical.length + (canonical.length % 2), '0'),
    ];
    let row = null;
    for (const candidate of candidates) {
      // eslint-disable-next-line no-await-in-loop
      row = await certs.findOne('serialNumberHex', candidate);
      if (row) break;
    }
    // Yayıncı adı burada çözülüyor: alan bu düzeltmeyle geldi, yani ondan önce yazılmış
    // kayıtlarda boş. O kayıtlar tek bir ara CA varken üretildi, yani varsayılana koymak doğru
    // -- ve onları düşürmek, alanın eklendiği güne kadarki her sertifikayı 'unknown' yapardı.
    out.push({ canonical, row, authority: row ? (row.issuerName || defaultAuthority) : null });
  }
  return out;
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

  const resolved = await resolveRequested(certs, request.requests, pkiIssuer.subCA?.name || null);

  const authority = chooseResponder(resolved, pkiIssuer.subCA?.name || null);
  const issuerRevoked = await findRevokedIssuer(certs, pkiIssuer, authority);

  const statusMap = new Map();
  for (const { canonical, row, authority: rowAuthority } of resolved) {
    // Bu yanıt `authority` ile imzalanacak, yani BAŞKA bir CA'nın verdiği sertifikalar için
    // yetkili değil. Onlara 'good' ya da 'revoked' demek, yetkisi olmadığı bir sertifika
    // hakkında hüküm vermek olurdu; 'unknown' doğru cevaptır ve istemciyi doğru yayıncının
    // responder'ına yönlendirir.
    //
    // Kayıt yoksa da 'unknown' -- 'good' DEĞİL: bu CA'nın hiç üretmediği bir seri için
    // "iptal edilmemiş" demek, uydurma seri taşıyan bir sertifikaya olumlu cevap vermektir.
    if (!row || (authority && rowAuthority !== authority)) {
      statusMap.set(canonical, { status: 'unknown' });
      continue;
    }
    statusMap.set(canonical, await statusForRow(row, { issuerRevoked }));
  }

  return pkiIssuer.generateOcspResponse({ ocspRequestDer, statusLookup: statusMap, authority });
}

module.exports = { handleOcspRequest, chooseResponder, REASON_CODES, reasonCodeOf };
