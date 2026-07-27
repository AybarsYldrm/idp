'use strict';

// ============================================================================
// RFC 5280 CRL (Certificate Revocation List) üretimi. `certificates` koleksiyonundaki
// TÜM iptal edilmiş kayıtları tarar (bkz. db/query-utils.js'teki scan() deseni),
// GERÇEK imzalamayı core/pki-issuer.js üzerinden SİZİN @fitfak/ssl'inize delege eder.
//
// ÖNBELLEKLEME NOTU (v1.4 düzeltmesi): CRL üretimi (özellikle çok sayıda iptal varsa)
// pahalı olabilir VE CRL'ler doğası gereği "biraz eski" olsalar bile GÜVENLİDİR
// (istemciler zaten periyodik olarak yeniden çeker) -- bu yüzden bir önbellek tutuyoruz.
// ESKİ SÜRÜM bunu modül-seviyesi bir DEĞİŞKENDE (`let cached = null`) tutuyordu -- bu,
// birden fazla fitfak-idp instance'ı bir yük dengeleyici arkasında koşarken KIRIKTIR:
// instance A'da bir sertifika iptal edilip `invalidateCrlCache()` çağrılsa bile,
// instance B'nin KENDİ bellek-içi `cached` değişkeni bundan HİÇ HABERDAR OLMAZ ve eski
// (artık iptal edilmiş sertifikayı içermeyen) bir CRL sunmaya devam edebilir. Şimdi
// önbellek `core/ephemeral-store.js` üzerinden PAYLAŞILAN store'da tutuluyor -- hangi
// instance sorarsa sorsun AYNI önbellek durumunu görür.
// ============================================================================
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 dakika -- bu süre boyunca yeni bir iptal CRL'e YANSIMAYABİLİR
const CACHE_KEY = 'crl:current';

/**
 * @param {object} opts
 * @param {object} opts.db
 * @param {object} opts.pkiIssuer
 * @param {object} opts.cacheStore - core/ephemeral-store.js arayüzü (paylaşılan DB-destekli
 *   store) -- verilmezse (ör. testlerde) önbellek atlanır, HER çağrıda yeniden üretilir.
 * @param {boolean} [opts.forceRefresh]
 */
async function generateCrl({
  db, pkiIssuer, cacheStore, forceRefresh = false,
}) {
  if (!forceRefresh && cacheStore) {
    const cachedB64 = await cacheStore.get(CACHE_KEY);
    if (cachedB64) return Buffer.from(cachedB64, 'base64');
  }

  const certs = db.collection('certificates');
  const revoked = [];
  // eslint-disable-next-line no-restricted-syntax
  for await (const row of certs.scan()) {
    if (row.status === 'revoked') {
      revoked.push({ serialNumberHex: row.serialNumberHex, revokedAt: new Date(Number(row.revokedAt)) });
    }
  }

  const crlDer = await pkiIssuer.signCrl({ revokedCerts: revoked });
  if (cacheStore) await cacheStore.set(CACHE_KEY, crlDer.toString('base64'), CACHE_TTL_MS);
  return crlDer;
}

/** Bir sertifika iptal edildiğinde çağrılır -- PAYLAŞILAN önbelleği temizler, TÜM
 * instance'lar bir sonraki istekte taze bir CRL üretir. */
async function invalidateCrlCache(cacheStore) {
  if (cacheStore) await cacheStore.delete(CACHE_KEY);
}

module.exports = { generateCrl, invalidateCrlCache, CACHE_TTL_MS };
