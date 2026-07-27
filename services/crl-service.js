'use strict';

const { reasonCodeOf } = require('./ocsp-service');

// RFC 5280 CRL üretimi — İKİ ayrı liste.
//
// Bir CRL yalnızca KENDİ yayıncısının imzaladığı sertifikalar hakkında konuşur.
// Doğrulayan taraf, bir sertifikanın iptal durumunu ararken o sertifikanın
// YAYINCISI tarafından imzalanmış bir CRL bekler; başka bir anahtarla imzalanmış
// liste, o sertifikayı kapsıyor sayılmaz ve sessizce yok sayılır.
//
//   scope 'leaf'  -> ara CA imzalar, uç sertifikaların iptallerini taşır
//   scope 'root'  -> kök CA imzalar, ARA CA'ların iptallerini taşır
//
// Önceki sürüm tek bir liste üretiyor ve onu KÖK anahtarıyla imzalıyordu, oysa
// listedeki uç sertifikaları ara CA imzalamıştı. Sonuç: iptal kayıtları
// üretiliyor, yayınlanıyor, ve hiçbir doğrulayıcı tarafından dikkate alınmıyordu.
// İptalin işe yaramadığı, ancak biri iptal edilmiş bir sertifikayla giriş
// yapmayı denediğinde fark edilirdi.
//
// Zincir semantiği: ara CA iptal edildiğinde altındaki her şey düşer. Bunu
// kök CRL'i taşır; uç CRL'in ayrıca her sertifikayı listelemesi gerekmez.

const CACHE_TTL_MS = 5 * 60 * 1000;
const CACHE_KEY_LEAF = 'crl:leaf';
const CACHE_KEY_ROOT = 'crl:root';

/**
 * @param {'leaf'|'root'} scope
 */
async function generateCrl({
  db, pkiIssuer, cacheStore, scope = 'leaf', forceRefresh = false,
}) {
  const cacheKey = scope === 'root' ? CACHE_KEY_ROOT : CACHE_KEY_LEAF;

  if (!forceRefresh && cacheStore) {
    const cached = await cacheStore.get(cacheKey);
    if (cached) return Buffer.from(cached, 'base64');
  }

  const certs = db.collection('certificates');
  const subCaSkid = pkiIssuer.subCA?.skid;
  const subCaSkidHex = Buffer.isBuffer(subCaSkid) ? subCaSkid.toString('hex') : String(subCaSkid || '');

  const revoked = [];
  // eslint-disable-next-line no-restricted-syntax
  for await (const row of certs.scan()) {
    if (row.status !== 'revoked') continue;

    // Bir kaydın hangi listeye ait olduğu, onu KİMİN imzaladığına bağlıdır.
    // Ara CA kaydı kök listesine, geri kalan her şey uç listesine gider.
    const isIntermediate = row.profile === 'intermediate-ca' || row.skidHex === subCaSkidHex;
    const belongsHere = scope === 'root' ? isIntermediate : !isIntermediate;
    if (!belongsHere) continue;

    revoked.push({
      serialNumberHex: row.serialNumberHex,
      revokedAt: new Date(Number(row.revokedAt) || Date.now()),
      // Sebep kodu taşınmazsa her iptal 'unspecified' görünür ve bir anahtar
      // sızıntısı ile planlı bir yenileme aynı şeye benzer. Bunlar operasyonel
      // olarak çok farklı olaylardır.
      reasonCode: reasonCodeOf(row.revocationReason),
    });
  }

  const crlDer = await pkiIssuer.signCrl({ revokedCerts: revoked, scope });
  if (cacheStore) await cacheStore.set(cacheKey, crlDer.toString('base64'), CACHE_TTL_MS);
  return crlDer;
}

/** Bir iptal sonrası HER İKİ önbelleği de temizler -- hangi listeye düştüğü
 * çağıranın bilmesi gereken bir ayrıntı olmamalı. */
async function invalidateCrlCache(cacheStore) {
  if (!cacheStore) return;
  await cacheStore.delete(CACHE_KEY_LEAF);
  await cacheStore.delete(CACHE_KEY_ROOT);
}

module.exports = { generateCrl, invalidateCrlCache, CACHE_TTL_MS, CACHE_KEY_LEAF, CACHE_KEY_ROOT };
