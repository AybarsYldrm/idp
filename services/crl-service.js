'use strict';

const { reasonCodeOf } = require('./ocsp-service');

// RFC 5280 CRL üretimi — HER YAYINCI İÇİN AYRI BİR LİSTE.
//
// Bir CRL yalnızca KENDİ yayıncısının imzaladığı sertifikalar hakkında konuşur.
// Doğrulayan taraf, bir sertifikanın iptal durumunu ararken o sertifikanın
// YAYINCISI tarafından imzalanmış bir CRL bekler; başka bir anahtarla imzalanmış
// liste, o sertifikayı kapsıyor sayılmaz ve sessizce yok sayılır (§6.3.3).
//
//   /crl/root          -> kök imzalar, ARA CA'ların iptallerini taşır
//   /crl/<otorite-adı>  -> o ara CA imzalar, YALNIZCA onun verdiği uçları taşır
//
// BU DOSYA İKİ KEZ DÜZELTİLDİ ve ikisi de aynı hatanın farklı ölçekleriydi.
//
// İlk sürüm TEK bir liste üretip onu KÖK anahtarıyla imzalıyordu, oysa listedeki
// uç sertifikaları ara CA imzalamıştı. İkinci sürüm listeyi ikiye ayırdı ama uç
// tarafını hâlâ tek bir ara CA'nın imzaladığı TEK bir liste olarak bıraktı --
// beş ara CA varken (her amaç için ayrı) bu, o beşten dördünün verdiği her
// sertifikanın iptalinin etkisiz kalması demekti.
//
// İkisinin de ortak yanı, yanlış olduğunun HİÇBİR YERDE görünmemesiydi: iptal
// kaydı üretiliyor, liste yayınlanıyor, HTTP 200 dönüyor ve doğrulayıcı listeyi
// kendi sertifikasını kapsamadığı için yok sayıyordu. Fark edilmesinin tek yolu,
// iptal edilmiş bir sertifikayla giriş yapmayı deneyip başarılı olmaktı.
//
// Zincir semantiği: ara CA iptal edildiğinde altındaki her şey düşer. Bunu kök
// CRL'i taşır; uç listelerin ayrıca her sertifikayı listelemesi gerekmez.

const CACHE_TTL_MS = 5 * 60 * 1000;
const CACHE_KEY_ROOT = 'crl:root';
const cacheKeyFor = (authority) => `crl:leaf:${authority}`;

// Eski adlar dışarıda kullanılıyordu; kaldırmak, bu modülü içeri alan her yeri
// aynı anda değiştirmeyi gerektirirdi.
const CACHE_KEY_LEAF = cacheKeyFor('default');

/**
 * Bir yayıncının iptal listesi.
 *
 * @param {object}  opts
 * @param {string} [opts.authority]  kasadaki otorite adı ('workload-ca', 'email-ca', ...).
 *                                   Verilmezse varsayılan uç yayıncısı kullanılır.
 * @param {'leaf'|'root'} [opts.scope]
 */
async function generateCrl({
  db, pkiIssuer, cacheStore, scope = 'leaf', authority = null, forceRefresh = false,
}) {
  const isRoot = scope === 'root';
  // Otorite adı çözülmeden önbellek anahtarı kurulamaz: iki farklı otorite için aynı anahtarı
  // kullanmak, birinin listesini diğerine servis etmek olurdu ve bu, düzeltmeye çalıştığımız
  // hatanın önbellek üzerinden geri gelmesi demek.
  const issuerName = isRoot ? 'root' : (authority || pkiIssuer.subCA?.name || 'default');
  const cacheKey = isRoot ? CACHE_KEY_ROOT : cacheKeyFor(issuerName);

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
    // Ara CA kaydı kök listesine, geri kalan her şey kendi yayıncısının listesine gider.
    const isIntermediate = row.profile === 'intermediate-ca' || row.skidHex === subCaSkidHex;
    if (isRoot) {
      if (!isIntermediate) continue;
    } else {
      if (isIntermediate) continue;
      // `issuerName` alanı bu düzeltmeyle geldi, yani ondan ÖNCE yazılmış kayıtlarda boş.
      // Onları varsayılan yayıncının listesine koymak, alanın eklendiği güne kadar üretilmiş
      // her iptali sessizce düşürmekten iyidir -- ve o kayıtlar zaten tek bir ara CA varken
      // üretilmişti, yani varsayım doğru.
      const rowIssuer = row.issuerName || pkiIssuer.subCA?.name || '';
      if (rowIssuer !== issuerName) continue;
    }

    revoked.push({
      serialNumberHex: row.serialNumberHex,
      revokedAt: new Date(Number(row.revokedAt) || Date.now()),
      // Sebep kodu taşınmazsa her iptal 'unspecified' görünür ve bir anahtar
      // sızıntısı ile planlı bir yenileme aynı şeye benzer. Bunlar operasyonel
      // olarak çok farklı olaylardır.
      reasonCode: reasonCodeOf(row.revocationReason),
    });
  }

  const crlDer = await pkiIssuer.signCrl({
    revokedCerts: revoked,
    scope,
    authority: isRoot ? 'root' : issuerName,
  });
  if (cacheStore) await cacheStore.set(cacheKey, crlDer.toString('base64'), CACHE_TTL_MS);
  return crlDer;
}

/**
 * Bir iptal sonrası önbellekleri temizler.
 *
 * Hangi listeye düştüğü çağıranın bilmesi gereken bir ayrıntı olmamalı, o yüzden `authority`
 * verilmezse TÜM uç listeleri geçersizleşir. Yanlış listeyi temizlemek, iptal edilmiş bir
 * sertifikanın beş dakika daha 'geçerli' görünmesi demektir -- ve bu, temizlemeyi hiç
 * yapmamakla aynı sonucu verir.
 */
async function invalidateCrlCache(cacheStore, { authorities = [], authority = null } = {}) {
  if (!cacheStore) return;
  await cacheStore.delete(CACHE_KEY_ROOT);
  if (authority) {
    await cacheStore.delete(cacheKeyFor(authority));
    return;
  }
  await cacheStore.delete(CACHE_KEY_LEAF);
  for (const name of authorities) await cacheStore.delete(cacheKeyFor(name));
}

module.exports = {
  generateCrl, invalidateCrlCache, cacheKeyFor,
  CACHE_TTL_MS, CACHE_KEY_LEAF, CACHE_KEY_ROOT,
};
