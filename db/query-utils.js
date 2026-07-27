'use strict';

// ============================================================================
// @fitfak/database'in GERÇEK API'sinde çoklu-eşleşme sorgusu YOK (`findOne` tek
// kayıt döner). Kullanıcının kendi referans `server.js`'inde (ListUsers, FindRecord
// '*' dalı) gösterdiği GERÇEK desen: `collection.scan()` -- TÜM kayıtlar üzerinde
// async iterasyon -- artı elle filtreleme. Bu dosya o deseni tek bir yerde toplar.
//
// NOT (dürüstlük): `scan()` tüm koleksiyonu tarar -- çok büyük koleksiyonlarda
// (milyonlarca oturum/credential kaydı) bu O(n)'dir. `sessions`/`webauthn_credentials`
// gibi koleksiyonlar kullanıcı başına küçük kaldığı sürece (birkaç oturum/passkey)
// pratikte sorun değil; gerçekten büyüyen bir koleksiyon için @fitfak/database'in
// (varsa) sayfalı/indeksli bir tarama API'sine geçmeyi düşünün.
// ============================================================================

async function scanFindAll(collection, field, value) {
  const results = [];
  for await (const rec of collection.scan()) {
    if (rec[field] === value) results.push(rec);
  }
  return results;
}

module.exports = { scanFindAll };
