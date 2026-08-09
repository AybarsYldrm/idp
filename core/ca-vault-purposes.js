'use strict';

// Bir ara CA'nın hangi taleplere cevap verebileceğini belirleyen amaç adları.
//
// Kaynak @fitfak/database'in PkiVault'u; bu dosya yalnızca onu, KRİPTO
// KÜTÜPHANESİNİ YÜKLEMEDEN erişilebilir kılıyor. core/ca-vault.js @fitfak/ssl'e
// bağımlı ve olması gerekiyor; oysa "bu profil hangi amaca ait" sorusu saf
// veridir ve onu sormak için bir CA açmak gerekmemeli.
//
// Paket bulunamazsa aynı sabitler yerel olarak kullanılıyor. Bu, spiffe.js'teki
// kararın TERSİ ve fark önemli: SPIFFE kimliği iki taraf arasında
// KARŞILAŞTIRILAN bir değerdir, o yüzden iki uygulaması olamaz. Buradakiler ise
// yalnızca bu dağıtımın kendi içinde kullandığı sabit dizeler -- ayrışsalar bile
// karşı tarafa bir şey ifade etmiyorlar, ve testlerin paket kurulu olmadan
// koşabilmesi bundan daha değerli.

const FALLBACK = Object.freeze({
  TLS_SERVER: 'tls-server',
  TLS_CLIENT: 'tls-client',
  WORKLOAD: 'workload',
  EMAIL: 'email',
  CODE_SIGNING: 'code-signing',
  TIMESTAMPING: 'timestamping',
  OCSP: 'ocsp-responder',
});

let PKI_PURPOSES = FALLBACK;
try {
  // eslint-disable-next-line global-require
  const pkg = require('@fitfak/database');
  if (pkg.PKI_PURPOSES) PKI_PURPOSES = pkg.PKI_PURPOSES;
} catch (_) {
  // Paket yok: yukarıdaki sabitlerle devam.
}

module.exports = { PKI_PURPOSES };
