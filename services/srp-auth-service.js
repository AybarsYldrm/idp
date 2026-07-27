'use strict';

const crypto = require('node:crypto');

const { SrpServer, SrpError, fakeCredentials } = require('../core/srp');
const { AppError } = require('../core/errors');

// SRP girişinin HTTP tarafı.
//
// İki adımlı bir protokol, durumsuz bir HTTP arayüzüne oturtuluyor: sunucunun
// efemer gizli üssü b, iki istek arasında bir yerde durmak zorunda. Paylaşılan
// ephemeral store kullanılıyor -- süreç belleği DEĞİL: birden fazla instance bir
// yük dengeleyici arkasındayken ikinci istek başka bir instance'a düşer ve o
// instance b'yi bilmezse giriş, yükün nereye gittiğine bağlı olarak rastgele
// başarısız olur.
//
// Durum tek kullanımlıktır ve doğrulamadan ÖNCE tüketilir: aynı challenge'a
// karşı sınırsız M1 denemesi, çevrimiçi sözlük saldırısının tam olarak istediği
// şeydir.

const SRP_STATE_TTL_MS = 2 * 60 * 1000;

/**
 * Kullanıcı numaralandırmasına karşı sunucunun kendi sırrı. Var olmayan bir
 * kullanıcı için üretilen sahte salt bundan türetilir; her açılışta değişmemesi
 * gerekir, yoksa "aynı isim için salt değişti" gözlemi hesabın var olmadığını
 * ele verir.
 */
function serverEnumerationSecret(config) {
  return crypto.createHash('sha256')
    .update(config.db.rootSecret || Buffer.alloc(32))
    .update('srp-enumeration-v1')
    .digest();
}

/**
 * 1. adım: istemci kimliğini ve A'sını gönderir; sunucu salt ve B ile yanıtlar.
 *
 * Kullanıcı yoksa da GERÇEKÇİ bir yanıt döner. Erken "kullanıcı bulunamadı"
 * dönmek, giriş ucunu bir numaralandırma oracle'ına çevirir: kayıt uçları ne
 * kadar dikkatli yazılırsa yazılsın, saldırgan hangi e-postaların kayıtlı
 * olduğunu buradan öğrenir.
 */
async function beginSrpLogin({ db, store, config, identity }) {
  if (!identity || typeof identity !== 'string') {
    throw new AppError('invalid_request', 'kimlik gerekli', { httpStatus: 400 });
  }
  const normalized = identity.trim().toLowerCase();

  const users = db.collection('users');
  let row = null;
  try { row = await users.findOne('email', normalized); } catch (_) { row = null; }
  if (!row) {
    try { row = await users.findOne('username', identity.trim()); } catch (_) { row = null; }
  }

  const real = row && row.srpSalt && row.srpVerifier;
  const credentials = real
    ? { saltB64: row.srpSalt, verifierB64: row.srpVerifier }
    : fakeCredentials(normalized, serverEnumerationSecret(config));

  const server = new SrpServer({ identity: normalized, ...credentials });
  const challenge = server.challenge();

  // b (sunucunun efemer gizli üssü) ve doğrulayıcı, ikinci isteğe kadar
  // saklanıyor. Bu değerler paylaşılan store'da durduğu için şifreli
  // veritabanına yazılır; ömürleri iki dakikadır.
  const stateId = crypto.randomUUID();
  await store.set(stateId, JSON.stringify({
    identity: normalized,
    saltB64: credentials.saltB64,
    verifierB64: credentials.verifierB64,
    b: server.b.toString(16),
    B: challenge.B,
    userId: real ? String(row._id) : null,
  }), SRP_STATE_TTL_MS);

  return { stateId, saltB64: challenge.saltB64, B: challenge.B };
}

/**
 * 2. adım: istemci A ve M1 kanıtını gönderir. Başarılıysa sunucu M2 ile kendini
 * doğrular ve giriş akışı (2. faktör) devam eder.
 */
async function finishSrpLogin({ db, store, stateId, A, M1 }) {
  if (!stateId || !A || !M1) {
    throw new AppError('invalid_request', 'eksik parametre', { httpStatus: 400 });
  }

  const raw = await store.get(stateId);
  // Durum, doğrulamadan ÖNCE tüketiliyor: aksi halde tek bir challenge'a karşı
  // sınırsız parola denemesi yapılabilirdi ve SRP'nin çevrimiçi tahmin sınırı
  // ortadan kalkardı.
  await store.delete(stateId);

  if (!raw) {
    throw new AppError('auth_failed', 'Kimlik doğrulama başarısız', { httpStatus: 401 });
  }
  const state = JSON.parse(raw);

  const server = new SrpServer({
    identity: state.identity,
    saltB64: state.saltB64,
    verifierB64: state.verifierB64,
  });
  // Challenge'ı yeniden üretmek yerine, İLK adımda gönderilmiş olanı geri
  // yüklüyoruz: B yeniden hesaplanırsa (yeni bir rastgele b ile) istemcinin
  // kanıtı hiçbir zaman tutmaz.
  server.b = BigInt(`0x${state.b}`);
  server.B = BigInt(`0x${Buffer.from(state.B, 'base64').toString('hex')}`);

  let result;
  try {
    result = server.verify({ A, M1 });
  } catch (err) {
    if (err instanceof SrpError) {
      // Tek ve aynı hata: "kullanıcı yok" ile "parola yanlış" ayrımı
      // saldırgana verilmiyor.
      throw new AppError('auth_failed', 'Kimlik doğrulama başarısız', { httpStatus: 401 });
    }
    throw err;
  }

  // Sahte kimlik bilgileriyle buraya ulaşmak imkânsıza yakındır (kimse o
  // doğrulayıcının x'ini bilmiyor), ama ulaşılsaydı userId null olurdu --
  // o durumda da giriş verilmemeli.
  if (!state.userId) {
    throw new AppError('auth_failed', 'Kimlik doğrulama başarısız', { httpStatus: 401 });
  }

  return { M2: result.M2, userId: state.userId, sessionKey: result.sessionKey };
}

/**
 * Kayıt / parola değiştirme: doğrulayıcı TARAYICIDA üretilir ve buraya gelir.
 * Sunucu parolayı görmez, dolayısıyla karmaşıklık kuralını da uygulayamaz --
 * bu kontrol istemci tarafına geçer. Bu, PAKE kullanmanın kaçınılmaz sonucudur
 * ve gizlenmemelidir: sunucu tarafı parola politikası, parolayı görmeyi gerektirir.
 */
async function setSrpCredentials({ db, userId, saltB64, verifierB64 }) {
  if (!saltB64 || !verifierB64) {
    throw new AppError('invalid_request', 'salt ve doğrulayıcı gerekli', { httpStatus: 400 });
  }
  // Boyut kontrolü: yanlış uzunlukta bir doğrulayıcı, protokolü sessizce
  // çalışmaz hale getirir ve belirtisi yine "parola yanlış" olur.
  const verifier = Buffer.from(verifierB64, 'base64');
  const salt = Buffer.from(saltB64, 'base64');
  if (verifier.length < 200 || verifier.length > 256) {
    throw new AppError('invalid_request', 'doğrulayıcı boyutu geçersiz', { httpStatus: 400 });
  }
  if (salt.length < 16 || salt.length > 64) {
    throw new AppError('invalid_request', 'salt boyutu geçersiz', { httpStatus: 400 });
  }

  await db.collection('users').update(userId, {
    srpSalt: saltB64,
    srpVerifier: verifierB64,
    // Eski parola hash'i artık gereksiz. Bırakılırsa, SRP'ye geçmiş bir hesap
    // hâlâ eski (parolayı telde gönderen) yoldan da girilebilir olurdu -- yani
    // geçiş, saldırgana bir seçenek eklemekten başka bir şey yapmazdı.
    passwordHash: '',
  });
  return { updated: true };
}

module.exports = { beginSrpLogin, finishSrpLogin, setSrpCredentials, SRP_STATE_TTL_MS };
