'use strict';

const crypto = require('node:crypto');
const { modPow } = require('@fitfak/ssl/src/bigint');

// SRP-6a (RFC 5054 / RFC 2945) — parolanın sunucuya HİÇ ulaşmadığı kimlik doğrulama.
//
// Neden bir PAKE.
//
// Parolayı TLS içinde düz metin gönderip sunucuda scrypt'lemek, parolayı düz
// metin GÖNDERMEK demektir. TLS'i sonlandıran her şey -- ters proxy, CDN, yük
// dengeleyici, hata ayıklama için açılmış bir istek loglayıcı, bellek dökümü
// alan biri -- o anda parolanın kendisini görür. "Salt'lı saklıyoruz" bunu
// değiştirmez: saklama sonrasını korur, aktarımı değil.
//
// SRP'de sunucu parolayı hiçbir aşamada görmez. İstemci parolayı yalnızca
// kendi tarafında bir üstel işleme sokar; taraflar aynı oturum anahtarına
// bağımsız olarak varır ve birbirlerine parolayı bilmenin KANITINI gönderir.
//
// Dürüst sınır: SRP "augmented" bir PAKE'dir. Sunucu bir doğrulayıcı (v = g^x)
// saklar ve bu, parolanın kendisi değildir -- ama v çalınırsa ÇEVRİMDIŞI sözlük
// saldırısı mümkündür. OPAQUE bunu da engeller. Buradaki karşı önlem x'i pahalı
// bir KDF ile türetmektir (aşağıya bakın), ki bu çevrimdışı saldırıyı parola
// başına scrypt maliyetine çıkarır.
//
// RFC 5054'ten BİLEREK sapma: RFC, x = SHA1(s | SHA1(I ":" p)) der. SHA-1 hızlı
// olduğundan çalınmış bir doğrulayıcıya karşı sözlük saldırısı da hızlıdır.
// Burada x = PBKDF2-HMAC-SHA256(p, s, 600000) kullanılıyor. RFC 5054
// uyumluluğunu bozar; üçüncü taraf bir SRP istemcisiyle konuşulmayacağı için
// kabul edilebilir bir takas.
//
// Neden PBKDF2, scrypt değil? Bu türetme tarayıcıda da BİREBİR aynı şekilde
// yapılmak zorunda -- x istemcide hesaplanır, parola cihazdan çıkmaz. Web
// Crypto scrypt sunmaz, PBKDF2 sunar. scrypt kullanmak, tarayıcıya elle
// yazılmış bir scrypt göndermeyi gerektirirdi ve ince hatalı bir KDF burada
// sessizce yanlış anahtar üretir: belirti "parola yanlış" olur, sebebi bulmak
// çok zordur. Elle yazılmış kripto ile bellek-sertliği arasında seçim
// gerektiğinde, her iki tarafta da denetimden geçmiş yerleşik uygulamayı
// kullanmak daha savunulabilir.
//
// Bunun bedeli açıktır: PBKDF2 bellek-sert değildir, dolayısıyla ÇALINMIŞ bir
// doğrulayıcıya karşı GPU hızlandırmalı sözlük saldırısı scrypt'e göre daha
// ucuzdur. 600.000 tur (OWASP'ın PBKDF2-HMAC-SHA256 için önerdiği alt sınır)
// bunu tahmin başına anlamlı bir maliyette tutar, ve doğrulayıcı zaten
// şifrelenmiş veritabanında durur -- yani saldırganın önce onu ele geçirmesi
// gerekir.

// RFC 5054 Ek A, 2048-bit grup. N güvenli asaldır (N = 2q+1), g = 2.
// Bu değerlerin gerçekten asal olduğu test/srp-demo.js içinde doğrulanır:
// yanlış bir N, protokolü çalışır gösterip güvenliğini tamamen kaldırırdı.
const N_HEX = [
  'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050',
  'A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50',
  'E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8',
  '55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B',
  'CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748',
  '544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6',
  'AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6',
  '94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73',
].join('');

const N = BigInt(`0x${N_HEX}`);
const g = 2n;
const N_BYTES = 256; // 2048 bit

// OWASP'ın PBKDF2-HMAC-SHA256 için önerdiği alt sınır.
const PBKDF2_ITERATIONS = 600000;
const PBKDF2_DKLEN = 32;

class SrpError extends Error {
  constructor(code, message) { super(message); this.name = 'SrpError'; this.code = code; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Yardımcılar
// ─────────────────────────────────────────────────────────────────────────────

/** Sabit uzunluğa sola sıfır dolgusu. RFC 5054 §2.6: hash'lenen her grup
 * elemanı N uzunluğuna PAD edilir. Dolgusuz hash'lemek, A veya B'nin baştaki
 * baytı sıfır olduğunda iki tarafın FARKLI u değeri hesaplamasına yol açar --
 * kimlik doğrulama, girdilerin şansına bağlı olarak arada bir başarısız olur. */
function pad(buf) {
  if (buf.length >= N_BYTES) return buf;
  return Buffer.concat([Buffer.alloc(N_BYTES - buf.length), buf]);
}

function toBuf(bigint) {
  let hex = bigint.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return Buffer.from(hex, 'hex');
}

function toBig(buf) {
  return BigInt(`0x${buf.toString('hex') || '00'}`);
}

function H(...parts) {
  const hash = crypto.createHash('sha256');
  for (const p of parts) hash.update(Buffer.isBuffer(p) ? p : Buffer.from(String(p), 'utf8'));
  return hash.digest();
}

/** k = H(N | PAD(g)) — SRP-6a. SRP-6'da k=3 sabitti; sabit k, sunucunun
 * kendini doğrulamadan istemciyi kandırabildiği bir saldırıya açıktı. */
const k = toBig(H(pad(toBuf(N)), pad(toBuf(g))));

/**
 * x = KDF(parola, salt). Parolanın tek üstel gösterimi burada üretilir ve
 * SADECE istemcide çalışır (kayıt sırasında bir kez de sunucuya doğrulayıcı
 * üretmek için istemcide çalışır).
 */
function deriveX(password, salt) {
  const dk = crypto.pbkdf2Sync(
    Buffer.from(String(password), 'utf8'), salt,
    PBKDF2_ITERATIONS, PBKDF2_DKLEN, 'sha256',
  );
  return toBig(dk) % N;
}

// ─────────────────────────────────────────────────────────────────────────────
// Kayıt (istemci tarafında çalışır)
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Parolanın kendisi yerine bir doğrulayıcı üretir. `verifier` ve `salt`
 * sunucuya gönderilir; parola cihazdan ÇIKMAZ.
 */
function createVerifier({ password, salt = crypto.randomBytes(32) }) {
  const x = deriveX(password, salt);
  const v = modPow(g, x, N);
  return { salt, verifier: toBuf(v).toString('base64'), saltB64: salt.toString('base64') };
}

// ─────────────────────────────────────────────────────────────────────────────
// İstemci
// ─────────────────────────────────────────────────────────────────────────────
class SrpClient {
  constructor({ identity, password }) {
    this.identity = identity;
    this.password = password;
    // a: efemer, oturuma özel. 256 bit RFC 5054'ün önerdiği alt sınırın üzerinde.
    this.a = toBig(crypto.randomBytes(32));
    this.A = modPow(g, this.a, N);
    if (this.A % N === 0n) {
      // Pratikte imkânsız ama kontrol ucuz: A ≡ 0 gönderen bir istemci
      // sunucuyu S=0 hesaplamaya zorlar.
      throw new SrpError('bad_ephemeral', 'A ≡ 0 (mod N) -- yeniden deneyin');
    }
  }

  /** İlk mesaj: sunucuya kimlik ve A gider. Parola gitmez. */
  start() {
    return { identity: this.identity, A: toBuf(this.A).toString('base64') };
  }

  /**
   * Sunucunun (salt, B) yanıtını işler ve M1 kanıtını üretir.
   */
  respond({ saltB64, B: B_b64 }) {
    const salt = Buffer.from(saltB64, 'base64');
    const B = toBig(Buffer.from(B_b64, 'base64'));

    // B ≡ 0 (mod N) reddedilmeli: aksi halde sunucu S=0 dayatabilir ve
    // istemci parolayı bilmeyen biriyle ortak anahtara "varmış" olur.
    if (B % N === 0n) throw new SrpError('bad_server_ephemeral', 'sunucu B ≡ 0 (mod N) gönderdi');

    const u = toBig(H(pad(toBuf(this.A)), pad(toBuf(B))));
    if (u === 0n) throw new SrpError('bad_u', 'u = 0');

    const x = deriveX(this.password, salt);
    // S = (B - k*g^x)^(a + u*x) mod N
    let base = (B - ((k * modPow(g, x, N)) % N)) % N;
    if (base < 0n) base += N;               // JS'te % negatif kalabilir
    const S = modPow(base, this.a + (u * x), N);
    this.K = H(toBuf(S));

    this.M1 = H(
      xorBuf(H(toBuf(N)), H(pad(toBuf(g)))),
      H(Buffer.from(this.identity, 'utf8')),
      salt,
      pad(toBuf(this.A)),
      pad(toBuf(B)),
      this.K,
    );
    this._B = B;
    return { M1: this.M1.toString('base64') };
  }

  /**
   * Sunucunun M2 kanıtını doğrular. Bu adım atlanamaz: atlanırsa istemci,
   * parolayı bilmeyen sahte bir sunucuyla konuştuğunu asla anlamaz ve o
   * oturumda üretilen anahtarı kullanmaya devam eder.
   */
  verifyServer({ M2: M2_b64 }) {
    const expected = H(pad(toBuf(this.A)), this.M1, this.K);
    const given = Buffer.from(M2_b64, 'base64');
    if (given.length !== expected.length || !crypto.timingSafeEqual(expected, given)) {
      throw new SrpError('server_auth_failed', 'sunucu kendini doğrulayamadı');
    }
    return { sessionKey: this.K };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sunucu
// ─────────────────────────────────────────────────────────────────────────────
class SrpServer {
  /**
   * @param {object} opts
   * @param {string} opts.identity
   * @param {string} opts.saltB64      kayıt sırasında saklanan salt
   * @param {string} opts.verifierB64  kayıt sırasında saklanan doğrulayıcı
   */
  constructor({ identity, saltB64, verifierB64 }) {
    this.identity = identity;
    this.salt = Buffer.from(saltB64, 'base64');
    this.v = toBig(Buffer.from(verifierB64, 'base64'));
    this.b = toBig(crypto.randomBytes(32));
    // B = (k*v + g^b) mod N
    this.B = ((k * this.v) + modPow(g, this.b, N)) % N;
  }

  /** İstemciye giden yanıt: salt ve B. */
  challenge() {
    return { saltB64: this.salt.toString('base64'), B: toBuf(this.B).toString('base64') };
  }

  /**
   * İstemcinin A ve M1'ini doğrular. Başarılıysa M2 döner.
   *
   * Başarısızlık HER ZAMAN aynı hatayla döner: hangi adımda takıldığını
   * söylemek, saldırgana "kullanıcı var ama parola yanlış" ile "kullanıcı yok"
   * ayrımını verir.
   */
  verify({ A: A_b64, M1: M1_b64 }) {
    const A = toBig(Buffer.from(A_b64, 'base64'));

    // A ≡ 0 (mod N) reddedilmeli. Kabul edilirse S = (A * v^u)^b = 0 olur ve
    // parolayı hiç bilmeyen bir istemci, sunucunun hesapladığı anahtarı
    // (sıfırın hash'i) tahmin ederek geçebilir. RFC 5054'ün en kritik maddesi.
    if (A % N === 0n) throw new SrpError('auth_failed', 'kimlik doğrulama başarısız');

    const u = toBig(H(pad(toBuf(A)), pad(toBuf(this.B))));
    if (u === 0n) throw new SrpError('auth_failed', 'kimlik doğrulama başarısız');

    // S = (A * v^u)^b mod N
    const S = modPow((A * modPow(this.v, u, N)) % N, this.b, N);
    const K = H(toBuf(S));

    const expectedM1 = H(
      xorBuf(H(toBuf(N)), H(pad(toBuf(g)))),
      H(Buffer.from(this.identity, 'utf8')),
      this.salt,
      pad(toBuf(A)),
      pad(toBuf(this.B)),
      K,
    );

    const givenM1 = Buffer.from(M1_b64, 'base64');
    if (givenM1.length !== expectedM1.length || !crypto.timingSafeEqual(expectedM1, givenM1)) {
      throw new SrpError('auth_failed', 'kimlik doğrulama başarısız');
    }

    return { M2: H(pad(toBuf(A)), expectedM1, K).toString('base64'), sessionKey: K };
  }
}

function xorBuf(a, b) {
  const out = Buffer.alloc(Math.min(a.length, b.length));
  for (let i = 0; i < out.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/**
 * Var olmayan bir kullanıcı için de gerçekçi görünen bir challenge üretir.
 *
 * Sunucu "böyle bir kullanıcı yok" diye erken dönerse, kayıt uçları ne kadar
 * dikkatli yazılırsa yazılsın giriş ucu bir kullanıcı numaralandırma oracle'ı
 * olur. Salt, kullanıcı adından deterministik olarak türetilir: aynı isim için
 * her seferinde aynı salt döner, farklı isimler için farklı -- rastgele üretmek,
 * iki denemede farklı salt görülmesiyle "bu kullanıcı yok" bilgisini sızdırırdı.
 */
function fakeCredentials(identity, serverSecret) {
  const salt = crypto.createHmac('sha256', serverSecret)
    .update(`srp-fake-salt:${identity}`).digest();
  // Doğrulayıcı da deterministik ama kimsenin bilmediği bir x'ten üretilir,
  // dolayısıyla hiçbir parola bu hesaba giriş yapamaz.
  const x = toBig(crypto.createHmac('sha256', serverSecret)
    .update(`srp-fake-x:${identity}`).digest()) % N;
  return {
    saltB64: salt.toString('base64'),
    verifierB64: toBuf(modPow(g, x, N)).toString('base64'),
  };
}

module.exports = {
  N, g, k, N_BYTES, PBKDF2_ITERATIONS, PBKDF2_DKLEN,
  SrpError, SrpClient, SrpServer,
  createVerifier, deriveX, fakeCredentials,
  _internal: { pad, toBuf, toBig, H, xorBuf },
};
