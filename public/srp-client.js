/* eslint-env browser */
'use strict';

// SRP-6a istemcisi — tarayıcı tarafı.
//
// Bu dosyanın tek işi: parolanın ASLA ağa çıkmaması. Kayıt sırasında doğrulayıcı
// burada üretilir, giriş sırasında kanıt burada hesaplanır; her iki durumda da
// sunucuya giden şey parolanın kendisi değildir.
//
// core/srp.js ile bit düzeyinde aynı hesabı yapmak zorundadır: aynı grup, aynı
// hash, aynı dolgu kuralı, aynı KDF. Herhangi biri ayrışırsa taraflar farklı
// anahtara varır ve bu "yanlış parola" gibi görünür -- gerçek sebebi bulmak
// çok zordur. Bu yüzden sabitler tek tek buraya kopyalanmıştır ve
// test/srp-parity-demo.js ikisinin aynı sonucu ürettiğini doğrular.
//
// Elle yazılmış kripto YOK: hash ve KDF Web Crypto'nun yerleşik uygulamasıdır.
// Yalnızca modüler üs alma BigInt ile yapılır, çünkü Web Crypto onu sunmaz.

(function (global) {
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

  const N = BigInt('0x' + N_HEX);
  const g = 2n;
  const N_BYTES = 256;

  // ---- kodlama yardımcıları --------------------------------------------------------------
  function hexToBytes(hex) {
    if (hex.length % 2) hex = '0' + hex;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  function bytesToHex(bytes) {
    let s = '';
    for (const b of bytes) s += b.toString(16).padStart(2, '0');
    return s;
  }
  function toBytes(bigint) { return hexToBytes(bigint.toString(16)); }
  function toBig(bytes) { return BigInt('0x' + (bytesToHex(bytes) || '00')); }
  function b64(bytes) { return btoa(String.fromCharCode.apply(null, Array.from(bytes))); }
  function unb64(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function concat(arrays) {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
  }

  /** RFC 5054 §2.6: hash'lenen grup elemanları |N| uzunluğuna sola dolgulanır. */
  function pad(bytes) {
    if (bytes.length >= N_BYTES) return bytes;
    const out = new Uint8Array(N_BYTES);
    out.set(bytes, N_BYTES - bytes.length);
    return out;
  }

  async function H() {
    const parts = Array.prototype.slice.call(arguments).map(function (p) {
      return typeof p === 'string' ? new TextEncoder().encode(p) : p;
    });
    const digest = await crypto.subtle.digest('SHA-256', concat(parts));
    return new Uint8Array(digest);
  }

  function xorBytes(a, b) {
    const n = Math.min(a.length, b.length);
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  // ---- modüler üs alma -------------------------------------------------------------------
  // Web Crypto modPow sunmaz, dolayısıyla BigInt ile yapılır. Sabit zamanlı
  // DEĞİLDİR; istemci tarafında sırrı bilen zaten kullanıcının kendi cihazıdır,
  // dolayısıyla buradaki yan kanal sunucu tarafındaki kadar anlamlı değil --
  // ama farkında olarak yazıldığı için not düşülüyor.
  function modPow(base, exp, mod) {
    if (mod === 1n) return 0n;
    let result = 1n;
    base = ((base % mod) + mod) % mod;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      exp >>= 1n;
      base = (base * base) % mod;
    }
    return result;
  }

  let kCached = null;
  async function getK() {
    if (!kCached) kCached = toBig(await H(pad(toBytes(N)), pad(toBytes(g))));
    return kCached;
  }

  // Sunucudaki core/srp.js ile AYNI olmak zorunda: aynı algoritma, aynı tur
  // sayısı, aynı çıktı uzunluğu. Biri değişirse taraflar farklı x'e varır ve
  // belirti "parola yanlış" olur.
  const PBKDF2_ITERATIONS = 600000;
  const PBKDF2_DKLEN = 32;

  /**
   * x = PBKDF2-HMAC-SHA256(parola, salt, 600000).
   *
   * Web Crypto'nun yerleşik uygulaması kullanılır -- tarayıcıya elle yazılmış
   * bir KDF göndermemek, bu dosyadaki en önemli tasarım kararıdır.
   */
  async function deriveX(password, salt) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'],
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      keyMaterial, PBKDF2_DKLEN * 8,
    );
    return toBig(new Uint8Array(bits)) % N;
  }

  class SrpClient {
    constructor(options) {
      this.identity = options.identity;
      this.password = options.password;
      const a = new Uint8Array(32);
      crypto.getRandomValues(a);
      this.a = toBig(a);
      this.A = modPow(g, this.a, N);
    }

    start() {
      return { identity: this.identity, A: b64(toBytes(this.A)) };
    }

    async respond(challenge) {
      const salt = unb64(challenge.saltB64);
      const B = toBig(unb64(challenge.B));

      // Sunucunun B ≡ 0 göndermesi, ortak anahtarı sıfıra sabitleyip parolayı
      // bilmeden anlaşmaya varmak demektir.
      if (B % N === 0n) throw new Error('SRP: sunucu geçersiz B gönderdi');

      const k = await getK();
      const u = toBig(await H(pad(toBytes(this.A)), pad(toBytes(B))));
      if (u === 0n) throw new Error('SRP: u = 0');

      const x = await deriveX(this.password, salt);

      let base = (B - ((k * modPow(g, x, N)) % N)) % N;
      if (base < 0n) base += N;
      const S = modPow(base, this.a + (u * x), N);
      this.K = await H(toBytes(S));

      this.M1 = await H(
        xorBytes(await H(toBytes(N)), await H(pad(toBytes(g)))),
        await H(this.identity),
        salt,
        pad(toBytes(this.A)),
        pad(toBytes(B)),
        this.K,
      );
      return { M1: b64(this.M1) };
    }

    /** Sunucunun kanıtı. Doğrulanmazsa sahte bir sunucuyla konuşulduğu anlaşılmaz. */
    async verifyServer(response) {
      const expected = await H(pad(toBytes(this.A)), this.M1, this.K);
      const given = unb64(response.M2);
      if (given.length !== expected.length) throw new Error('SRP: sunucu doğrulanamadı');
      let diff = 0;
      for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ given[i];
      if (diff !== 0) throw new Error('SRP: sunucu doğrulanamadı');
      return { sessionKey: this.K };
    }
  }

  /** Kayıt: doğrulayıcı burada üretilir, parola cihazdan çıkmaz. */
  async function createVerifier(password, saltBytes) {
    const salt = saltBytes || crypto.getRandomValues(new Uint8Array(32));
    const x = await deriveX(password, salt);
    return { saltB64: b64(salt), verifier: b64(toBytes(modPow(g, x, N))) };
  }

  global.FitfakSrp = {
    SrpClient, createVerifier, N, g,
    _internal: { pad, toBytes, toBig, H, b64, unb64, modPow, deriveX, xorBytes },
  };
}(typeof window !== 'undefined' ? window : globalThis));
