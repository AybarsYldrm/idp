'use strict';

// Minimal, amaca özel CBOR (RFC 8949) kodlayıcı/çözücü.
//
// NEDEN ELLE YAZILDI: WebAuthn attestationObject ve COSE_Key yapıları CBOR ile kodlanır.
// Genel amaçlı bir npm 'cbor' paketi kullanmak yerine -- talep edildiği gibi harici
// bağımlılığı sıfırlayıp node:crypto ile "sıfırdan" doğrulama yapabilmek için -- burada
// SADECE WebAuthn'ın kullandığı alt küme uygulanıyor:
//   - unsigned/negative integer (major type 0/1)
//   - byte string / text string (major type 2/3)
//   - array / map (major type 4/5)
//   - false/true/null/undefined (major type 7, simple values 20/21/22/23)
//
// Desteklenmeyenler (WebAuthn'da fiilen kullanılmadığı için): kesirli (float) sayılar,
// belirsiz uzunluklu (indefinite-length) kodlama, etiketler (major type 6) sadece
// atlanarak (skip) desteklenir. Bunlardan biriyle karşılaşılırsa hata fırlatılır --
// sessizce yanlış sonuç üretmek yerine.

function decode(buffer) {
  const state = { buf: buffer, offset: 0 };
  const value = decodeValue(state);
  return { value, bytesRead: state.offset };
}

function decodeValue(state) {
  const initial = state.buf[state.offset++];
  if (initial === undefined) throw new Error('cbor.decode: buffer beklenenden erken bitti');
  const majorType = initial >> 5;
  const addlInfo = initial & 0x1f;

  switch (majorType) {
    case 0: // unsigned int
      return readUint(state, addlInfo);
    case 1: { // negative int: -(1 + n)
      const n = readUint(state, addlInfo);
      return typeof n === 'bigint' ? -1n - n : -1 - n;
    }
    case 2: { // byte string
      const len = Number(readUint(state, addlInfo));
      const bytes = state.buf.subarray(state.offset, state.offset + len);
      state.offset += len;
      return Buffer.from(bytes);
    }
    case 3: { // text string
      const len = Number(readUint(state, addlInfo));
      const str = state.buf.toString('utf8', state.offset, state.offset + len);
      state.offset += len;
      return str;
    }
    case 4: { // array
      const len = Number(readUint(state, addlInfo));
      const arr = new Array(len);
      for (let i = 0; i < len; i++) arr[i] = decodeValue(state);
      return arr;
    }
    case 5: { // map -- WebAuthn/COSE keys mix integer ve string anahtarlar kullanır,
              // bu yüzden düz JS objesi değil Map döndürüyoruz (sayısal anahtarlar
              // JS objelerinde string'e çevrilip COSE etiketleriyle çakışabilir).
      const len = Number(readUint(state, addlInfo));
      const map = new Map();
      for (let i = 0; i < len; i++) {
        const k = decodeValue(state);
        const v = decodeValue(state);
        map.set(k, v);
      }
      return map;
    }
    case 6: { // tag -- etiket numarasını atla, içindeki değeri döndür
      readUint(state, addlInfo);
      return decodeValue(state);
    }
    case 7: {
      if (addlInfo === 20) return false;
      if (addlInfo === 21) return true;
      if (addlInfo === 22) return null;
      if (addlInfo === 23) return undefined;
      throw new Error(`cbor.decode: desteklenmeyen simple/float değer (addlInfo=${addlInfo})`);
    }
    default:
      throw new Error(`cbor.decode: geçersiz major type ${majorType}`);
  }
}

function readUint(state, addlInfo) {
  if (addlInfo < 24) return addlInfo;
  if (addlInfo === 24) { const v = state.buf.readUInt8(state.offset); state.offset += 1; return v; }
  if (addlInfo === 25) { const v = state.buf.readUInt16BE(state.offset); state.offset += 2; return v; }
  if (addlInfo === 26) { const v = state.buf.readUInt32BE(state.offset); state.offset += 4; return v; }
  if (addlInfo === 27) { const v = state.buf.readBigUInt64BE(state.offset); state.offset += 8; return v; }
  throw new Error('cbor.decode: belirsiz uzunluklu (indefinite-length) kodlama desteklenmiyor');
}

// ---- Encoder (üretimde çalışma zamanında gerekmiyor; test harness'inde sahte
// authenticator/COSE key kurgulamak için kullanılıyor) ----

function encode(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (value === undefined) return Buffer.from([0xf7]);
  if (typeof value === 'boolean') return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === 'number' || typeof value === 'bigint') return encodeInt(value);
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return encodeHead(2, value.length, Buffer.from(value));
  }
  if (typeof value === 'string') {
    const strBuf = Buffer.from(value, 'utf8');
    return encodeHead(3, strBuf.length, strBuf);
  }
  if (Array.isArray(value)) {
    const parts = [encodeHead(4, value.length)];
    for (const item of value) parts.push(encode(item));
    return Buffer.concat(parts);
  }
  if (value instanceof Map) {
    const parts = [encodeHead(5, value.size)];
    for (const [k, v] of value) { parts.push(encode(k)); parts.push(encode(v)); }
    return Buffer.concat(parts);
  }
  throw new Error(`cbor.encode: desteklenmeyen tip ${typeof value}`);
}

function encodeInt(n) {
  if (typeof n === 'bigint') {
    return n >= 0n ? encodeHead(0, n) : encodeHead(1, -1n - n);
  }
  return n >= 0 ? encodeHead(0, n) : encodeHead(1, -1 - n);
}

function encodeHead(majorType, len, payload) {
  const mt = majorType << 5;
  const n = typeof len === 'bigint' ? len : BigInt(len);
  let head;
  if (n < 24n) head = Buffer.from([mt | Number(n)]);
  else if (n <= 0xffn) head = Buffer.from([mt | 24, Number(n)]);
  else if (n <= 0xffffn) { head = Buffer.alloc(3); head[0] = mt | 25; head.writeUInt16BE(Number(n), 1); }
  else if (n <= 0xffffffffn) { head = Buffer.alloc(5); head[0] = mt | 26; head.writeUInt32BE(Number(n), 1); }
  else { head = Buffer.alloc(9); head[0] = mt | 27; head.writeBigUInt64BE(n, 1); }
  return payload ? Buffer.concat([head, payload]) : head;
}

module.exports = { decode, encode };
