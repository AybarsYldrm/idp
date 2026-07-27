'use strict';

// ---------------------------------------------------------------------------
// Sıfırdan Protobuf (wire format v3) encoder/decoder.
// npm bağımlılığı yok. Mesaj şemaları .proto dosyası yerine düz JS obje
// olarak tanımlanır.
// ---------------------------------------------------------------------------

const WIRE_VARINT = 0;
const WIRE_64BIT = 1;
const WIRE_LEN = 2;
const WIRE_32BIT = 5;

const VARINT_TYPES = new Set([
  'int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64', 'bool', 'enum',
]);
const FIXED64_TYPES = new Set(['fixed64', 'sfixed64', 'double']);
const FIXED32_TYPES = new Set(['fixed32', 'sfixed32', 'float']);
const LEN_TYPES = new Set(['string', 'bytes', 'message']);

function wireTypeOf(type) {
  if (VARINT_TYPES.has(type)) return WIRE_VARINT;
  if (FIXED64_TYPES.has(type)) return WIRE_64BIT;
  if (FIXED32_TYPES.has(type)) return WIRE_32BIT;
  if (LEN_TYPES.has(type)) return WIRE_LEN;
  throw new Error(`protobuf: bilinmeyen alan tipi '${type}'`);
}

// ---- varint ----------------------------------------------------------------

function encodeVarint(value) {
  let n = typeof value === 'bigint' ? value : BigInt(Math.trunc(value));
  if (n < 0n) n &= 0xFFFFFFFFFFFFFFFFn; // proto: negatif varintler 10 byte'lık unsigned temsille yazılır
  const out = [];
  do {
    let byte = Number(n & 0x7Fn);
    n >>= 7n;
    if (n !== 0n) byte |= 0x80;
    out.push(byte);
  } while (n !== 0n);
  return Buffer.from(out);
}

function decodeVarint(buf, offset) {
  let result = 0n;
  let shift = 0n;
  let pos = offset;
  for (;;) {
    if (pos >= buf.length) throw new Error('protobuf: varint beklenmedik şekilde bitti');
    const b = buf[pos];
    result |= BigInt(b & 0x7F) << shift;
    pos += 1;
    if ((b & 0x80) === 0) break;
    shift += 7n;
  }
  return { value: result, next: pos };
}

function zigzagEncode(n) {
  const v = typeof n === 'bigint' ? n : BigInt(Math.trunc(n));
  return v >= 0n ? (v << 1n) : ((-v << 1n) - 1n);
}

function zigzagDecode(v) {
  return (v & 1n) ? -((v + 1n) >> 1n) : (v >> 1n);
}

// ---- skaler encode/decode ---------------------------------------------------

function encodeScalar(type, value) {
  switch (type) {
    case 'int32': case 'int64': case 'uint32': case 'uint64':
      return encodeVarint(value);
    case 'sint32': case 'sint64':
      return encodeVarint(zigzagEncode(value));
    case 'bool':
      return encodeVarint(value ? 1 : 0);
    case 'enum':
      return encodeVarint(Number(value) | 0);
    case 'fixed64': { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(value)); return b; }
    case 'sfixed64': { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(value)); return b; }
    case 'double': { const b = Buffer.alloc(8); b.writeDoubleLE(Number(value)); return b; }
    case 'fixed32': { const b = Buffer.alloc(4); b.writeUInt32LE(Number(value) >>> 0); return b; }
    case 'sfixed32': { const b = Buffer.alloc(4); b.writeInt32LE(Number(value) | 0); return b; }
    case 'float': { const b = Buffer.alloc(4); b.writeFloatLE(Number(value)); return b; }
    case 'string':
      return Buffer.from(String(value), 'utf8');
    case 'bytes':
      return Buffer.isBuffer(value) ? value : Buffer.from(value || []);
    default:
      throw new Error(`protobuf: encodeScalar desteklemiyor '${type}'`);
  }
}

function decodeVarintScalar(type, buf) {
  const { value } = decodeVarint(buf, 0);
  switch (type) {
    case 'int32': return Number(BigInt.asIntN(32, value));
    case 'int64': return BigInt.asIntN(64, value);
    case 'uint32': return Number(BigInt.asUintN(32, value));
    case 'uint64': return BigInt.asUintN(64, value);
    case 'sint32': return Number(zigzagDecode(value));
    case 'sint64': return zigzagDecode(value);
    case 'bool': return value !== 0n;
    case 'enum': return Number(value);
    default: throw new Error(`protobuf: decodeVarintScalar desteklemiyor '${type}'`);
  }
}

function decodeFixedScalar(type, buf) {
  switch (type) {
    case 'fixed64': return buf.readBigUInt64LE(0);
    case 'sfixed64': return buf.readBigInt64LE(0);
    case 'double': return buf.readDoubleLE(0);
    case 'fixed32': return buf.readUInt32LE(0);
    case 'sfixed32': return buf.readInt32LE(0);
    case 'float': return buf.readFloatLE(0);
    default: throw new Error(`protobuf: decodeFixedScalar desteklemiyor '${type}'`);
  }
}

// ---- mesaj encode ------------------------------------------------------------

function encodeMessage(schemas, typeName, obj) {
  const fields = schemas[typeName];
  if (!fields) throw new Error(`protobuf: şema bulunamadı '${typeName}'`);
  const chunks = [];

  for (const f of fields) {
    const value = obj ? obj[f.name] : undefined;
    if (value === undefined || value === null) continue;

    const wt = f.type === 'message' ? WIRE_LEN : wireTypeOf(f.type);

    if (f.repeated) {
      const arr = Array.isArray(value) ? value : [value];
      if (arr.length === 0) continue;

      if (f.type === 'message' || f.type === 'string' || f.type === 'bytes') {
        // her eleman ayrı length-delimited alan olarak yazılır
        for (const item of arr) {
          const payload = f.type === 'message'
            ? encodeMessage(schemas, f.msgType, item)
            : encodeScalar(f.type, item);
          chunks.push(encodeTag(f.no, WIRE_LEN), encodeVarint(payload.length), payload);
        }
      } else {
        // sayısal skalerler proto3'te varsayılan olarak "packed" yazılır
        const inner = arr.map((v) => encodeScalar(f.type, v));
        const packed = Buffer.concat(inner);
        chunks.push(encodeTag(f.no, WIRE_LEN), encodeVarint(packed.length), packed);
      }
      continue;
    }

    if (f.type === 'message') {
      const payload = encodeMessage(schemas, f.msgType, value);
      chunks.push(encodeTag(f.no, WIRE_LEN), encodeVarint(payload.length), payload);
    } else if (wt === WIRE_LEN) {
      const payload = encodeScalar(f.type, value);
      chunks.push(encodeTag(f.no, WIRE_LEN), encodeVarint(payload.length), payload);
    } else {
      chunks.push(encodeTag(f.no, wt), encodeScalar(f.type, value));
    }
  }

  return Buffer.concat(chunks);
}

function encodeTag(fieldNo, wireType) {
  return encodeVarint((fieldNo << 3) | wireType);
}

// ---- mesaj decode --------------------------------------------------------------

function decodeMessage(schemas, typeName, buf) {
  const fields = schemas[typeName];
  if (!fields) throw new Error(`protobuf: şema bulunamadı '${typeName}'`);
  const byNo = new Map(fields.map((f) => [f.no, f]));
  const out = {};

  let pos = 0;
  while (pos < buf.length) {
    const tagDec = decodeVarint(buf, pos);
    pos = tagDec.next;
    const tag = Number(tagDec.value);
    const fieldNo = tag >>> 3;
    const wireType = tag & 0x7;
    const f = byNo.get(fieldNo);

    let rawLen, payload;
    switch (wireType) {
      case WIRE_VARINT: {
        const v = decodeVarint(buf, pos);
        payload = buf.slice(pos, v.next);
        pos = v.next;
        break;
      }
      case WIRE_64BIT:
        payload = buf.slice(pos, pos + 8);
        pos += 8;
        break;
      case WIRE_32BIT:
        payload = buf.slice(pos, pos + 4);
        pos += 4;
        break;
      case WIRE_LEN: {
        const lenDec = decodeVarint(buf, pos);
        pos = lenDec.next;
        rawLen = Number(lenDec.value);
        payload = buf.slice(pos, pos + rawLen);
        pos += rawLen;
        break;
      }
      default:
        throw new Error(`protobuf: desteklenmeyen wire type ${wireType}`);
    }

    if (!f) continue; // bilinmeyen alan, proto3 semantiğiyle atla

    let value;
    if (f.type === 'message') {
      value = decodeMessage(schemas, f.msgType, payload);
    } else if (f.type === 'string') {
      value = payload.toString('utf8');
    } else if (f.type === 'bytes') {
      value = payload; // Ham Buffer olarak bırak, dosya akışı (File Stream) için kritik!
    } else if (VARINT_TYPES.has(f.type)) {
      if (f.repeated && wireType === WIRE_LEN) {
        // packed repeated varint okuma
        const items = [];
        let p = 0;
        while (p < payload.length) {
          const d = decodeVarint(payload, p);
          items.push(decodeVarintScalar(f.type, payload.slice(p, d.next)));
          p = d.next;
        }
        pushRepeated(out, f, items);
        continue;
      }
      value = decodeVarintScalar(f.type, payload);
    } else {
      // fixed32/fixed64/float/double
      if (f.repeated && wireType === WIRE_LEN) {
        const size = FIXED32_TYPES.has(f.type) ? 4 : 8;
        const items = [];
        for (let p = 0; p < payload.length; p += size) {
          items.push(decodeFixedScalar(f.type, payload.slice(p, p + size)));
        }
        pushRepeated(out, f, items);
        continue;
      }
      value = decodeFixedScalar(f.type, payload);
    }

    if (f.repeated) {
      pushRepeated(out, f, [value]);
    } else {
      out[f.name] = value;
    }
  }

  // repeated alanlar hiç gelmediyse boş dizi olarak kalsın
  for (const f of fields) {
    if (f.repeated && out[f.name] === undefined) out[f.name] = [];
  }

  return out;
}

function pushRepeated(out, f, items) {
  if (!out[f.name]) out[f.name] = [];
  out[f.name].push(...items);
}

module.exports = {
  encodeMessage,
  decodeMessage,
  encodeVarint,
  decodeVarint,
  WIRE_VARINT,
  WIRE_64BIT,
  WIRE_LEN,
  WIRE_32BIT,
};