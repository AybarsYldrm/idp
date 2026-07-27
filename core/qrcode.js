'use strict';

const zlib = require('node:zlib');

// ============================================================================
// Sıfırdan QR Code üretici (ISO/IEC 18004) -- npm bağımlılığı yok (PNG deflate için
// sadece node:zlib). KAPSAM: BYTE modu, 1-9. versiyonlar, hata düzeltme seviyesi L
// (~%7 kurtarma -- ekranda gösterilen bir kod için yeterli; basılı/hasar görebilecek
// kullanım için M/Q/H gerekirdi ama bu da versiyon başına daha az veri kapasitesi
// demektir). V9-L byte kapasitesi ~230 bayt -- herhangi bir otpauth:// URI'si için
// fazlasıyla yeterli. 10-26. versiyonlar BİLEREK desteklenmiyor: spec bu aralıkta byte
// modu uzunluk alanını 8 yerine 16 bite çıkarıyor, bu karmaşıklığı/hata riskini gerçek
// kullanım ihtiyacı olmadan almanın anlamı yok.
//
// DÜRÜSTLÜK NOTU: Bu implementasyon dahili bir round-trip testiyle (encode edilen
// matristen kod çözüp orijinal baytları geri kurtarma) doğrulanmıştır (bkz.
// test/qrcode-demo.js) -- ama bu SADECE kendi encoder/decoder çiftimin tutarlı
// olduğunu kanıtlar, gerçek bir telefon kamerasıyla taranabilirliği DEĞİL. Üretime
// almadan önce gerçek bir authenticator uygulamasıyla taramayı test edin.
// ============================================================================

// ---- GF(256) aritmetiği (QR'ın kullandığı ilkel polinom: x^8 + x^4 + x^3 + x^2 + 1 = 0x11D) ----
const GF_EXP = new Array(512);
const GF_LOG = new Array(256);
(function initGaloisField() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11D;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

// Reed-Solomon üretici polinomu (derece = ecCount), katsayılar yüksekten alçağa.
function rsGeneratorPoly(ecCount) {
  let poly = [1];
  for (let i = 0; i < ecCount; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= gfMul(poly[j], 1);
      next[j + 1] ^= gfMul(poly[j], GF_EXP[i]);
    }
    poly = next;
  }
  return poly;
}

// Bir veri bloğu (byte dizisi) için Reed-Solomon hata düzeltme codeword'lerini üretir.
function rsEncode(dataBytes, ecCount) {
  const generator = rsGeneratorPoly(ecCount); // uzunluk ecCount+1, generator[0] HER ZAMAN 1 (monik)
  const remainder = new Array(ecCount).fill(0);
  for (const byte of dataBytes) {
    const factor = byte ^ remainder[0];
    remainder.shift();
    remainder.push(0);
    if (factor !== 0) {
      // generator[0]=1 örtük olarak zaten factor çıkarımıyla iptal edildiği için
      // SADECE generator[1..ecCount] (ecCount adet katsayı) uygulanır.
      for (let i = 0; i < ecCount; i++) {
        remainder[i] ^= gfMul(generator[i + 1], factor);
      }
    }
  }
  return remainder;
}

// ============================================================================
// Versiyon tabloları (1-10, EC seviyesi L). [totalCodewords, ecCodewordsPerBlock,
// block1Count, block1DataCw, block2Count, block2DataCw]. block2Count=0 ise tek grup.
// ============================================================================
const VERSION_TABLE_L = {
  1: {
    total: 26, ecPerBlock: 7, blocks: [[1, 19]],
  },
  2: {
    total: 44, ecPerBlock: 10, blocks: [[1, 34]],
  },
  3: {
    total: 70, ecPerBlock: 15, blocks: [[1, 55]],
  },
  4: {
    total: 100, ecPerBlock: 20, blocks: [[1, 80]],
  },
  5: {
    total: 134, ecPerBlock: 26, blocks: [[1, 108]],
  },
  6: {
    total: 172, ecPerBlock: 18, blocks: [[2, 68]],
  },
  7: {
    total: 196, ecPerBlock: 20, blocks: [[2, 78]],
  },
  8: {
    total: 242, ecPerBlock: 24, blocks: [[2, 97]],
  },
  9: {
    total: 292, ecPerBlock: 30, blocks: [[2, 116]],
  },
  10: {
    total: 346, ecPerBlock: 18, blocks: [[2, 68], [2, 69]],
  },
};

const ALIGNMENT_POSITIONS = {
  1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
  7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
};

// EC seviyesi format bitleri (L=01) -- format bilgisi kodlaması: 2 bit EC seviyesi +
// 3 bit mask no -> BCH(15,5) ile 15 bit'e genişletilir, sabit maske 0x5412 ile XOR'lanır.
const FORMAT_EC_BITS = { L: 0b01, M: 0b00, Q: 0b11, H: 0b10 };

function bchFormatBits(data15) {
  // BCH(15,5) üreteç polinomu 0b10100110111 (QR spec Annex C).
  let g = data15 << 10;
  const poly = 0b10100110111;
  for (let i = 14; i >= 10; i--) {
    if (g & (1 << i)) g ^= poly << (i - 10);
  }
  return ((data15 << 10) | g) ^ 0b101010000010010;
}

function pickVersion(byteLength) {
  for (let v = 1; v <= 9; v++) {
    const t = VERSION_TABLE_L[v];
    const totalDataCw = t.blocks.reduce((sum, [count, dataCw]) => sum + count * dataCw, 0);
    // BYTE modu overhead: versiyon 1-9 için 4 bit mod + 8 bit uzunluk göstergesi (versiyon
    // 10-26 spec gereği 16 bit uzunluk ister -- karmaşıklığı ve hata riskini azaltmak için
    // desteklenen aralığı BİLEREK 9'da sınırlıyoruz; V9-L kapasitesi (~230 bayt) zaten
    // herhangi bir otpauth:// URI'si için fazlasıyla yeterli).
    const overheadBits = 4 + 8;
    const capacityBytes = Math.floor((totalDataCw * 8 - overheadBits) / 8);
    if (byteLength <= capacityBytes) return v;
  }
  return null; // veri çok uzun -- otpauth:// URI'leri için pratikte olmaz
}

// ---- Bit tamponu ----
class BitBuffer {
  constructor() { this.bits = []; }
  put(value, length) {
    for (let i = length - 1; i >= 0; i--) this.bits.push((value >>> i) & 1);
  }
  toBytes() {
    const bytes = [];
    for (let i = 0; i < this.bits.length; i += 8) {
      let byte = 0;
      for (let j = 0; j < 8; j++) byte = (byte << 1) | (this.bits[i + j] || 0);
      bytes.push(byte);
    }
    return bytes;
  }
}

function buildDataCodewords(textBytes, version) {
  const t = VERSION_TABLE_L[version];
  const totalDataCw = t.blocks.reduce((sum, [count, dataCw]) => sum + count * dataCw, 0);

  const bb = new BitBuffer();
  bb.put(0b0100, 4); // byte modu göstergesi
  bb.put(textBytes.length, 8); // karakter sayısı (v1-9 için 8 bit)
  for (const byte of textBytes) bb.put(byte, 8);

  const terminatorLen = Math.min(4, totalDataCw * 8 - bb.bits.length);
  if (terminatorLen > 0) bb.put(0, terminatorLen);
  while (bb.bits.length % 8 !== 0) bb.bits.push(0);

  const padBytes = [0xEC, 0x11];
  let padIdx = 0;
  while (bb.bits.length / 8 < totalDataCw) {
    bb.put(padBytes[padIdx % 2], 8);
    padIdx++;
  }
  return bb.toBytes();
}

// Veri codeword'lerini bloklara böler, her blok için RS EC codeword'lerini üretir,
// sonra spec'in gerektirdiği şekilde INTERLEAVE eder (bloklar arası sırayla, byte-byte).
function interleaveBlocks(dataCodewords, version) {
  const t = VERSION_TABLE_L[version];
  const blocks = [];
  let offset = 0;
  for (const [count, dataCw] of t.blocks) {
    for (let i = 0; i < count; i++) {
      const data = dataCodewords.slice(offset, offset + dataCw);
      offset += dataCw;
      const ec = rsEncode(data, t.ecPerBlock);
      blocks.push({ data, ec });
    }
  }
  const maxDataLen = Math.max(...blocks.map((b) => b.data.length));
  const out = [];
  for (let i = 0; i < maxDataLen; i++) {
    for (const b of blocks) if (i < b.data.length) out.push(b.data[i]);
  }
  for (let i = 0; i < t.ecPerBlock; i++) {
    for (const b of blocks) out.push(b.ec[i]);
  }
  return out;
}

// ============================================================================
// Modül matrisi oluşturma
// ============================================================================
function moduleCount(version) { return version * 4 + 17; }

function createMatrix(version) {
  const n = moduleCount(version);
  const matrix = Array.from({ length: n }, () => new Array(n).fill(null)); // null = henüz atanmadı
  const isFunction = Array.from({ length: n }, () => new Array(n).fill(false));

  function setFn(r, c, val) {
    if (r < 0 || r >= n || c < 0 || c >= n) return;
    matrix[r][c] = val;
    isFunction[r][c] = true;
  }

  function placeFinder(r0, c0) {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const rr = r0 + r; const cc = c0 + c;
        if (rr < 0 || rr >= n || cc < 0 || cc >= n) continue;
        const isBorder = r === -1 || r === 7 || c === -1 || c === 7;
        const inRing = (r >= 0 && r <= 6 && (c === 0 || c === 6)) || (c >= 0 && c <= 6 && (r === 0 || r === 6));
        const inCore = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        setFn(rr, cc, !isBorder && (inRing || inCore));
      }
    }
  }
  placeFinder(0, 0);
  placeFinder(0, n - 7);
  placeFinder(n - 7, 0);

  // zamanlama desenleri
  for (let i = 8; i < n - 8; i++) {
    setFn(6, i, i % 2 === 0);
    setFn(i, 6, i % 2 === 0);
  }

  // hizalama desenleri
  const positions = ALIGNMENT_POSITIONS[version] || [];
  for (const r0 of positions) {
    for (const c0 of positions) {
      // finder köşeleriyle çakışanları atla
      if ((r0 === 6 && c0 === 6) || (r0 === 6 && c0 === n - 7) || (r0 === n - 7 && c0 === 6)) continue;
      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) {
          const dist = Math.max(Math.abs(r), Math.abs(c));
          setFn(r0 + r, c0 + c, dist !== 1);
        }
      }
    }
  }

  // karanlık modül (sabit)
  setFn(4 * version + 9, 8, true);

  // format bilgisi için yer ayır (asıl değerler sonra yazılacak) -- şimdilik false ile dolduruyoruz
  for (let i = 0; i < 9; i++) { if (i !== 6) { setFn(8, i, false); setFn(i, 8, false); } }
  for (let i = 0; i < 8; i++) { setFn(8, n - 1 - i, false); setFn(n - 1 - i, 8, false); }

  return { matrix, isFunction, n };
}

function placeFormatInfo(matrix, n, maskId) {
  const data5 = (FORMAT_EC_BITS.L << 3) | maskId;
  const bits15 = bchFormatBits(data5);
  const bit = (i) => (bits15 >>> i) & 1;

  // sol-üst kopya
  const col = [0, 1, 2, 3, 4, 5, 7, 8]; // 6. satır zamanlama deseni için atlanır
  for (let i = 0; i < 6; i++) matrix[i][8] = bit(i);
  matrix[7][8] = bit(6); matrix[8][8] = bit(7); matrix[8][7] = bit(8);
  for (let i = 9; i < 15; i++) matrix[8][14 - i] = bit(i);

  // sağ-üst + sol-alt kopya
  for (let i = 0; i < 8; i++) matrix[n - 1 - i][8] = bit(i);
  for (let i = 8; i < 15; i++) matrix[8][n - 15 + i] = bit(i);
}

function placeData(matrix, isFunction, n, codewords) {
  const bits = [];
  for (const byte of codewords) for (let i = 7; i >= 0; i--) bits.push((byte >>> i) & 1);
  let bitIdx = 0;
  let upward = true;

  for (let colPair = n - 1; colPair > 0; colPair -= 2) {
    if (colPair === 6) colPair = 5; // zamanlama sütununu atla
    for (let i = 0; i < n; i++) {
      const row = upward ? n - 1 - i : i;
      for (const col of [colPair, colPair - 1]) {
        if (!isFunction[row][col]) {
          matrix[row][col] = bitIdx < bits.length ? !!bits[bitIdx] : false;
          bitIdx++;
        }
      }
    }
    upward = !upward;
  }
}

function applyMask(matrix, isFunction, n, maskId) {
  const maskFn = [
    (r, c) => (r + c) % 2 === 0,
    (r, c) => r % 2 === 0,
    (r, c) => c % 3 === 0,
    (r, c) => (r + c) % 3 === 0,
    (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
    (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
    (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
    (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
  ][maskId];
  const out = matrix.map((row) => row.slice());
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (!isFunction[r][c] && maskFn(r, c)) out[r][c] = !out[r][c];
    }
  }
  return out;
}

function maskPenalty(m, n) {
  let penalty = 0;
  // kural 1: aynı renkte 5+ ardışık modül (satır+sütun)
  for (let r = 0; r < n; r++) {
    let run = 1;
    for (let c = 1; c < n; c++) {
      if (m[r][c] === m[r][c - 1]) { run++; } else { if (run >= 5) penalty += 3 + (run - 5); run = 1; }
    }
    if (run >= 5) penalty += 3 + (run - 5);
  }
  for (let c = 0; c < n; c++) {
    let run = 1;
    for (let r = 1; r < n; r++) {
      if (m[r][c] === m[r - 1][c]) { run++; } else { if (run >= 5) penalty += 3 + (run - 5); run = 1; }
    }
    if (run >= 5) penalty += 3 + (run - 5);
  }
  // kural 2: 2x2 aynı renk bloklar
  for (let r = 0; r < n - 1; r++) {
    for (let c = 0; c < n - 1; c++) {
      if (m[r][c] === m[r][c + 1] && m[r][c] === m[r + 1][c] && m[r][c] === m[r + 1][c + 1]) penalty += 3;
    }
  }
  // kural 3: bulucu-benzeri desen (1:1:3:1:1 oranı, çevresi 4 açık modül)
  const pattern1 = [true, false, true, true, true, false, true, false, false, false, false];
  const pattern2 = pattern1.slice().reverse();
  function matchesAt(arr, start, pat) {
    for (let i = 0; i < pat.length; i++) if (arr[start + i] !== pat[i]) return false;
    return true;
  }
  for (let r = 0; r < n; r++) {
    const row = m[r];
    for (let c = 0; c <= n - 11; c++) {
      if (matchesAt(row, c, pattern1) || matchesAt(row, c, pattern2)) penalty += 40;
    }
  }
  for (let c = 0; c < n; c++) {
    const col = m.map((row) => row[c]);
    for (let r = 0; r <= n - 11; r++) {
      if (matchesAt(col, r, pattern1) || matchesAt(col, r, pattern2)) penalty += 40;
    }
  }
  // kural 4: koyu modül oranı
  let dark = 0;
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (m[r][c]) dark++;
  const percent = (dark * 100) / (n * n);
  penalty += Math.floor(Math.abs(percent - 50) / 5) * 10;
  return penalty;
}

/** Verilen byte dizisini (BYTE modu) QR kod modül matrisine (boolean[][]) kodlar. */
function encodeToMatrix(textBytes) {
  const version = pickVersion(textBytes.length);
  if (!version) throw new Error(`qrcode: veri çok uzun (${textBytes.length} bayt) -- desteklenen azami versiyon 10-L`);

  const dataCw = buildDataCodewords(textBytes, version);
  const allCw = interleaveBlocks(dataCw, version);
  const { matrix, isFunction, n } = createMatrix(version);
  placeData(matrix, isFunction, n, allCw);

  let best = null;
  for (let maskId = 0; maskId < 8; maskId++) {
    const masked = applyMask(matrix, isFunction, n, maskId);
    const penalty = maskPenalty(masked, n);
    if (!best || penalty < best.penalty) best = { maskId, matrix: masked, penalty };
  }
  placeFormatInfo(best.matrix, n, best.maskId);
  return {
    matrix: best.matrix, size: n, version, maskId: best.maskId,
  };
}

// ============================================================================
// PNG render (1-bit paletli, sıkıştırılmamış filtre + zlib deflate) -- npm YOK.
// ============================================================================
function crc32(buf) {
  let c;
  const table = crc32.table || (crc32.table = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })());
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function pngChunk(type, data) {
  const typeBuf = Buffer.from(type, 'ascii');
  const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32BE(data.length, 0);
  const crcBuf = Buffer.alloc(4); crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
}

/** boolean[][] matrisini, her modülü `scale` piksele büyüterek PNG Buffer'a render eder. */
function matrixToPng(matrix, size, { scale = 8, margin = 4 } = {}) {
  const dim = (size + margin * 2) * scale;
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(dim, 0);
  ihdrData.writeUInt32BE(dim, 4);
  ihdrData[8] = 1; // bit depth
  ihdrData[9] = 0; // grayscale
  ihdrData[10] = 0; ihdrData[11] = 0; ihdrData[12] = 0;
  const ihdr = pngChunk('IHDR', ihdrData);

  const bytesPerRow = Math.ceil(dim / 8);
  const raw = Buffer.alloc((bytesPerRow + 1) * dim);
  for (let y = 0; y < dim; y++) {
    const rowStart = y * (bytesPerRow + 1);
    raw[rowStart] = 0; // filtre: None
    const moduleY = Math.floor(y / scale) - margin;
    for (let x = 0; x < dim; x++) {
      const moduleX = Math.floor(x / scale) - margin;
      const dark = moduleY >= 0 && moduleY < size && moduleX >= 0 && moduleX < size && matrix[moduleY][moduleX];
      if (!dark) { // beyaz = bit 1 (grayscale'de 1 = açık/beyaz)
        const byteIdx = rowStart + 1 + Math.floor(x / 8);
        raw[byteIdx] |= (0x80 >> (x % 8));
      }
    }
  }
  const idat = pngChunk('IDAT', zlib.deflateSync(raw));
  const iend = pngChunk('IEND', Buffer.alloc(0));
  return Buffer.concat([signature, ihdr, idat, iend]);
}

/** Kolaylık fonksiyonu: bir metni (ör. otpauth:// URI) doğrudan PNG Buffer'a kodlar. */
function textToPngBuffer(text, opts) {
  const bytes = [...Buffer.from(text, 'utf8')];
  const { matrix, size } = encodeToMatrix(bytes);
  return matrixToPng(matrix, size, opts);
}

module.exports = {
  encodeToMatrix, matrixToPng, textToPngBuffer, pickVersion, VERSION_TABLE_L,
};
