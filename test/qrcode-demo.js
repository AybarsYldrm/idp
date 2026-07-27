'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const qrcode = require('../core/qrcode');

// ----------------------------------------------------------------------------
// Kendi GF(256)/Reed-Solomon matematiğini core/qrcode.js'ten YENİDEN KULLANMAK yerine
// (ki bu, encoder'daki bir hatayı decoder'a da taşıyıp gizleyebilirdi) burada BAĞIMSIZ,
// küçük bir GF/syndrome hesaplayıcı yazıyoruz -- amaç: encoder'ın ürettiği codeword'lerin
// GERÇEKTEN geçerli bir Reed-Solomon kod sözcüğü olduğunu (yani orijinal veri +
// üreteç-polinomuna göre hesaplanmış EC baytlarının sendromlarının SIFIR olduğunu)
// tamamen ayrı bir hesaplamayla teyit etmek.
// ----------------------------------------------------------------------------
const GF_EXP = new Array(512);
const GF_LOG = new Array(256);
(function initGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) { GF_EXP[i] = x; GF_LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11D; }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
}());
function gfMul(a, b) { if (a === 0 || b === 0) return 0; return GF_EXP[GF_LOG[a] + GF_LOG[b]]; }
function gfPow(base, exp) { return GF_EXP[(GF_LOG[base] * exp) % 255]; }

// codeword polinomunu alpha^i noktalarında değerlendirir (Horner yöntemi) -- hepsi 0 ise hatasız.
function computeSyndromes(codewords, ecCount) {
  const syndromes = [];
  for (let i = 0; i < ecCount; i++) {
    let result = 0;
    const point = gfPow(2, i);
    for (const cw of codewords) result = gfMul(result, point) ^ cw;
    syndromes.push(result);
  }
  return syndromes;
}

function readFormatMaskId(matrix) {
  // Sol-üst format bilgisi kopyasından 5 veri bitini (BCH düzeltmesi olmadan, gürültü
  // olmadığı için gerekmiyor) doğrudan okuyoruz -- bkz. core/qrcode.js placeFormatInfo.
  const bits = [];
  for (let i = 0; i < 6; i++) bits.push(matrix[i][8]);
  bits.push(matrix[7][8]);
  // format değeri BCH(15,5) ile 15 bite genişletilmiş + 0x5412 ile XOR'lanmış olarak
  // yazılmıştı; ilk 5 bit EC-seviyesi(2)+mask(3) verisidir ama maskelenmiş halde. Aynı
  // sabit maskeyle geri XOR'layarak ham 15-bit değeri, oradan da üst 5 biti çıkarırız.
  let raw15 = 0;
  for (let i = 0; i < 6; i++) raw15 |= (matrix[i][8] ? 1 : 0) << i;
  raw15 |= (matrix[7][8] ? 1 : 0) << 6;
  raw15 |= (matrix[8][8] ? 1 : 0) << 7;
  raw15 |= (matrix[8][7] ? 1 : 0) << 8;
  const n = matrix.length;
  for (let i = 9; i < 15; i++) raw15 |= (matrix[8][14 - i] ? 1 : 0) << i;
  const unmasked = raw15 ^ 0b101010000010010;
  const data5 = (unmasked >>> 10) & 0b11111;
  return data5 & 0b111; // alt 3 bit = mask id (üst 2 bit EC seviyesi)
}

const MASK_FNS = [
  (r, c) => (r + c) % 2 === 0,
  (r, c) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

function rebuildIsFunctionMask(version, n) {
  // core/qrcode.js'teki createMatrix ile AYNI fonksiyon-modül haritasını, encode edilmiş
  // matrisi tekrar üretmeden, sadece hangi hücrelerin "veri" olduğunu bulmak için
  // yeniden inşa ediyoruz (kopya kod -- kasıtlı: encoder'daki olası bir hatayı burada
  // TEKRARLAMAMAK için tamamen encoder'ın kendi iç fonksiyonlarını kullanmıyoruz,
  // sadece halka açık `encodeToMatrix` çıktısını + versiyon bilgisini kullanıyoruz).
  const isFn = Array.from({ length: n }, () => new Array(n).fill(false));
  function markFinder(r0, c0) {
    for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) {
      const rr = r0 + r; const cc = c0 + c;
      if (rr < 0 || rr >= n || cc < 0 || cc >= n) continue;
      isFn[rr][cc] = true;
    }
  }
  markFinder(0, 0); markFinder(0, n - 7); markFinder(n - 7, 0);
  for (let i = 8; i < n - 8; i++) { isFn[6][i] = true; isFn[i][6] = true; }
  const ALIGN = { 1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50] };
  const positions = ALIGN[version] || [];
  for (const r0 of positions) for (const c0 of positions) {
    if ((r0 === 6 && c0 === 6) || (r0 === 6 && c0 === n - 7) || (r0 === n - 7 && c0 === 6)) continue;
    for (let r = -2; r <= 2; r++) for (let c = -2; c <= 2; c++) {
      const rr = r0 + r; const cc = c0 + c;
      if (rr >= 0 && rr < n && cc >= 0 && cc < n) isFn[rr][cc] = true;
    }
  }
  isFn[4 * version + 9][8] = true;
  for (let i = 0; i < 9; i++) { if (i !== 6) { isFn[8][i] = true; isFn[i][8] = true; } }
  for (let i = 0; i < 8; i++) { isFn[8][n - 1 - i] = true; isFn[n - 1 - i][8] = true; }
  return isFn;
}

function extractCodewords(matrix, version) {
  const n = matrix.length;
  const isFn = rebuildIsFunctionMask(version, n);
  const maskId = readFormatMaskId(matrix);
  const maskFn = MASK_FNS[maskId];

  const bits = [];
  let upward = true;
  for (let colPair = n - 1; colPair > 0; colPair -= 2) {
    if (colPair === 6) colPair = 5;
    for (let i = 0; i < n; i++) {
      const row = upward ? n - 1 - i : i;
      for (const col of [colPair, colPair - 1]) {
        if (!isFn[row][col]) {
          const raw = matrix[row][col];
          const unmasked = maskFn(row, col) ? !raw : raw;
          bits.push(unmasked ? 1 : 0);
        }
      }
    }
    upward = !upward;
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    bytes.push(b);
  }
  return bytes;
}

function deinterleaveAndVerify(codewords, version) {
  const { VERSION_TABLE_L } = qrcode;
  const t = VERSION_TABLE_L[version];
  const blockDataLens = [];
  for (const [count, dataCw] of t.blocks) for (let i = 0; i < count; i++) blockDataLens.push(dataCw);
  const numBlocks = blockDataLens.length;
  const maxDataLen = Math.max(...blockDataLens);

  const blockData = blockDataLens.map(() => []);
  let pos = 0;
  for (let i = 0; i < maxDataLen; i++) {
    for (let b = 0; b < numBlocks; b++) if (i < blockDataLens[b]) blockData[b].push(codewords[pos++]);
  }
  const blockEc = blockDataLens.map(() => []);
  for (let i = 0; i < t.ecPerBlock; i++) for (let b = 0; b < numBlocks; b++) blockEc[b].push(codewords[pos++]);

  const recoveredData = [];
  for (let b = 0; b < numBlocks; b++) {
    const full = [...blockData[b], ...blockEc[b]];
    const syndromes = computeSyndromes(full, t.ecPerBlock);
    assert.ok(syndromes.every((s) => s === 0), `V${version} blok ${b}: Reed-Solomon sendromları sıfır değil -- codeword'ler geçersiz! syndromes=${syndromes}`);
    recoveredData.push(...blockData[b]);
  }
  return recoveredData;
}

function decodeBytesFromDataCodewords(dataCw) {
  // ilk 4 bit mod (0100=byte), sonraki 8 bit uzunluk, sonra o kadar bayt.
  const modeAndLen = (dataCw[0] << 8) | dataCw[1];
  const mode = (modeAndLen >>> 12) & 0xF;
  assert.strictEqual(mode, 0b0100, 'mod göstergesi BYTE (0100) olmalı');
  const len = (modeAndLen >>> 4) & 0xFF;
  const bytes = [];
  // 4 bit mod + 8 bit uzunluk = 12 bit kaydırma ile devam eden nibble akışından baytları çek
  let bitPos = 12;
  const allBits = [];
  for (const cw of dataCw) for (let i = 7; i >= 0; i--) allBits.push((cw >>> i) & 1);
  for (let i = 0; i < len; i++) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | allBits[bitPos++];
    bytes.push(byte);
  }
  return { bytes, len };
}

function main() {
  const testStrings = [
    'A', // V1 sınırı
    'otpauth://totp/test:user?secret=JBSWY3DPEHPK3PXP&issuer=test', // tipik kısa otpauth
    'otpauth://totp/fitfak%20kimlik:abuzer.yildirim%40fitfak.net?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=fitfak%20kimlik&algorithm=SHA1&digits=6&period=30', // uzun, gerçekçi otpauth
    'x'.repeat(15), // V1 sınırına yakın
    'x'.repeat(30), // V2
    'x'.repeat(80), // V4-5 civarı
    'x'.repeat(150), // V7-8 civarı
    'x'.repeat(225), // V9 sınırına yakın (desteklenen en büyük versiyon)
  ];

  for (const text of testStrings) {
    const inputBytes = [...Buffer.from(text, 'utf8')];
    const { matrix, version } = qrcode.encodeToMatrix(inputBytes);

    const codewords = extractCodewords(matrix, version);
    const dataCw = deinterleaveAndVerify(codewords, version);
    const { bytes: recoveredBytes, len } = decodeBytesFromDataCodewords(dataCw);

    assert.strictEqual(len, inputBytes.length, `V${version}: uzunluk alanı yanlış çözüldü`);
    assert.deepStrictEqual(recoveredBytes, inputBytes, `V${version}: geri kurtarılan baytlar orijinalle eşleşmiyor`);
    console.log(`qrcode: V${version} ("${text.length > 30 ? text.slice(0, 27) + '...' : text}", ${inputBytes.length} bayt) -- kodla + Reed-Solomon sendromları sıfır + orijinal baytlar TAM eşleşti`);
  }

  // gerçek bir PNG üret ve dosyaya yaz (manuel/görsel doğrulama için) -- test/qr-sample.png
  const samplePng = qrcode.textToPngBuffer('otpauth://totp/fitfak%20kimlik:demo?secret=JBSWY3DPEHPK3PXP&issuer=fitfak%20kimlik');
  const outPath = path.join(__dirname, '..', '.tmp-qr-sample.png');
  fs.writeFileSync(outPath, samplePng);
  assert.ok(samplePng.slice(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])), 'PNG imzası geçersiz');
  console.log(`qrcode: örnek PNG üretildi (${samplePng.length} bayt) -- ${outPath}`);

  console.log('\nALL QRCODE CHECKS PASSED (V1-V9, Reed-Solomon sendrom doğrulaması + PNG üretimi)');
}

main();
