'use strict';

const zlib = require('node:zlib');

// Kullanıcıdan gelen görsellerin güvenli hale getirilmesi.
//
// Bir profil fotoğrafı, kullanıcının sunucuya YÜKLEDİĞİ ve sunucunun BAŞKA
// kullanıcılara SERVİS ETTİĞİ bir dosyadır. Bu iki özellik bir arada, onu
// saldırı yüzeyi yapar. Dört ayrı tehdit var ve her biri farklı bir yerde
// durdurulmalı:
//
// 1. SIKIŞTIRMA BOMBASI. 10 KB'lık bir PNG, başlığında 60000x60000 yazabilir.
//    Bir çözücü bunu açmaya kalkarsa 14 GB piksel tamponu ayırmaya çalışır ve
//    süreç ölür. Savunma: BOYUTLARI, herhangi bir çözme işleminden ÖNCE
//    başlıktan okumak ve sınırı orada uygulamak. "Önce aç, sonra bak" bu
//    saldırının tam olarak beklediği sıradır.
//
// 2. ZIP BOMBASI. Boyutlar makul olsa bile IDAT verisi, beyan edilen piksel
//    sayısıyla açıklanamayacak kadar büyük açılabilir. Savunma: açılan veriyi
//    beyan edilen boyutlardan hesaplanan ÜST SINIRLA karşılaştırmak; fazlası
//    yalan demektir.
//
// 3. POLYGLOT / GÖMÜLÜ YÜK. Bir dosya hem geçerli PNG hem geçerli HTML olabilir;
//    tarayıcı içerik tipini "koklarsa" onu script olarak çalıştırır. Ayrıca
//    tEXt/iCCP/EXIF gibi yardımcı bölümler istenen her şeyi taşıyabilir (EXIF
//    ayrıca GPS konumu taşır -- gizlilik sorunu). Savunma: dosyayı YENİDEN
//    KURMAK, yalnızca görüntü için gereken bölümleri koruyarak. Kırpma değil,
//    beyaz liste.
//
// 4. SVG. Hiçbir koşulda kabul edilmiyor: SVG bir belge biçimidir, script
//    çalıştırabilir ve dış kaynak çekebilir. "Sadece görsel" diye kabul etmek,
//    kullanıcı tarafından yüklenen HTML'i aynı origin'de servis etmektir.

// Kullanıcının istediği üst sınır. Yeniden boyutlandırma YAPILMIYOR: daha
// büyük bir görseli küçültmek, tam da 1. maddedeki çözme işlemini yapmak
// demektir. Bunun yerine sınırı aşan dosya reddediliyor ve küçültme işi
// tarayıcıya (canvas) bırakılıyor -- orada patlarsa yalnızca kullanıcının
// kendi sekmesi etkilenir.
const MAX_DIMENSION = 256;

// Dosya boyutu sınırı. 256x256 bir avatar pratikte 30-60 KB'dır; 256 KB
// rahat bir tavan ve aynı zamanda bant genişliği/depolama sınırı.
const MAX_FILE_BYTES = 256 * 1024;

// Açılmış veri için üst sınır: 256*256 piksel * 4 kanal + satır başına 1 filtre
// baytı. Bunun üzerindeki her şey, beyan edilen boyutlarla tutarsızdır.
const MAX_INFLATED_BYTES = (MAX_DIMENSION * MAX_DIMENSION * 4) + MAX_DIMENSION + 1024;

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

// Korunacak PNG bölümleri. Beyaz liste, kara liste değil: yarın eklenecek yeni
// bir bölüm tipi otomatik olarak DIŞARIDA kalır.
//   IHDR başlık, PLTE palet, IDAT piksel verisi, IEND son,
//   tRNS şeffaflık (yardımcı ama görsel olarak gerekli)
const PNG_KEEP_CHUNKS = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS']);

class ImageRejected extends Error {
  constructor(reason, detail) {
    super(detail || reason);
    this.name = 'ImageRejected';
    this.code = 'image_rejected';
    this.reason = reason;
    this.httpStatus = 400;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PNG
// ─────────────────────────────────────────────────────────────────────────────
function parsePngChunks(buf) {
  const chunks = [];
  let offset = PNG_MAGIC.length;
  while (offset + 12 <= buf.length) {
    const length = buf.readUInt32BE(offset);
    // Uzunluk alanı 2^31-1'i aşamaz (PNG spec). Aşan bir değer, sonraki
    // aritmetiği taşırma yoluyla kandırma denemesidir.
    if (length > 0x7fffffff) throw new ImageRejected('malformed', 'PNG chunk uzunluğu geçersiz');
    const type = buf.toString('ascii', offset + 4, offset + 8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > buf.length) throw new ImageRejected('malformed', 'PNG chunk dosya sınırını aşıyor');
    chunks.push({ type, data: buf.subarray(dataStart, dataEnd) });
    offset = dataEnd + 4; // + CRC
    if (type === 'IEND') break;
  }
  return chunks;
}

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc & 1) ? ((crc >>> 1) ^ 0xedb88320) : (crc >>> 1);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function encodePngChunk(type, data) {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'ascii');
  data.copy(out, 8);
  const typeAndData = out.subarray(4, 8 + data.length);
  out.writeUInt32BE(crc32(typeAndData), 8 + data.length);
  return out;
}

function inspectPng(buf) {
  const chunks = parsePngChunks(buf);
  const ihdr = chunks.find((c) => c.type === 'IHDR');
  if (!ihdr || ihdr.data.length < 13) throw new ImageRejected('malformed', 'PNG IHDR yok');

  const width = ihdr.data.readUInt32BE(0);
  const height = ihdr.data.readUInt32BE(4);
  const bitDepth = ihdr.data[8];
  const colorType = ihdr.data[9];
  const interlace = ihdr.data[12];

  if (width === 0 || height === 0) throw new ImageRejected('malformed', 'PNG boyutu sıfır');

  // BOYUT KONTROLÜ, ÇÖZMEDEN ÖNCE. Sıralama burada güvenliğin kendisidir.
  if (width > MAX_DIMENSION || height > MAX_DIMENSION) {
    throw new ImageRejected('too_large',
      `Görsel en fazla ${MAX_DIMENSION}x${MAX_DIMENSION} olabilir (gelen: ${width}x${height})`);
  }

  // Interlace (Adam7) çözücüyü daha karmaşık bir yola sokar ve avatarlar için
  // hiçbir faydası yok; kabul etmemek saldırı yüzeyini gereksiz yere büyütmemek.
  if (interlace !== 0) throw new ImageRejected('unsupported', 'Interlaced PNG kabul edilmiyor');

  return { format: 'png', width, height, bitDepth, colorType, chunks };
}

/**
 * IDAT verisini SINIRLI olarak açar. Amaç görüntüyü çözmek değil, beyan edilen
 * boyutlarla tutarlı olduğunu görmek: sınırı aşan bir akış, başlığında yazandan
 * çok daha fazlasını taşıyor demektir.
 */
function assertPngNotABomb(chunks, { width, height, bitDepth, colorType }) {
  const idat = Buffer.concat(chunks.filter((c) => c.type === 'IDAT').map((c) => c.data));
  if (idat.length === 0) throw new ImageRejected('malformed', 'PNG IDAT yok');

  const channels = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[colorType];
  if (!channels) throw new ImageRejected('unsupported', `PNG renk tipi ${colorType} desteklenmiyor`);

  const bytesPerPixel = Math.ceil((channels * bitDepth) / 8);
  const expected = height * (1 + (width * bytesPerPixel));
  const limit = Math.min(MAX_INFLATED_BYTES, expected + 1024);

  let inflated;
  try {
    // maxOutputLength, zlib'in kendi sınırı: sınır aşıldığında akış durur ve
    // hata döner -- yani belleği önce doldurup sonra fark etmiyoruz.
    inflated = zlib.inflateSync(idat, { maxOutputLength: limit });
  } catch (err) {
    if (/maxOutputLength|buffer/i.test(err.message)) {
      throw new ImageRejected('bomb',
        'Görsel, beyan ettiği boyutlarla açıklanamayacak kadar çok veri içeriyor');
    }
    throw new ImageRejected('malformed', 'PNG piksel verisi çözülemedi');
  }

  if (inflated.length > expected + 1024) {
    throw new ImageRejected('bomb', 'Açılan veri beyan edilen boyutlarla tutarsız');
  }
}

/**
 * PNG'yi yalnızca gerekli bölümlerden yeniden kurar.
 *
 * Bu bir "temizleme" değil, YENİDEN İNŞA: çıktı, beyaz listedeki bölümler
 * dışında girdiden hiçbir şey taşımaz. Gömülü HTML, EXIF, renk profili,
 * yorum alanı -- hepsi yeni dosyada yoktur çünkü kopyalanmamıştır.
 */
function rebuildPng(chunks) {
  const kept = chunks.filter((c) => PNG_KEEP_CHUNKS.has(c.type));
  if (kept[0]?.type !== 'IHDR') throw new ImageRejected('malformed', 'PNG IHDR ilk bölüm değil');
  if (!kept.some((c) => c.type === 'IEND')) kept.push({ type: 'IEND', data: Buffer.alloc(0) });
  return Buffer.concat([PNG_MAGIC, ...kept.map((c) => encodePngChunk(c.type, c.data))]);
}

// ─────────────────────────────────────────────────────────────────────────────
// JPEG
// ─────────────────────────────────────────────────────────────────────────────
// SOFn bölümleri görüntü boyutlarını taşır. SOF4/8/12 mevcut değildir (DHT/JPG/DAC).
const JPEG_SOF_MARKERS = new Set([
  0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf,
]);

function inspectJpeg(buf) {
  if (buf[0] !== 0xff || buf[1] !== 0xd8) throw new ImageRejected('malformed', 'JPEG SOI yok');

  let offset = 2;
  const segments = [];
  while (offset + 4 <= buf.length) {
    if (buf[offset] !== 0xff) throw new ImageRejected('malformed', 'JPEG marker beklendi');
    const marker = buf[offset + 1];
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      offset += 2; continue;
    }
    if (marker === 0xda) { // SOS -- taranmış veri buradan sonra
      segments.push({ marker, start: offset, data: buf.subarray(offset) });
      break;
    }
    const length = buf.readUInt16BE(offset + 2);
    if (length < 2 || offset + 2 + length > buf.length) {
      throw new ImageRejected('malformed', 'JPEG segment uzunluğu geçersiz');
    }
    segments.push({ marker, start: offset, data: buf.subarray(offset, offset + 2 + length) });

    if (JPEG_SOF_MARKERS.has(marker)) {
      const height = buf.readUInt16BE(offset + 5);
      const width = buf.readUInt16BE(offset + 7);
      if (width === 0 || height === 0) throw new ImageRejected('malformed', 'JPEG boyutu sıfır');
      if (width > MAX_DIMENSION || height > MAX_DIMENSION) {
        throw new ImageRejected('too_large',
          `Görsel en fazla ${MAX_DIMENSION}x${MAX_DIMENSION} olabilir (gelen: ${width}x${height})`);
      }
      return { format: 'jpeg', width, height, segments, buf };
    }
    offset += 2 + length;
  }
  throw new ImageRejected('malformed', 'JPEG boyut bilgisi (SOF) bulunamadı');
}

/**
 * JPEG'i APPn ve COM segmentleri olmadan yeniden kurar.
 *
 * APP1 = EXIF: gömülü küçük resim, üretici bilgisi ve GPS KONUMU taşır.
 * Kullanıcının profil fotoğrafıyla birlikte ev adresini yayınlamak, kimsenin
 * kastetmediği ama sıkça olan bir sızıntıdır.
 */
function rebuildJpeg({ segments }) {
  const parts = [Buffer.from([0xff, 0xd8])];
  for (const seg of segments) {
    const isApp = seg.marker >= 0xe0 && seg.marker <= 0xef;
    const isComment = seg.marker === 0xfe;
    if (isApp || isComment) continue;
    parts.push(seg.data);
  }
  return Buffer.concat(parts);
}

// ─────────────────────────────────────────────────────────────────────────────
// Genel giriş noktası
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Yüklenen baytları doğrular ve güvenli bir biçimde yeniden kurar.
 *
 * İSTEMCİNİN BEYANINA HİÇ BAKILMAZ: content-type başlığı da, dosya adı da,
 * istemcinin "bu 256x256" demesi de. Hepsi saldırganın kontrolündedir. Karar
 * yalnızca baytlardan verilir.
 *
 * @returns {{ format, width, height, bytes, contentType }}
 */
function sanitizeAvatar(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);

  if (buf.length === 0) throw new ImageRejected('empty', 'Boş dosya');
  if (buf.length > MAX_FILE_BYTES) {
    throw new ImageRejected('too_large',
      `Dosya en fazla ${Math.floor(MAX_FILE_BYTES / 1024)} KB olabilir`);
  }

  // Sihirli baytlar. SVG, GIF, WEBP, BMP ve diğer her şey buradan geçemez --
  // beyaz liste olduğu için yeni bir biçim eklemek bilinçli bir karar gerektirir.
  if (buf.subarray(0, 8).equals(PNG_MAGIC)) {
    const info = inspectPng(buf);
    assertPngNotABomb(info.chunks, info);
    return {
      format: 'png',
      width: info.width,
      height: info.height,
      bytes: rebuildPng(info.chunks),
      contentType: 'image/png',
    };
  }

  if (buf[0] === 0xff && buf[1] === 0xd8) {
    const info = inspectJpeg(buf);
    return {
      format: 'jpeg',
      width: info.width,
      height: info.height,
      bytes: rebuildJpeg(info),
      contentType: 'image/jpeg',
    };
  }

  throw new ImageRejected('unsupported', 'Yalnızca PNG ve JPEG kabul ediliyor');
}

module.exports = {
  sanitizeAvatar, ImageRejected,
  MAX_DIMENSION, MAX_FILE_BYTES, MAX_INFLATED_BYTES,
  // test ve ileride yeniden kullanım için
  inspectPng, inspectJpeg, rebuildPng, rebuildJpeg, crc32,
};
