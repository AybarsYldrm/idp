'use strict';

const crypto = require('node:crypto');
const ssl = require('@fitfak/ssl');

// RFC 6962 §4 — CT log'unun HTTP arayüzü.
//
// Yollar RFC'de sabittir (`/ct/v1/...`); değiştirilirse hiçbir izleyici ya da
// istemci log'u kullanamaz. Yanıt alanlarının adları da öyle (snake_case).
//
// ── Neden kendi log'umuz, ve halka açık log'lar hakkında ────────────────────
// Halka açık CT log'ları (Google Argon/Xenon, Cloudflare Nimbus, Let's Encrypt
// Oak) YALNIZCA kök program tarafından tanınan bir CA'ya zincirlenen
// sertifikaları kabul eder. FITFAK kökü bir tarayıcı kök deposunda olmadığı
// için o log'lar bizim sertifikalarımızı REDDEDER -- bu bir yapılandırma
// eksiği değil, tasarım gereğidir.
//
// Dolayısıyla:
//   * Kendi CA'mızdan çıkan sertifikalar -> kendi log'umuz. Amaç aynı: alan adı
//     sahibi, kendi adına ne verildiğini bağımsız olarak görebilsin.
//   * Halka açık güven gerektiğinde (tarayıcıların tanıyacağı bir sertifika)
//     ACME ile Let's Encrypt gibi bir CA kullanılır ve CT gönderimini O CA
//     kendisi yapar -- bizim tarafımızda ek bir iş yoktur.
//
// Kendi log'umuzu "halka açık log'a da gönderelim" diye zorlamak, reddedilecek
// istekler üretmekten başka bir şey yapmaz.

const CT_PATH_PREFIX = '/ct/v1';

/**
 * Log girdilerini şifreli veritabanında tutar.
 *
 * Ekleme-yalnızca (append-only) olması uygulama kuralıdır: bu store hiçbir
 * güncelleme/silme yolu sunmaz. Merkle ağacı zaten geçmişi değiştirmeyi
 * kanıtlanabilir kılar, ama bir kaydı hiç yazmamak da bir saldırıdır ve ona
 * karşı koruma, log'un birden fazla tarafça izlenmesidir.
 */
function createDbLogStorage(db) {
  const entries = db.collection('ct_log_entries');

  // Ağaç her STH/kanıt isteğinde baştan kurulmasın diye bellekte tutuluyor.
  // Log ekleme-yalnızca olduğu için önbellek yalnızca BÜYÜR; geçersiz kılınması
  // gerekmez.
  let cache = null;

  async function loadAll() {
    if (cache) return cache;
    const rows = [];
    // eslint-disable-next-line no-restricted-syntax
    for await (const row of entries.scan()) rows.push(row);
    rows.sort((a, b) => Number(a.leafIndex) - Number(b.leafIndex));
    cache = rows.map((r) => ({
      dedupeKey: r.dedupeKey,
      timestamp: Number(r.timestamp),
      entryType: Number(r.entryType),
      leafHash: Buffer.from(r.leafHashB64, 'base64'),
      merkleLeaf: Buffer.from(r.merkleLeafB64, 'base64'),
      sct: Buffer.from(r.sctB64, 'base64'),
    }));
    return cache;
  }

  return {
    async append(entry) {
      const all = await loadAll();
      const leafIndex = all.length;
      await entries.insert({
        dedupeKey: entry.dedupeKey,
        leafIndex: BigInt(leafIndex),
        timestamp: BigInt(entry.timestamp),
        entryType: entry.entryType,
        leafHashB64: entry.leafHash.toString('base64'),
        merkleLeafB64: entry.merkleLeaf.toString('base64'),
        sctB64: entry.sct.toString('base64'),
      });
      all.push({ ...entry });
      return leafIndex;
    },
    async findByKey(key) {
      const all = await loadAll();
      const found = all.find((e) => e.dedupeKey === key);
      if (found) return found;
      // Önbellek bu süreçte doldurulmuş olabilir ama başka bir instance yazmış
      // olabilir; indeksten de bakıyoruz.
      const row = await entries.findOne('dedupeKey', key);
      return row ? { dedupeKey: row.dedupeKey, sct: Buffer.from(row.sctB64, 'base64') } : null;
    },
    async all() { return loadAll(); },
    async size() { return (await loadAll()).length; },
  };
}

/**
 * Log imzalama anahtarını yükler ya da üretir.
 *
 * Bu anahtarın DEĞİŞMESİ, log'un kimliğinin (logId) değişmesi demektir; daha
 * önce verilmiş bütün SCT'ler doğrulanamaz hale gelir. Bu yüzden anahtar
 * kalıcıdır ve üretildiğinde bir daha döndürülmez -- döndürmek yeni bir log
 * açmaktır, aynı log'a devam etmek değil.
 */
function loadOrCreateLogKey(dir) {
  const fs = require('node:fs');
  const path = require('node:path');
  const privPath = path.join(dir, 'ct-log.key');
  const pubPath = path.join(dir, 'ct-log.pub');

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    return {
      privateKeyPem: fs.readFileSync(privPath, 'utf8'),
      publicKeyPem: fs.readFileSync(pubPath, 'utf8'),
    };
  }

  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  // P-256/SHA-256: RFC 6962'nin izin verdiği iki imza algoritmasından biri
  // (diğeri RSA). Tüm CT istemcileri ikisini de destekler.
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  fs.writeFileSync(privPath, privateKeyPem, { mode: 0o600 });
  fs.writeFileSync(pubPath, publicKeyPem);
  return { privateKeyPem, publicKeyPem };
}

function createCtLog({ db, keyDir }) {
  const { privateKeyPem, publicKeyPem } = loadOrCreateLogKey(keyDir);
  return new ssl.CertificateTransparencyLog({
    privateKeyPem, publicKeyPem, storage: createDbLogStorage(db),
  });
}

/** RFC 6962 §4 uçlarını sunan (req, res) işleyicisi. */
function createCtHandler({ ctLog, publicKeyPem }) {
  const sendJson = (res, status, obj) => {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': Buffer.byteLength(body),
      'cache-control': 'no-store',
    });
    res.end(body);
  };

  const readBody = (req) => new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > 512 * 1024) { req.destroy(); reject(new Error('body too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });

  return async function handle(req, res) {
    const url = new URL(req.url, 'http://ct.trust.fitfak.net');
    const route = url.pathname.slice(CT_PATH_PREFIX.length);

    try {
      // ---- log'un kendisini tanıtan uç (RFC dışı ama izleyiciler için şart) ----
      if (route === '/get-log-info' && req.method === 'GET') {
        return sendJson(res, 200, {
          log_id: ctLog.logId.toString('base64'),
          key: publicKeyPem.replace(/-----[^-]+-----|\s/g, ''),
          mmd_seconds: 86400,
          description: 'FITFAK Certificate Transparency Log',
          // Halka açık log'ların aksine bu log yalnızca FITFAK kökünü kabul eder.
          accepted_roots: 'https://status.trust.fitfak.net/root.crt',
        });
      }

      if ((route === '/add-chain' || route === '/add-pre-chain') && req.method === 'POST') {
        const body = JSON.parse((await readBody(req)).toString('utf8'));
        if (!Array.isArray(body.chain) || body.chain.length === 0) {
          return sendJson(res, 400, { error_message: 'chain is required', success: false });
        }
        const certDer = Buffer.from(body.chain[0], 'base64');
        const issuerDer = body.chain[1] ? Buffer.from(body.chain[1], 'base64') : null;
        const issuerSpkiDer = issuerDer
          ? new crypto.X509Certificate(issuerDer).publicKey.export({ type: 'spki', format: 'der' })
          : null;

        const sct = await ctLog.add({
          certDer,
          issuerSpkiDer,
          precert: route === '/add-pre-chain',
        });

        // Yanıt biçimi RFC 6962 §4.1'de sabit: SCT'nin alanları ayrı ayrı döner,
        // ham SCT baytları değil.
        return sendJson(res, 200, {
          sct_version: 0,
          id: sct.subarray(1, 33).toString('base64'),
          timestamp: Number(sct.readBigUInt64BE(33)),
          extensions: '',
          signature: sct.subarray(43).toString('base64'),
        });
      }

      if (route === '/get-sth' && req.method === 'GET') {
        return sendJson(res, 200, await ctLog.signedTreeHead());
      }

      if (route === '/get-proof-by-hash' && req.method === 'GET') {
        const hash = url.searchParams.get('hash');
        if (!hash) return sendJson(res, 400, { error_message: 'hash is required' });
        const proof = await ctLog.proofByHash(hash);
        if (!proof) return sendJson(res, 404, { error_message: 'leaf not found' });
        return sendJson(res, 200, proof);
      }

      if (route === '/get-entries' && req.method === 'GET') {
        const start = Number(url.searchParams.get('start') || 0);
        const end = Number(url.searchParams.get('end') || 0);
        if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start) {
          return sendJson(res, 400, { error_message: 'invalid range' });
        }
        // Sınırsız aralık, tek istekle tüm log'u indirmeye çalışan bir istemcinin
        // sunucuyu meşgul etmesine yol açar. RFC bir üst sınır koymayı log'a bırakır.
        const cappedEnd = Math.min(end, start + 999);
        return sendJson(res, 200, { entries: await ctLog.getEntries(start, cappedEnd) });
      }

      return sendJson(res, 404, { error_message: 'unknown endpoint' });
    } catch (err) {
      console.error('[ct] hata:', err);
      return sendJson(res, 500, { error_message: 'internal error' });
    }
  };
}

module.exports = { createCtLog, createCtHandler, createDbLogStorage, loadOrCreateLogKey, CT_PATH_PREFIX };
