'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const ssl = require('@fitfak/ssl');
const { ProductionPkiIssuer } = require('../core/pki-issuer');
const { createCtLog, createCtHandler } = require('../services/ct-log-service');
const { createMockDb } = require('./mock-db');

// Certificate Transparency'nin sertifika üretimine bağlanması.
//
// Kripto ve Merkle ağacı @fitfak/ssl tarafında RFC 6962 test vektörleriyle
// doğrulanıyor. Burada doğrulanan, ZİNCİRLEME sorununun gerçekten çözüldüğü:
// SCT sertifikanın içine yazılır, ama SCT'yi almak için sertifikayı log'a
// göndermek gerekir. Önsertifika (poison uzantılı, hiçbir yerde geçerli
// olmayan) bu döngüyü kırar.

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

function hasOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; }
  catch (_) { return false; }
}

function get(port, pathname) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: pathname }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    }).on('error', reject);
  });
}

function post(port, pathname, obj) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(obj);
    const req = http.request({
      host: '127.0.0.1', port, path: pathname, method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fitfak-ct-'));
  const db = createMockDb(['ct_log_entries', 'secrets']);

  const ctLog = createCtLog({ db, keyDir: dir });
  // CA malzemesi artık dosyada değil kasada; `caDir` yalnızca eski dosyaları
  // içeri almak için veriliyor ve burada boş bir dizin.
  const issuer = await ProductionPkiIssuer.open({ db, caDir: dir, ctLog, logger: null });

  console.log('\n[1] Log anahtarı kalıcı');
  check('özel anahtar yazıldı', fs.existsSync(path.join(dir, 'ct-log.key')));
  check('anahtar dosyası 0600', (fs.statSync(path.join(dir, 'ct-log.key')).mode & 0o777) === 0o600);
  const again = createCtLog({ db, keyDir: dir });
  check('yeniden açılışta AYNI logId', again.logId.equals(ctLog.logId));

  console.log('\n[2] Sertifika üretimi SCT gömüyor');
  const key = ssl.generateEcKeyPair('P-256');
  const csr = ssl.generateCSR(
    { keyType: 'ec', curveName: key.curve, ...key },
    [[ssl.oid.OIDs.commonName, 'x']], [],
  );
  const issued = await issuer.signCertificateFromCsr({
    csrPem: csr, profile: 'client-auth',
    subjectOverride: { cn: 'Aybars', email: 'a@fitfak.net' },
  });
  fs.writeFileSync(path.join(dir, 'leaf.crt'), issued.leafPem);

  const der = Buffer.from(
    issued.leafPem.split('\n').filter((l) => l && !l.startsWith('-----')).join(''), 'base64',
  );
  // SCT listesi uzantısının OID'i sertifikada geçmeli.
  const sctOidDer = ssl.asn1.OID(ssl.CT_OIDS.sctList);
  check('sertifika SCT listesi uzantısı taşıyor', der.includes(sctOidDer));

  // Poison, GERÇEK sertifikada ASLA olmamalı: kritik ve tanınmayan bir uzantı,
  // sertifikayı her istemcide geçersiz kılardı.
  const poisonOidDer = ssl.asn1.OID(ssl.CT_OIDS.poison);
  check('gerçek sertifikada poison uzantısı YOK', !der.includes(poisonOidDer));

  console.log('\n[3] Log kaydı oluştu ve önsertifika olarak yazıldı');
  const sth = await ctLog.signedTreeHead();
  check('ağaçta bir girdi var', sth.tree_size === 1);
  const entries = await ctLog.storage.all();
  check('girdi türü önsertifika (precert)', entries[0].entryType === ssl.ct.LOG_ENTRY_TYPE.PRECERT);

  console.log('\n[4] SCT imzası bağımsız olarak doğrulanıyor');
  const logPub = crypto.createPublicKey(fs.readFileSync(path.join(dir, 'ct-log.pub'), 'utf8'));
  const sct = entries[0].sct;
  const timestamp = Number(sct.readBigUInt64BE(33));
  const sigLen = sct.readUInt16BE(45);
  const signature = sct.subarray(47, 47 + sigLen);

  const precertEntry = ssl.ct.buildPrecertEntry({
    precertDer: (() => {
      // Önsertifikayı yeniden üretmek yerine log'un sakladığı yaprağı kullanmak
      // daha doğru olurdu; burada imzanın log anahtarıyla tuttuğunu göstermek
      // için imzalanan yapıyı yaprak baytlarından yeniden kuruyoruz.
      return der;
    })(),
    issuerSpkiDer: new crypto.X509Certificate(issuer.subCA.certPem)
      .publicKey.export({ type: 'spki', format: 'der' }),
  });
  // Yaprak baytlarından imzalanan yapıyı kurmak: MerkleTreeLeaf ile
  // SignedData aynı gövdeyi paylaşır, yalnızca baştaki iki bayt farklıdır.
  const leafBody = entries[0].merkleLeaf.subarray(2);
  const signedData = Buffer.concat([
    Buffer.from([0x00]), Buffer.from([0x00]), leafBody,
  ]);
  check('SCT imzası log anahtarıyla doğrulanıyor',
    crypto.verify('sha256', signedData, logPub, signature));
  check('SCT zaman damgası makul', Math.abs(Date.now() - timestamp) < 60000);

  console.log('\n[5] Aynı anahtarla ikinci sertifika ayrı bir log girdisi');
  const key2 = ssl.generateEcKeyPair('P-256');
  const csr2 = ssl.generateCSR({ keyType: 'ec', curveName: key2.curve, ...key2 },
    [[ssl.oid.OIDs.commonName, 'y']], []);
  await issuer.signCertificateFromCsr({
    csrPem: csr2, profile: 'client-auth', subjectOverride: { cn: 'B', email: 'b@fitfak.net' },
  });
  check('ağaç 2 girdiye çıktı', (await ctLog.signedTreeHead()).tree_size === 2);

  console.log('\n[6] RFC 6962 HTTP uçları');
  const server = http.createServer(createCtHandler({
    ctLog, publicKeyPem: fs.readFileSync(path.join(dir, 'ct-log.pub'), 'utf8'),
  }));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  const sthResp = JSON.parse((await get(port, '/ct/v1/get-sth')).body);
  check('get-sth tree_size dönüyor', sthResp.tree_size === 2);
  check('get-sth kök hash dönüyor', !!sthResp.sha256_root_hash);
  check('get-sth imza dönüyor', !!sthResp.tree_head_signature);

  const info = JSON.parse((await get(port, '/ct/v1/get-log-info')).body);
  check('log kendini tanıtıyor', info.log_id === ctLog.logId.toString('base64'));

  const proofResp = await get(port,
    `/ct/v1/get-proof-by-hash?hash=${encodeURIComponent(entries[0].leafHash.toString('base64'))}`);
  const proof = JSON.parse(proofResp.body);
  check('kapsama kanıtı dönüyor', proof.leaf_index === 0);
  check('kanıt doğrulanıyor', ssl.ct.verifyInclusionProof({
    leaf: entries[0].leafHash,
    index: 0,
    treeSize: 2,
    proof: proof.audit_path.map((p) => Buffer.from(p, 'base64')),
    rootHash: Buffer.from(sthResp.sha256_root_hash, 'base64'),
  }));

  const entriesResp = JSON.parse((await get(port, '/ct/v1/get-entries?start=0&end=1')).body);
  check('get-entries girdileri dönüyor', entriesResp.entries.length === 2);

  console.log('\n[7] add-chain: dışarıdan gönderim');
  const extKey = ssl.generateEcKeyPair('P-256');
  const extCsr = ssl.generateCSR({ keyType: 'ec', curveName: extKey.curve, ...extKey },
    [[ssl.oid.OIDs.commonName, 'ext']], []);
  // İmzalamak için TAM bir imzalayıcı gerekiyor. `issuer.subCA` artık yalnızca
  // özel anahtar İÇERMEYEN bir görünüm -- kasadan istemek zorunda olmak, bir CA
  // anahtarının nerede kullanıldığının her zaman tek bir çağrıda görünmesi
  // demek.
  const subCaSigner = await issuer.vault.loadSigner(issuer.subCA.name);
  const extCert = ssl.issueCertificateFromCSR(extCsr, subCaSigner, { validityDays: 90 });
  const addResp = await post(port, '/ct/v1/add-chain', {
    chain: [extCert.der.toString('base64')],
  });
  const added = JSON.parse(addResp.body);
  check('add-chain SCT dönüyor', addResp.status === 200 && !!added.signature);
  check('SCT log kimliğini taşıyor', added.id === ctLog.logId.toString('base64'));

  const addAgain = JSON.parse((await post(port, '/ct/v1/add-chain', {
    chain: [extCert.der.toString('base64')],
  })).body);
  check('aynı sertifika aynı SCT\'yi alıyor', addAgain.timestamp === added.timestamp);
  check('ağaç şişmedi', (await ctLog.signedTreeHead()).tree_size === 3);

  console.log('\n[8] Hatalı istekler');
  check('boş zincir reddediliyor',
    (await post(port, '/ct/v1/add-chain', { chain: [] })).status === 400);
  check('bilinmeyen uç 404', (await get(port, '/ct/v1/nope')).status === 404);
  check('olmayan yaprak için kanıt 404',
    (await get(port, `/ct/v1/get-proof-by-hash?hash=${encodeURIComponent(crypto.randomBytes(32).toString('base64'))}`)).status === 404);

  if (hasOpenssl()) {
    console.log('\n[9] openssl sertifikayı okuyabiliyor');
    const text = execFileSync('openssl', ['x509', '-in', path.join(dir, 'leaf.crt'), '-noout', '-text'],
      { encoding: 'utf8' });
    check('openssl CT uzantısını görüyor',
      /CT Precertificate SCTs|1\.3\.6\.1\.4\.1\.11129\.2\.4\.2/.test(text));
    check('sertifika hâlâ geçerli biçimde', /Subject:.*CN\s*=\s*Aybars/.test(text));
  }

  server.close();
  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\nOK - CT sertifika entegrasyonu: ${checks} kontrol geçti.`);
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
