'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const ssl = require('@fitfak/ssl');
const pki = require('@fitfak/ssl/src/pki');
const { ProductionPkiIssuer } = require('../core/pki-issuer');
const { createStatusHandler, createPolicyHandler } = require('../services/status-server');
const { createMockDb } = require('./mock-db');

// İptalin gerçekten işe yaraması.
//
// Üç ayrı şey burada doğrulanıyor ve üçü de daha önce sessizce bozuktu:
//
//  1. CRL, uç sertifikaları İMZALAYAN anahtarla imzalanmalı. Kök ile imzalanmış
//     bir liste, ara CA'nın verdiği sertifikaları kapsamaz ve doğrulayıcılar onu
//     dikkate almaz -- iptal kaydı üretilir, yayınlanır, hiçbir şey olmaz.
//  2. Bilinmeyen bir seri 'unknown' olmalı, 'good' değil. Yetkili bir
//     responder'ın hiç üretmediği bir seri için "iptal edilmemiş" demesi,
//     uydurma seri taşıyan bir sertifikaya olumlu cevap vermektir.
//  3. Ara CA iptal edildiğinde altındaki uç sertifikalar da iptal sayılmalı.

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

/** `openssl crl -CAfile` sonucu stderr'e yazar; exit kodu asıl cevaptır. */
function opensslVerifyCrl(crlPath, caPath) {
  try {
    execFileSync('openssl', ['crl', '-in', crlPath, '-inform', 'DER', '-CAfile', caPath, '-noout'],
      { stdio: ['pipe', 'pipe', 'pipe'] });
    return true;
  } catch (_) { return false; }
}

function hasOpenssl() {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }); return true; }
  catch (_) { return false; }
}

async function issueLeaf(issuer, db, { cn, email, profile = 'client-auth' }) {
  const key = ssl.generateEcKeyPair('P-256');
  const csr = ssl.generateCSR(
    { keyType: 'ec', curveName: key.curve, ...key },
    [[ssl.oid.OIDs.commonName, cn]], [],
  );
  const issued = await issuer.signCertificateFromCsr({
    csrPem: csr, profile, subjectOverride: { cn, email },
  });
  await db.collection('certificates').insert({
    serialNumberHex: issued.serialNumberHex,
    skidHex: issued.skidHex,
    userId: 'u1', subjectCn: cn, profile,
    certPem: issued.leafPem,
    notBefore: BigInt(issued.notBefore.getTime()),
    notAfter: BigInt(issued.notAfter.getTime()),
    status: 'valid', revokedAt: 0n, revocationReason: '',
    createdAt: BigInt(Date.now()), issuedVia: 'test',
  });
  return issued;
}

async function revoke(db, serialNumberHex, reason) {
  const certs = db.collection('certificates');
  const row = await certs.findOne('serialNumberHex', serialNumberHex);
  await certs.update(row._id, {
    status: 'revoked', revokedAt: BigInt(Date.now()), revocationReason: reason,
  });
}

function post(port, pathname, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: pathname,
      headers: { 'content-type': 'application/ocsp-request', 'content-length': body.length } },
    (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

function get(port, pathname) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: pathname }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    }).on('error', reject);
  });
}

/**
 * Durumu openssl'e okutuyoruz, kendi ayrıştırıcımıza değil.
 *
 * Kendi ürettiğimiz baytları yine kendi kodumuzun okuyabilmesi hiçbir şey
 * kanıtlamaz: iki tarafta da aynı yanlış anlaşılma olabilir. Anlamlı olan,
 * bağımsız bir uygulamanın yanıtı bizim kastettiğimiz gibi okumasıdır --
 * gerçek istemciler de onu okuyacak.
 */
let respCounter = 0;
function readOcspStatus(der, tmpDir) {
  const file = path.join(tmpDir, `resp-${respCounter++}.der`);
  fs.writeFileSync(file, der);
  const text = execFileSync('openssl', ['ocsp', '-respin', file, '-resp_text', '-noverify'],
    { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  const m = /Cert Status:\s*(\w+)/i.exec(text);
  return { certStatus: m ? m[1].toLowerCase() : null, text };
}

async function main() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fitfak-revoke-'));
  if (!hasOpenssl()) {
    console.log('SKIP - iptal zinciri: openssl bulunamadi');
    process.exit(0);
  }
  const db = createMockDb(['certificates', 'secrets']);
  const issuer = await ProductionPkiIssuer.open({ db, caDir: dir, logger: null });

  const cacheStore = {
    _m: new Map(),
    async get(k) { return this._m.get(k) || null; },
    async set(k, v) { this._m.set(k, v); },
    async delete(k) { this._m.delete(k); },
  };

  console.log('\n[1] İki uç sertifika verilir');
  const alice = await issueLeaf(issuer, db, { cn: 'alice', email: 'alice@fitfak.net' });
  const bob = await issueLeaf(issuer, db, { cn: 'bob', email: 'bob@fitfak.net' });
  check('alice sertifikası verildi', !!alice.serialNumberHex);
  check('bob sertifikası verildi', !!bob.serialNumberHex);

  const server = http.createServer(createStatusHandler({ db, pkiIssuer: issuer, cacheStore }));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  // OCSP isteği yayıncının adı ve anahtar özeti üzerine kurulur; kasadan tam
  // imzalayıcıyı almak, bu alanların sertifikanın kendisinden gelmesini garanti eder.
  const subCaSigner = await issuer.vault.loadSigner(issuer.subCA.name);
  const ocspFor = async (serialHex) => {
    const { der } = pki.buildOcspRequest(subCaSigner, BigInt(`0x${serialHex}`), { nonce: true });
    const res = await post(port, '/ocsp', der);
    return readOcspStatus(res.body, dir);
  };

  console.log('\n[2] İptal edilmemiş sertifika: good');
  check('alice good', (await ocspFor(alice.serialNumberHex)).certStatus === 'good');

  console.log('\n[3] Hiç verilmemiş bir seri: unknown (good DEĞİL)');
  // Bu, düzeltilen açığın ta kendisi: yetkili responder daha önce uydurma bir
  // seri için 'good' diyordu.
  const madeUp = (await ocspFor('7fffffffdeadbeef')).certStatus;
  check(`uydurma seri '${madeUp}' olarak yanıtlandı`, madeUp === 'unknown');

  console.log('\n[4] Uç sertifika iptali');
  await revoke(db, bob.serialNumberHex, 'keyCompromise');
  await cacheStore.delete('crl:leaf');
  check('bob revoked', (await ocspFor(bob.serialNumberHex)).certStatus === 'revoked');
  check('alice hâlâ good', (await ocspFor(alice.serialNumberHex)).certStatus === 'good');

  console.log('\n[5] CRL: doğru anahtarla imzalanmış ve iptali içeriyor');
  const crlRes = await get(port, '/crl');
  check('content-type application/pkix-crl', crlRes.headers['content-type'] === 'application/pkix-crl');
  fs.writeFileSync(path.join(dir, 'leaf.crl'), crlRes.body);
  fs.writeFileSync(path.join(dir, 'sub.pem'), issuer.subCA.certPem);
  fs.writeFileSync(path.join(dir, 'root.pem'), issuer.rootCA.certPem);

  if (hasOpenssl()) {
    // Asıl kontrol bu: CRL, ARA CA ile doğrulanabiliyor mu? Kök ile imzalanmış
    // olsaydı bu adım başarısız olur ve iptal hiçbir doğrulayıcıya ulaşmazdı.
    // NOT: `openssl crl -CAfile` sonucunu STDERR'e yazar. Yalnızca stdout'u
    // okumak, doğrulama başarılı olsa bile boş dize döndürür ve kontrol
    // sessizce hep başarısız görünür.
    check('openssl: CRL ara CA ile doğrulandı',
      opensslVerifyCrl(path.join(dir, 'leaf.crl'), path.join(dir, 'sub.pem')));

    const text = execFileSync('openssl', ['crl', '-in', path.join(dir, 'leaf.crl'),
      '-inform', 'DER', '-text', '-noout'], { encoding: 'utf8' });
    const bobSerialUpper = BigInt(`0x${bob.serialNumberHex}`).toString(16).toUpperCase();
    check('CRL bob\'un serisini içeriyor', text.toUpperCase().includes(bobSerialUpper));
    check('iptal sebebi taşınıyor', /Key Compromise/i.test(text));
  } else {
    console.log('  (openssl yok -- CRL imza doğrulaması atlandı)');
  }

  console.log('\n[6] ZİNCİR: ara CA iptal edilince altındaki her şey düşer');
  const subCaSkidHex = Buffer.isBuffer(issuer.subCA.skid)
    ? issuer.subCA.skid.toString('hex') : String(issuer.subCA.skid);
  const subCaInfo = ssl.certInfoFromPem(issuer.subCA.certPem);
  await db.collection('certificates').insert({
    serialNumberHex: subCaInfo.serialNumberHex || 'aa00',
    skidHex: subCaSkidHex,
    userId: 'system', subjectCn: 'FITFAK Authority Core Sub-CA G1',
    profile: 'intermediate-ca', certPem: issuer.subCA.certPem,
    notBefore: 0n, notAfter: 0n,
    status: 'revoked', revokedAt: BigInt(Date.now()), revocationReason: 'cACompromise',
    createdAt: BigInt(Date.now()), issuedVia: 'system',
  });
  await cacheStore.delete('crl:leaf');
  await cacheStore.delete('crl:root');

  // alice'in KENDİ kaydı hâlâ 'valid'. Yayıncısı düştüğü için yine de iptal.
  const aliceAfter = (await ocspFor(alice.serialNumberHex)).certStatus;
  check(`ara CA iptalinden sonra alice '${aliceAfter}'`, aliceAfter === 'revoked');

  console.log('\n[7] Ara CA iptali KÖK listesinde, uç listesinde değil');
  const rootCrl = await get(port, '/crl/root');
  check('/crl/root yanıt veriyor', rootCrl.status === 200);
  if (hasOpenssl()) {
    fs.writeFileSync(path.join(dir, 'root.crl'), rootCrl.body);
    check('openssl: kök CRL kök ile doğrulandı',
      opensslVerifyCrl(path.join(dir, 'root.crl'), path.join(dir, 'root.pem')));

    // Ters yön de önemli: uç CRL'i KÖK ile doğrulanmamalı. Doğrulanıyorsa
    // "hangi liste hangi sertifikaları kapsıyor" ayrımı gerçekte yok demektir.
    check('uç CRL kök ile doğrulanmıyor (kapsam ayrımı gerçek)',
      !opensslVerifyCrl(path.join(dir, 'leaf.crl'), path.join(dir, 'root.pem')));
  }

  console.log('\n[8] CA yayını ve politika dağıtımı');
  const inter = await get(port, '/intermediate.crt');
  check('/intermediate.crt sunuluyor', inter.status === 200 && inter.body.includes('BEGIN CERTIFICATE'));

  const policyServer = http.createServer(createPolicyHandler());
  await new Promise((r) => policyServer.listen(0, '127.0.0.1', r));
  const pport = policyServer.address().port;
  const dirRes = await get(pport, '/policy');
  const parsed = JSON.parse(dirRes.body.toString());
  check('politika dizini PEN 65133 bildiriyor', parsed.pen === '1.3.6.1.4.1.65133');
  check('client-auth politikası yayınlanıyor',
    parsed.policies.some((p) => p.oid === '1.3.6.1.4.1.65133.1.1'));
  const doc = await get(pport, '/policy/timestamping');
  check('politika belgesi sunuluyor', /1\.3\.6\.1\.4\.1\.65133\.1\.4/.test(doc.body.toString()));

  server.close();
  policyServer.close();
  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\nOK - iptal zinciri: ${checks} kontrol geçti.`);
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
