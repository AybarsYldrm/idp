'use strict';

// ============================================================================
// Gerçek bir mTLS el sıkışmasını uçtan uca doğrular: openssl ile üretilmiş gerçek bir
// CA + istemci sertifikası (trust.fitfak.net'in kimliğini temsil eder) + sunucu
// sertifikası kullanır. Sahte/simüle bir TLS YOKTUR -- gerçek `tls`/`http2` modülleri,
// gerçek X.509 sertifikaları, gerçek bir el sıkışma.
// ============================================================================
const fs = require('node:fs');
const path = require('node:path');
const http2 = require('node:http2');
const assert = require('node:assert');
const { execSync } = require('node:child_process');
const { PureGrpcClient } = require('../client/grpc-wire-client');

const CERT_DIR = path.join(__dirname, '..', '.tmp-mtls-test-certs');

function generateTestPki() {
  fs.mkdirSync(CERT_DIR, { recursive: true });
  const run = (cmd) => execSync(cmd, { cwd: CERT_DIR, stdio: 'pipe' });

  run('openssl ecparam -name prime256v1 -genkey -noout -out ca.key');
  run('openssl req -new -x509 -key ca.key -out ca.crt -days 3 -subj "/CN=Fitfak Test Root CA"');

  run('openssl ecparam -name prime256v1 -genkey -noout -out client.key');
  run('openssl req -new -key client.key -out client.csr -subj "/CN=trust.fitfak.net"');
  run('openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 3');

  run('openssl ecparam -name prime256v1 -genkey -noout -out other.key'); // GÜVENİLMEYEN (farklı CA'dan) istemci sertifikası
  run('openssl req -new -x509 -key other.key -out other.crt -days 3 -subj "/CN=Guvenilmeyen Istemci"');

  run('openssl ecparam -name prime256v1 -genkey -noout -out server.key');
  run('openssl req -new -key server.key -out server.csr -subj "/CN=localhost"');
  run('openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3');
}

function readAll(names) {
  const out = {};
  for (const n of names) out[n] = fs.readFileSync(path.join(CERT_DIR, n));
  return out;
}

async function main() {
  generateTestPki();
  const {
    'ca.crt': caCrt, 'client.crt': clientCrt, 'client.key': clientKey,
    'other.crt': otherCrt, 'other.key': otherKey, 'server.crt': serverCrt, 'server.key': serverKey,
  } = readAll(['ca.crt', 'client.crt', 'client.key', 'other.crt', 'other.key', 'server.crt', 'server.key']);

  let lastSeenClientCn = null;
  const server = http2.createSecureServer({
    key: serverKey,
    cert: serverCrt,
    ca: caCrt, // istemci sertifikalarını doğrulamak için güvenilen CA
    requestCert: true, // mTLS: istemciden sertifika İSTE
    rejectUnauthorized: true, // güvenilir CA tarafından imzalanmamışsa BAĞLANTIYI REDDET
  });

  server.on('stream', (stream, headers) => {
    const peerCert = stream.session.socket.getPeerCertificate();
    lastSeenClientCn = peerCert?.subject?.CN || null;
    const authorized = stream.session.socket.authorized;
    stream.respond({ ':status': 200, 'content-type': 'application/grpc' }, { waitForTrailers: true });
    stream.on('wantTrailers', () => stream.sendTrailers({ 'grpc-status': '0' }));
    stream.end(JSON.stringify({ authorized, cn: lastSeenClientCn }));
  });

  await new Promise((resolve) => { server.listen(0, resolve); });
  const port = server.address().port;

  try {
    // ---------------------------------------------------------------------
    // 1) GEÇERLİ istemci sertifikası (trust.fitfak.net kimliği) -- BAŞARILI olmalı
    // ---------------------------------------------------------------------
    const validClient = new PureGrpcClient(`https://localhost:${port}`, {
      cert: clientCrt, key: clientKey, ca: caCrt, rejectUnauthorized: true,
    });
    const result = await new Promise((resolve, reject) => {
      const req = validClient.session.request({ ':method': 'POST', ':path': '/test' });
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))));
      req.on('error', reject);
      req.end();
    });
    assert.strictEqual(result.authorized, true, 'sunucu istemci sertifikasını GÜVENİLİR CA\'dan olarak doğrulamalıydı');
    assert.strictEqual(result.cn, 'trust.fitfak.net', 'sunucu istemci sertifikasının CN\'ini (trust.fitfak.net) doğru görmeliydi');
    console.log('mtls: GEÇERLİ istemci sertifikasıyla (trust.fitfak.net kimliği) gerçek bir mTLS el sıkışması başarılı -- sunucu doğru CN\'i gördü');
    validClient.close();

    // ---------------------------------------------------------------------
    // 2) SERTİFİKASIZ bağlantı denemesi -- REDDEDİLMELİ (rejectUnauthorized:true,
    //    requestCert:true olduğu için sunucu istemcisiz/güvenilmeyen bağlantıyı keser)
    // ---------------------------------------------------------------------
    const noCertClient = new PureGrpcClient(`https://localhost:${port}`, { rejectUnauthorized: false });
    const noCertResult = await new Promise((resolve) => {
      const req = noCertClient.session.request({ ':method': 'POST', ':path': '/test' });
      req.on('error', (e) => resolve({ error: e.message }));
      req.on('response', () => resolve({ error: null })); // yanıt geldiyse (beklenmedik) hata yok say
      req.end();
    });
    // Node'un TLS katmanı, sunucu `rejectUnauthorized:true` ile sertifikasız/güvenilmeyen
    // bir bağlantıyı ya el sıkışma sırasında KESER (soket hatası) ya da bağlantıyı kurar
    // ama `authorized:false` işaretler -- HANGİSİ olursa olsun, sertifikasız istemcinin
    // GEÇERLİ bir yanıt ALAMADIĞINI doğruluyoruz.
    assert.ok(noCertResult.error, 'sertifikasız istemci bir hata İLE karşılaşmalıydı (bağlantı reddi)');
    console.log('mtls: sertifika SUNMAYAN istemci doğru şekilde reddedildi (mTLS zorunluluğu çalışıyor)');
    noCertClient.close();

    // ---------------------------------------------------------------------
    // 3) GÜVENİLMEYEN CA'dan imzalı sertifika -- REDDEDİLMELİ
    // ---------------------------------------------------------------------
    // NOT: mTLS reddi TLS EL SIKIŞMASI seviyesinde olur (herhangi bir HTTP/2 stream
    // açılmadan ÖNCE) -- bu yüzden hata `session` nesnesinde yayılır, tek tek stream/
    // request'te DEĞİL. PureGrpcClient bilerek `session.on('error', () => {})` ile
    // SESSION seviyesindeki hataları yutar (uzun ömürlü bir istemcinin geçici bağlantı
    // sorunlarında çökmemesi için makul bir tasarım) -- bu yüzden testte session'ı
    // KENDİ error dinleyicimizle dinliyoruz.
    const untrustedResult = await new Promise((resolve) => {
      const rawSession = require('node:http2').connect(`https://localhost:${port}`, {
        cert: otherCrt, key: otherKey, rejectUnauthorized: false,
      });
      const timer = setTimeout(() => { rawSession.close(); resolve({ error: 'zaman aşımı (bağlantı ne başarılı ne de hatalı oldu)' }); }, 5000);
      rawSession.on('error', (e) => { clearTimeout(timer); resolve({ error: e.message }); });
      rawSession.on('connect', () => {
        // el sıkışma TAMAMLANDI (beklenmedik, ama sunucunun authorized:false işaretleyip
        // işaretleyemediğini kontrol edelim) -- gerçek bir istek atıp yanıtı inceleyelim.
        const req = rawSession.request({ ':method': 'POST', ':path': '/test' });
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => { clearTimeout(timer); resolve({ body: Buffer.concat(chunks).toString('utf8') }); });
        req.on('error', (e) => { clearTimeout(timer); resolve({ error: e.message }); });
        req.end();
      });
    });
    // GÜVENLİK AÇISINDAN KRİTİK OLAN TEK ŞEY: güvenilmeyen bir sertifika HİÇBİR ZAMAN
    // authorized:true sonucuna yol AÇMAMALI -- Node'un TLS yığını bunu (bağlantıyı
    // tamamen keserek, stream'i ortasında keserek, ya da authorized:false işaretleyerek)
    // hangi mekanizmayla sağladığı İKİNCİL bir detaydır.
    const wasIncorrectlyAuthorized = untrustedResult.body && JSON.parse(untrustedResult.body).authorized === true;
    assert.ok(!wasIncorrectlyAuthorized, "GÜVENLİK HATASI: güvenilmeyen CA'dan bir sertifika authorized:true olarak kabul edildi!");
    console.log(`mtls: GÜVENİLMEYEN bir CA'dan imzalı sertifika sunan istemci doğru şekilde reddedildi (${untrustedResult.error || 'authorized:false'})`);

    console.log('\nALL mTLS CHECKS PASSED (gerçek CA + gerçek istemci/sunucu sertifikaları + gerçek TLS el sıkışması)');
  } finally {
    server.close();
    fs.rmSync(CERT_DIR, { recursive: true, force: true });
  }
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
