'use strict';

const path = require('node:path');

const serverSrp = require('../core/srp');

// Tarayıcı istemcisi ile sunucu uygulamasının GERÇEKTEN uyuştuğunun kanıtı.
//
// core/srp.js ve public/srp-client.js aynı protokolü iki ayrı kod tabanında
// uygular: biri node:crypto, diğeri Web Crypto üzerinde; biri Buffer, diğeri
// Uint8Array ile. İkisinin aynı sonucu ürettiği varsayılamaz -- ve ayrıştıkları
// takdirde belirti "parola yanlış" olur, ki bu sebebi bulmak için mümkün olan
// en yanıltıcı hata mesajıdır.
//
// public/srp-client.js burada DEĞİŞTİRİLMEDEN yükleniyor: Node 22 zaten
// globalThis.crypto.subtle, btoa/atob ve TextEncoder sağlıyor, yani tarayıcının
// kullanacağı kodun aynısı çalışıyor.

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

// Tarayıcı dosyası bir global'e yazıyor; burada onu yakalıyoruz.
require(path.join(__dirname, '..', 'public', 'srp-client.js'));
const browserSrp = globalThis.FitfakSrp;

async function main() {
  console.log('\n[1] Tarayıcı dosyası Node üzerinde olduğu gibi yükleniyor');
  check('FitfakSrp global olarak mevcut', !!browserSrp);
  check('aynı N', browserSrp.N === serverSrp.N);
  check('aynı g', browserSrp.g === serverSrp.g);

  const password = 'CorrectHorseBatteryStaple1!';
  const identity = 'aybars@fitfak.net';

  console.log('\n[2] Aynı salt -> aynı doğrulayıcı');
  // Kayıt tarayıcıda yapılır; sunucu doğrulayıcıyı yalnızca saklar. İki taraf
  // aynı x'i türetmezse, tarayıcıda üretilmiş bir hesaba hiçbir zaman
  // girilemez -- ve bu ancak ilk gerçek girişte fark edilir.
  const salt = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
  const serverSide = serverSrp.createVerifier({ password, salt });
  const browserSide = await browserSrp.createVerifier(password, new Uint8Array(salt));
  check('salt aynı', browserSide.saltB64 === serverSide.saltB64);
  check('doğrulayıcı bit düzeyinde aynı', browserSide.verifier === serverSide.verifier);

  console.log('\n[3] Tarayıcı istemcisi <-> sunucu: tam el sıkışma');
  const server = new serverSrp.SrpServer({
    identity,
    saltB64: serverSide.saltB64,
    verifierB64: serverSide.verifier,
  });
  const client = new browserSrp.SrpClient({ identity, password });

  const hello = client.start();
  const challenge = server.challenge();
  const proof = await client.respond(challenge);
  const serverResult = server.verify({ A: hello.A, M1: proof.M1 });
  check('sunucu, tarayıcı istemcisinin M1 kanıtını kabul etti', !!serverResult.M2);

  const clientResult = await client.verifyServer(serverResult);
  check('tarayıcı, sunucunun M2 kanıtını kabul etti', !!clientResult.sessionKey);
  check('iki taraf aynı oturum anahtarına vardı',
    Buffer.from(clientResult.sessionKey).equals(serverResult.sessionKey));

  console.log('\n[4] Ters yön: sunucu istemcisi <-> aynı doğrulayıcı');
  const server2 = new serverSrp.SrpServer({
    identity, saltB64: serverSide.saltB64, verifierB64: browserSide.verifier,
  });
  const client2 = new serverSrp.SrpClient({ identity, password });
  const r2 = server2.verify({
    A: client2.start().A,
    M1: client2.respond(server2.challenge()).M1,
  });
  check('tarayıcıda üretilen doğrulayıcı Node istemcisiyle de çalışıyor', !!r2.M2);

  console.log('\n[5] Yanlış parola, tarayıcı istemcisinde de reddedilir');
  const server3 = new serverSrp.SrpServer({
    identity, saltB64: serverSide.saltB64, verifierB64: serverSide.verifier,
  });
  const wrong = new browserSrp.SrpClient({ identity, password: 'YanlisParola1!' });
  let rejected = false;
  try {
    const p = await wrong.respond(server3.challenge());
    server3.verify({ A: wrong.start().A, M1: p.M1 });
  } catch (e) { rejected = e.code === 'auth_failed'; }
  check('yanlış parola reddedildi', rejected);

  console.log('\n[6] Parola hiçbir mesajda görünmüyor');
  const onWire = JSON.stringify([hello, challenge, proof, serverResult]);
  check('düz metin parola yok', !onWire.includes(password));

  console.log(`\nOK - SRP tarayıcı/sunucu eşdeğerliği: ${checks} kontrol geçti.`);
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
