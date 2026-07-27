'use strict';

const crypto = require('node:crypto');
const { isProbablePrime } = require('@fitfak/ssl/src/bigint');

const {
  N, g, SrpClient, SrpServer, createVerifier, fakeCredentials, SrpError, _internal,
} = require('../core/srp');

// SRP-6a — parolanın sunucuya hiç ulaşmadığının ve bilinen saldırıların
// reddedildiğinin doğrulanması.

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

function fullExchange({ identity, registeredPassword, attemptedPassword }) {
  const { saltB64, verifier } = createVerifier({ password: registeredPassword });
  const client = new SrpClient({ identity, password: attemptedPassword });
  const server = new SrpServer({ identity, saltB64, verifierB64: verifier });

  const hello = client.start();
  const challenge = server.challenge();
  const proof = client.respond(challenge);
  const serverResult = server.verify({ A: hello.A, M1: proof.M1 });
  const clientResult = client.verifyServer(serverResult);
  return { serverResult, clientResult, hello, challenge, proof };
}

function main() {
  console.log('\n[1] Grup parametreleri gerçekten güvenli asal');
  // Bu kontrol biçimsel değil. Asal olmayan bir N ile protokol sorunsuz
  // ÇALIŞIR -- taraflar aynı anahtara varır, kimlik doğrulama başarılı olur --
  // ama ayrık logaritma kolaylaşır ve güvenlik tamamen kaybolur. Sabitin
  // doğruluğu, protokolün çalışmasından gözlemlenemez.
  check('N asal', isProbablePrime(N, 24));
  check('N güvenli asal ((N-1)/2 de asal)', isProbablePrime((N - 1n) / 2n, 24));
  check('N 2048 bit', N.toString(2).length === 2048);
  check('g = 2 bir üreteç (g^((N-1)/2) ≡ N-1)',
    require('@fitfak/ssl/src/bigint').modPow(g, (N - 1n) / 2n, N) === N - 1n);

  console.log('\n[2] Doğru parola ile karşılıklı doğrulama');
  const ok = fullExchange({
    identity: 'aybars@fitfak.net',
    registeredPassword: 'CorrectHorseBatteryStaple1!',
    attemptedPassword: 'CorrectHorseBatteryStaple1!',
  });
  check('sunucu istemciyi doğruladı', !!ok.serverResult.M2);
  check('istemci sunucuyu doğruladı', !!ok.clientResult.sessionKey);
  check('iki taraf aynı oturum anahtarına vardı',
    ok.serverResult.sessionKey.equals(ok.clientResult.sessionKey));
  check('oturum anahtarı 32 bayt', ok.clientResult.sessionKey.length === 32);

  console.log('\n[3] Parola telde HİÇ görünmüyor');
  const password = 'CorrectHorseBatteryStaple1!';
  const { saltB64, verifier } = createVerifier({ password });
  const client = new SrpClient({ identity: 'u@fitfak.net', password });
  const server = new SrpServer({ identity: 'u@fitfak.net', saltB64, verifierB64: verifier });
  const wire = JSON.stringify([client.start(), server.challenge(),
    client.respond(server.challenge()), { verifier, saltB64 }]);
  check('parola hiçbir mesajda yok', !wire.includes(password));
  check('parola base64 olarak da yok', !wire.includes(Buffer.from(password).toString('base64')));
  check('sunucunun sakladığı doğrulayıcı parola değil',
    !Buffer.from(verifier, 'base64').includes(Buffer.from(password)));

  console.log('\n[4] Yanlış parola reddedilir');
  let rejected = false;
  try {
    fullExchange({
      identity: 'aybars@fitfak.net',
      registeredPassword: 'CorrectHorseBatteryStaple1!',
      attemptedPassword: 'CorrectHorseBatteryStaple2!',
    });
  } catch (e) { rejected = e.code === 'auth_failed'; }
  check('tek karakter farkı bile reddedilir', rejected);

  console.log('\n[5] A ≡ 0 saldırısı reddedilir');
  // RFC 5054'ün en kritik maddesi. Kabul edilseydi S = (A·v^u)^b = 0 olurdu ve
  // parolayı hiç bilmeyen bir istemci, sunucunun anahtarını (sıfırın hash'i)
  // hesaplayarak giriş yapardı.
  const srv = new SrpServer({ identity: 'u@fitfak.net', saltB64, verifierB64: verifier });
  let zeroRejected = false;
  try {
    srv.verify({ A: Buffer.alloc(1, 0).toString('base64'), M1: Buffer.alloc(32).toString('base64') });
  } catch (e) { zeroRejected = e.code === 'auth_failed'; }
  check('A = 0 reddedilir', zeroRejected);

  let nRejected = false;
  try {
    srv.verify({ A: _internal.toBuf(N).toString('base64'), M1: Buffer.alloc(32).toString('base64') });
  } catch (e) { nRejected = e.code === 'auth_failed'; }
  check('A = N (≡ 0 mod N) reddedilir', nRejected);

  console.log('\n[6] Sahte sunucu (B ≡ 0) istemci tarafından reddedilir');
  const c2 = new SrpClient({ identity: 'u@fitfak.net', password });
  let badB = false;
  try {
    c2.respond({ saltB64, B: Buffer.alloc(1, 0).toString('base64') });
  } catch (e) { badB = e.code === 'bad_server_ephemeral'; }
  check('B = 0 gönderen sunucu reddedilir', badB);

  console.log('\n[7] Doğrulayıcıyı bilmek, sunucu gibi davranmaya yetmez');
  // v çalınmışsa saldırgan İSTEMCİYE karşı sunucu taklidi yapabilir (SRP'nin
  // bilinen sınırı) ama SUNUCUYA karşı istemci olamaz: bunun için x gerekir ve
  // v = g^x'ten x'i çıkarmak ayrık logaritmadır.
  const attacker = new SrpServer({ identity: 'u@fitfak.net', saltB64, verifierB64: verifier });
  const honest = new SrpClient({ identity: 'u@fitfak.net', password: 'yanlis-parola' });
  let cannotImpersonate = false;
  try {
    const p = honest.respond(attacker.challenge());
    attacker.verify({ A: honest.start().A, M1: p.M1 });
  } catch (e) { cannotImpersonate = e.code === 'auth_failed'; }
  check('doğrulayıcı ile parolasız giriş yapılamaz', cannotImpersonate);

  console.log('\n[8] Her oturum farklı anahtar üretir (tekrar oynatma yok)');
  const s1 = fullExchange({ identity: 'x@fitfak.net', registeredPassword: 'p', attemptedPassword: 'p' });
  const s2 = fullExchange({ identity: 'x@fitfak.net', registeredPassword: 'p', attemptedPassword: 'p' });
  check('iki oturumun anahtarları farklı',
    !s1.clientResult.sessionKey.equals(s2.clientResult.sessionKey));
  check('iki oturumun M1 kanıtları farklı', s1.proof.M1 !== s2.proof.M1);

  console.log('\n[9] Var olmayan kullanıcı da gerçekçi bir challenge alır');
  // Sunucu "böyle bir kullanıcı yok" diye erken dönerse, giriş ucu bir kullanıcı
  // numaralandırma oracle'ı olur -- kayıt uçları ne kadar dikkatli yazılırsa
  // yazılsın.
  const serverSecret = crypto.randomBytes(32);
  const f1 = fakeCredentials('yok@fitfak.net', serverSecret);
  const f2 = fakeCredentials('yok@fitfak.net', serverSecret);
  const f3 = fakeCredentials('baska@fitfak.net', serverSecret);
  check('aynı kullanıcı için salt kararlı', f1.saltB64 === f2.saltB64);
  check('farklı kullanıcı için salt farklı', f1.saltB64 !== f3.saltB64);
  check('sahte doğrulayıcı gerçek boyutta',
    Buffer.from(f1.verifierB64, 'base64').length >= 250);

  let fakeFails = false;
  try {
    const fs_ = new SrpServer({ identity: 'yok@fitfak.net', ...f1, verifierB64: f1.verifierB64 });
    const fc = new SrpClient({ identity: 'yok@fitfak.net', password: 'herhangi' });
    const p = fc.respond(fs_.challenge());
    fs_.verify({ A: fc.start().A, M1: p.M1 });
  } catch (e) { fakeFails = e.code === 'auth_failed'; }
  check('sahte hesaba hiçbir parola ile girilemez', fakeFails);

  console.log(`\nOK - SRP-6a: ${checks} kontrol geçti.`);
}

main();
