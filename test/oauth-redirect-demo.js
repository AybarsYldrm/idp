'use strict';

const redirects = require('../core/oauth-redirect');

// Yönlendirme adresleri ve yetkilendirme kodları.
//
// Buradaki kontrollerin çoğu bir kayıt formunda "hayır" demekle ilgili ve bu
// sıkıcı görünüyor. Sıkıcı olmayan kısmı şu: kayıtlı bir yönlendirme adresi,
// yetkilendirme kodunun GİDECEĞİ yerdir. Yanlış bir değer oraya girdiğinde
// ortaya çıkan şey, o uygulamanın kullanıcılarının hesaplarının, o adresi
// kontrol eden kişiye teslim edilmesidir -- ve `example.com` gerçekten kayıtlı
// bir alan adıdır, sahibi de siz değilsiniz.
//
// Kodların yapısı ise AYRI bir konu ve dosyanın kendisi bunun bir güvenlik
// özelliği OLMADIĞINI söylüyor. Buradaki testler de o iddiayı test ediyor:
// yapının sağladığı şey, yanlış istemcinin gönderdiği bir kodun depoya hiç
// gitmeden reddedilmesi; sağlamadığı şey, kodun tahmin edilemezliği (o
// tamamen 32 baytlık rastgelelikten geliyor).

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

function rejects(label, fn) {
  let threw = false;
  try { fn(); } catch (_) { threw = true; }
  check(label, threw);
}

const SECRET = Buffer.alloc(32, 9);

function main() {
  console.log('\n1. Kayıt sırasında kabul edilenler');

  check('https adres kabul edilir',
    redirects.validateRedirectUri('https://dns.fitfak.net/callback') === 'https://dns.fitfak.net/callback');
  check('sorgu dizesi taşıyan adres kabul edilir',
    redirects.validateRedirectUri('https://dns.fitfak.net/cb?tenant=core').includes('tenant=core'));
  check('yerel geliştirme adresi (izin verildiğinde) kabul edilir',
    !!redirects.validateRedirectUri('http://localhost:3000/cb', { allowInsecureLocalhost: true }));

  console.log('\n2. Kayıt sırasında reddedilenler');

  // Kullanıcının şikayet ettiği tam da bu: form `https://example.com/oauth/callback`
  // ile kaydediliyor ve hiçbir şey itiraz etmiyor.
  rejects('example.com reddedilir', () => redirects.validateRedirectUri('https://example.com/oauth/callback'));
  rejects('example.org reddedilir', () => redirects.validateRedirectUri('https://example.org/cb'));
  rejects('.invalid TLD reddedilir', () => redirects.validateRedirectUri('https://app.invalid/cb'));
  rejects('your-app.com reddedilir', () => redirects.validateRedirectUri('https://your-app.com/cb'));

  rejects('http (yerel olmayan) reddedilir', () => redirects.validateRedirectUri('http://dns.fitfak.net/cb'));
  rejects('yerel http varsayılan olarak reddedilir', () => redirects.validateRedirectUri('http://localhost:3000/cb'));
  rejects('parça (#) reddedilir', () => redirects.validateRedirectUri('https://dns.fitfak.net/cb#tok'));
  rejects('joker karakter reddedilir', () => redirects.validateRedirectUri('https://*.fitfak.net/cb'));
  rejects('göreli adres reddedilir', () => redirects.validateRedirectUri('/callback'));
  rejects('nokta içermeyen ana makine reddedilir', () => redirects.validateRedirectUri('https://intranet/cb'));

  // `https://kurban.com@saldirgan.com/` bir insana kurban.com gibi görünür ve
  // tarayıcı saldirgan.com'a gider. Kayıt formunda gözden kaçması çok kolay.
  rejects('kullanıcı bilgisi taşıyan adres reddedilir',
    () => redirects.validateRedirectUri('https://dns.fitfak.net@saldirgan.com/cb'));

  console.log('\n3. Normalleştirme: aynı adresin iki yazımı aynı kayda çözülmeli');

  const a = redirects.validateRedirectUri('https://DNS.fitfak.net:443/callback');
  const b = redirects.validateRedirectUri('https://dns.fitfak.net/callback');
  check('büyük harf ve varsayılan port normalleştirilir', a === b);
  check('normalleştirilmiş biçim tekillik anahtarını eşitler',
    redirects.clientUriKey('dns', a) === redirects.clientUriKey('dns', b));

  console.log('\n4. Tutamaklar');

  const uri = 'https://dns.fitfak.net/callback';
  const handle = redirects.deriveHandle({ clientId: 'dns', redirectUri: uri, secret: SECRET });
  check('tutamak öneki taşıyor', handle.startsWith('r1.'));
  check('aynı istemci + aynı adres = aynı tutamak',
    redirects.deriveHandle({ clientId: 'dns', redirectUri: uri, secret: SECRET }) === handle);
  check('BAŞKA bir istemci için farklı tutamak',
    redirects.deriveHandle({ clientId: 'mail', redirectUri: uri, secret: SECRET }) !== handle);
  check('başka bir adres için farklı tutamak',
    redirects.deriveHandle({ clientId: 'dns', redirectUri: `${uri}2`, secret: SECRET }) !== handle);
  check('başka bir sır ile farklı tutamak',
    redirects.deriveHandle({ clientId: 'dns', redirectUri: uri, secret: Buffer.alloc(32, 8) }) !== handle);
  check('tutamak adresi sızdırmıyor',
    !Buffer.from(handle, 'utf8').includes(Buffer.from('fitfak')));

  console.log('\n5. Yetkilendirme kodları');

  const { code, lookupKey } = redirects.issueAuthorizationCode({ clientId: 'dns', redirectHandle: handle });
  check('kod sürüm önekiyle başlıyor', code.startsWith('1.'));
  check('bir depo anahtarı üretiliyor', typeof lookupKey === 'string' && lookupKey.length > 0);

  const parsed = redirects.parseAuthorizationCode(code, { clientId: 'dns' });
  check('doğru istemci kodu çözebiliyor', parsed !== null);
  check('çözülen depo anahtarı üretilenle aynı', parsed.lookupKey === lookupKey);

  // Yapının sağladığı TEK şey bu: yanlış istemcinin kodu depoya hiç gitmeden düşer.
  check('BAŞKA bir istemci için çözülemiyor',
    redirects.parseAuthorizationCode(code, { clientId: 'mail' }) === null);

  check('bozuk kod null döner', redirects.parseAuthorizationCode('bozuk', { clientId: 'dns' }) === null);
  check('yanlış sürüm null döner',
    redirects.parseAuthorizationCode(`2.${code.slice(2)}`, { clientId: 'dns' }) === null);
  check('kısaltılmış gövde null döner',
    redirects.parseAuthorizationCode(`1.${code.slice(2, 20)}`, { clientId: 'dns' }) === null);
  check('boş kod null döner', redirects.parseAuthorizationCode('', { clientId: 'dns' }) === null);
  check('nokta olmayan kod null döner', redirects.parseAuthorizationCode('1abc', { clientId: 'dns' }) === null);

  console.log('\n6. Kodun tahmin edilemezliği yapıdan DEĞİL rastgelelikten geliyor');

  const seen = new Set();
  for (let i = 0; i < 500; i++) {
    seen.add(redirects.issueAuthorizationCode({ clientId: 'dns', redirectHandle: handle }).code);
  }
  check('500 kodun hepsi farklı', seen.size === 500);

  // Aynı istemci + aynı tutamak için üretilen iki kod, sabit önekleri paylaşır
  // ama gövdenin geri kalanı tamamen farklıdır. Bu, yapının GÖRÜNÜR olduğunu ve
  // gizlilik sağlamadığını doğruluyor -- dosyanın iddiası da tam olarak bu.
  const one = redirects.issueAuthorizationCode({ clientId: 'dns', redirectHandle: handle });
  const two = redirects.issueAuthorizationCode({ clientId: 'dns', redirectHandle: handle });
  const p1 = redirects.parseAuthorizationCode(one.code, { clientId: 'dns' });
  const p2 = redirects.parseAuthorizationCode(two.code, { clientId: 'dns' });
  check('iki kod aynı istemci referansını taşıyor', p1.clientRef === p2.clientRef);
  check('iki kod aynı yönlendirme referansını taşıyor', p1.redirectRef === p2.redirectRef);
  check('ama depo anahtarları farklı', p1.lookupKey !== p2.lookupKey);

  console.log(`\nOK - yönlendirme adresleri ve kodlar: ${checks} kontrol geçti.`);
}

try { main(); }
catch (err) { console.error('\nFAILED:', err.message); process.exit(1); }
