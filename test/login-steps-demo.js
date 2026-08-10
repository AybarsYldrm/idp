'use strict';

const fs = require('node:fs');
const path = require('node:path');

const authService = require('../services/auth-service');

// Giriş akışının adımlara ayrılması ve İKİNCİ FAKTÖRÜN HESABA GÖRE SEÇİLMESİ.
//
// Eskiden tek bir ekranda e-posta ve parola birlikte isteniyor, ikinci faktör ekranında ise
// hesapta olsun olmasın HER yöntem gösteriliyordu. İkincisi asıl sorundu: yalnızca TOTP'si olan
// birine "cihaz anahtarı ile onayla" düğmesi göstermek, seçilebilen ama çalışmayan bir yol
// sunmaktır -- ve kullanıcı onu denediğinde başına geleni anlamaz.
//
//
// BURADA SINANAN ASIL ŞEY BİR SIZINTININ OLMAMASI
//
// "Önce e-posta, sonra parola" akışının bariz uygulaması, ilk adımda sunucuya sormaktır: bu
// hesap var mı, hangi yöntemleri kullanıyor. O uygulama çalışır ve bir HESAP SAYIM ARACIDIR:
// parolayı bilmeyen biri, bir adres listesini sırayla girip hangilerinin kayıtlı olduğunu ve
// hangi ikinci faktörü kullandığını öğrenir. İkincisi hedefli kimlik avı için doğrudan işe yarar.
//
// Bu yüzden ilk adım sunucuya HİÇ GİTMEZ ve yöntem listesi parola doğrulandıktan SONRA döner.
// Aşağıdaki kontroller o sıralamayı ve listenin içeriğini doğruluyor.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

const PAGE = fs.readFileSync(path.join(__dirname, '..', 'public', 'demo-login.html'), 'utf8');

async function main() {
  console.log('\n1. Sayfa iki ayrı adım olarak kurulmuş');

  {
    check('kimlik adımı var', /id="view-login"/.test(PAGE));
    check('parola adımı AYRI bir görünüm', /id="view-password"/.test(PAGE));
    check('kimlik adımında "devam et" var', /id="btn-identify"/.test(PAGE));
    check('parola alanı artık kimlik adımında değil',
      PAGE.indexOf('id="login-password"') > PAGE.indexOf('id="view-password"'));

    // Hangi hesapla devam edildiği parola adımında görünmeli. Görünmezse kullanıcı yanlış
    // hesabın parolasını girer, reddedilir ve parolasını unuttuğunu sanır.
    check('parola adımı hangi hesap olduğunu gösteriyor', /id="identity-mail"/.test(PAGE));
    check('ve hesabı değiştirme yolu var', /id="btn-change-identity"/.test(PAGE));
  }

  console.log('\n2. İlk adım sunucuya SORMUYOR');

  {
    // Kritik kontrol. `goToPasswordStep` içinde bir ağ çağrısı olsaydı, o çağrı "bu hesap var mı"
    // sorusunun cevabını parolayı bilmeyen birine açardı.
    const fn = /function goToPasswordStep\(\)\s*\{[\s\S]*?\n  \}/.exec(PAGE);
    check('goToPasswordStep tanımlı', !!fn);
    const body = fn[0];
    check('fetch yok', !/fetch\s*\(/.test(body));
    check('FitfakOAuth çağrısı yok', !/FitfakOAuth\./.test(body));
    check('await yok — yani ağ turu yok', !/await\s/.test(body));
  }

  console.log('\n3. Yöntem listesi parola doğrulandıktan SONRA dönüyor');

  {
    // `availableSecondFactors` sunucu tarafında ve yalnızca ikinci faktör challenge'ının
    // içinde dönüyor. Bunu daha erken dönen bir uç YOK.
    const source = fs.readFileSync(path.join(__dirname, '..', 'services', 'auth-service.js'), 'utf8');
    const occurrences = (source.match(/availableMethods:/g) || []).length;
    check('yöntem listesi yalnızca challenge yanıtlarında', occurrences === 2);

    // İkisi de `requiresSecondFactor` ile birlikte dönüyor: yani parola (ya da SRP) kanıtı
    // verilmeden bu liste hiç üretilmiyor.
    const blocks = source.split('availableMethods:');
    for (let i = 1; i < blocks.length; i++) {
      const before = blocks[i - 1].slice(-260);
      check(`liste #${i} bir ikinci-faktör challenge'ı içinde`, /requiresSecondFactor:\s*true/.test(before));
    }
  }

  console.log('\n4. Liste hesabın GERÇEKTEN sahip olduğu yöntemleri veriyor');

  {
    const factors = (user) => authService._test_availableSecondFactors(user);

    check('yalnızca TOTP kurmuş hesap',
      JSON.stringify(factors({ mfaMethods: '["totp"]', emailVerified: false })) === '["totp"]');

    const passkeyOnly = factors({ mfaMethods: '["webauthn"]', emailVerified: false });
    check('yalnızca geçiş anahtarı kurmuş hesap',
      passkeyOnly.length === 1 && passkeyOnly[0] === 'webauthn');
    // Arayüz buna bakarak TOTP alanını hiç göstermiyor: gösterseydi, o hesapta çalışmayan bir
    // kod kutusu olurdu.
    check('ve TOTP listede YOK', passkeyOnly.indexOf('totp') === -1);

    const both = factors({ mfaMethods: '["totp","webauthn"]', emailVerified: true });
    check('ikisi de kuruluysa ikisi de listede',
      both.indexOf('totp') >= 0 && both.indexOf('webauthn') >= 0);

    // E-posta kodu, doğrulanmış adresi olan her hesapta var: anahtarı başka cihazda kalan
    // kullanıcının çıkış yolu budur. Ama BİRİNCİL olarak seçilmiyor -- arayüz onu yalnızca
    // yedek olarak gösteriyor, çünkü en zayıf yöntemi varsayılan yapmak, güçlü bir faktör
    // kurmuş kullanıcıyı da ona alıştırırdı.
    check('doğrulanmış e-posta yedek yol veriyor', both.indexOf('email_otp') >= 0);
    check('doğrulanmamış e-posta vermiyor',
      factors({ mfaMethods: '["totp"]', emailVerified: false }).indexOf('email_otp') === -1);

    check('hiç yöntem yoksa liste boş',
      JSON.stringify(factors({ mfaMethods: '[]', emailVerified: false })) === '[]');
    check('bozuk kayıt çökertmiyor',
      Array.isArray(factors({ mfaMethods: undefined, emailVerified: false })));
  }

  console.log('\n5. Arayüz listeye göre yalnızca çalışan yolu gösteriyor');

  {
    const fn = /function startSecondFactor\(result\)\s*\{[\s\S]*?\n  \}/.exec(PAGE);
    check('startSecondFactor tanımlı', !!fn);
    const body = fn[0];

    check('sunucunun listesini okuyor', /result\.availableMethods/.test(body));
    check('geçiş anahtarı düğmesi listeye bağlı', /btn-confirm-2fa-passkey[\s\S]*?hasPasskey/.test(body));
    check('TOTP kutusu listeye bağlı', /twofa-code[\s\S]*?hasTotp/.test(body));
    check('yedek yol listeye bağlı', /btn-2fa-email-fallback[\s\S]*?hasEmail/.test(body));

    // İkisi de varsa geçiş anahtarı öne çıkıyor: kimlik avına karşı dayanıklı olan odur
    // (kaynak bağlama), altı haneli bir kod değil.
    check('geçiş anahtarı varsa doğrudan başlatılıyor',
      /if \(hasPasskey\)[\s\S]*?btn-confirm-2fa-passkey'\)\.click\(\)/.test(body));
    // Güçlü faktör yoksa boş bir ekran gösterip kullanıcıyı bağlantı aramaya bırakmıyor.
    check('hiç güçlü faktör yoksa doğrudan e-posta koduna geçiliyor',
      /!hasPasskey && !hasTotp && hasEmail/.test(body));
  }

  console.log('\n6. Her iki giriş yolu da aynı seçiciye bağlanıyor');

  {
    // Parola ile giriş ve geçiş anahtarı ile giriş, ikisi de ikinci faktör isteyebilir. Biri
    // eski `showView('view-2fa')` yolunda kalsaydı, o yoldan gelen kullanıcıya hesabında
    // olmayan yöntemler gösterilmeye devam ederdi.
    check('parola yolu startSecondFactor kullanıyor',
      /requiresSecondFactor\) \{ startSecondFactor\(result\); return; \}/.test(PAGE));
    check('geçiş anahtarı yolu da',
      /requiresSecondFactor\) \{ startSecondFactor\(finishResult\); return; \}/.test(PAGE));
    check('hiçbir yol doğrudan view-2fa\'ya atlamıyor',
      !/showView\('view-2fa'\); return;/.test(PAGE));
  }

  console.log(`\nOK - giriş adımları: ${checks} kontrol geçti.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message, err.stack); process.exit(1); },
);
