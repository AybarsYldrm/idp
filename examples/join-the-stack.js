'use strict';

// BİR UYGULAMANIN BU YIĞINA KATILMASI, BAŞTAN SONA.
//
//   node examples/join-the-stack.js
//
// Anlatılan şey, `dns-resolver` adında bir uygulamanın iki sisteme de TEK bir kimlikle
// bağlanması: veritabanına mTLS ile (SPIFFE kimliği sertifikanın URI SAN'ında), IdP'ye
// OAuth istemcisi olarak. İkisinde de aynı ad kullanılıyor ve bu tesadüf değil -- yönetim
// paneli uygulamayı tek bir adla kaydediyor ve OAuth istemci kimliğini, veritabanı servis
// adını ve SPIFFE kimliğini o addan türetiyor.
//
//
// ÖNCE: UYGULAMAYI KAYDEDİN
//
// one.fitfak.net'te, yönetici olarak:
//
//     POST /admin/applications
//     { "name": "dns-resolver",
//       "description": "DNS çözücü",
//       "redirectUris": ["https://dns.fitfak.net/oauth/callback"],
//       "roles": ["reader", "writer"] }
//
// Yanıt İKİ sır taşır ve ikisi de BİR KEZ gösterilir:
//
//     clientSecret      -> IdP'ye konuşmak için        (FITFAK_OAUTH_CLIENT_SECRET)
//     enrolmentSecret   -> veritabanına kaydolmak için (FITFAK_ENROLMENT_SECRET)
//
// İkisi de bu uygulamanın KENDİ kimlik bilgileri. Eşleştirme dizininden okunabilir
// olsalardı, o makinedeki her süreç bu uygulama gibi konuşabilirdi -- o yüzden adresler
// keşfediliyor, sırlar keşfedilmiyor.
//
//
// SONRA: BU DOSYA
//
//     FITFAK_OAUTH_CLIENT_SECRET=... FITFAK_ENROLMENT_SECRET=... node examples/join-the-stack.js
//
// Kayıt sırrı YALNIZCA ilk çalıştırmada gerekli. Sertifika `.service-state/` altına yazılıyor
// ve sonraki açılışlar onu kullanıyor -- bu, kayıt sırrının gerçekten tek kullanımlık
// kalmasını sağlayan şey. Saklanmasaydı her yeniden başlatma yeniden kaydolmak zorunda kalır
// ve sır, yalnızca süreçler yeniden başladığı için kalıcı bir arka kapıya dönüşürdü.

const { joinFitfakWhenReady } = require('../client/join-fitfak');

const APPLICATION = process.env.FITFAK_APP_NAME || 'dns-resolver';

const log = {
  info: (o) => console.log('  ', JSON.stringify(o)),
  warn: (o) => console.warn('  !', JSON.stringify(o)),
  debug: () => {},
};

async function main() {
  console.log(`\n[1] '${APPLICATION}' yığına katılıyor`);

  // TEK ÇAĞRI. Altında olan biten şunlar ve her biri, elle yazıldığında atlanabilen bir adım:
  //
  //   * adresler ve kök sertifika eşleştirme dizininden okunuyor
  //   * saklanmış bir sertifika varsa KULLANILIYOR (kayıt sırrı harcanmıyor)
  //   * yoksa bir kez kaydolunuyor ve sertifika saklanıyor
  //   * yenileme otomatik başlıyor -- buradaki sertifikalar kısa ömürlü, yenilemeyen bir
  //     uygulama saatlerce çalışıp sonra bir TLS el sıkışma hatasıyla durur
  //   * veritabanı henüz IdP tarafından açılmadıysa BEKLENİYOR (`WhenReady`); mühürlü bir
  //     veritabanı bu mimaride normal bir açılış sıralamasıdır, arıza değil
  const app = await joinFitfakWhenReady({
    name: APPLICATION,
    roles: ['reader', 'writer'],
    logger: log,
  });

  console.log(`\n[2] Kimlik -- iki sistemde de AYNI`);
  console.log('   SPIFFE       :', app.spiffeId);
  console.log('   OAuth client :', app.name);
  console.log('   IdP          :', app.issuer);
  console.log('   güven alanı  :', app.trustDomain);
  console.log('   kök parmak izi:', app.rootFingerprint || '(eşleştirme dizini yok)');

  // Sertifika kendini yeniliyor ve bunu duyuruyor. Dinlemek zorunlu değil; kendi
  // sağlık göstergesine yazmak isteyen bir servis için burada.
  app.serviceIdentity?.on?.('renewed', (e) => {
    console.log('   sertifika yenilendi, geçerlilik:', new Date(e.notAfter).toISOString());
  });

  console.log('\n[3] Veri düzlemi -- mTLS üzerinden veritabanı');
  const records = app.db.collection('records');
  await records.insert({
    name: 'ornek.fitfak.net',
    type: 'A',
    value: '203.0.113.10',
    // Kaydı KİMİN yazdığı sertifikadan geliyor, uygulamanın beyanından değil. Aradaki fark,
    // bir denetim kaydının kanıt olup olmadığı.
    writtenBy: app.spiffeId,
    createdAt: BigInt(Date.now()),
  });
  const found = await records.findOne('name', 'ornek.fitfak.net');
  console.log('   yazıldı ve okundu:', found.name, '->', found.value);
  console.log('   yazan            :', found.writtenBy);

  console.log('\n[4] Kontrol düzlemi -- IdP\'ye belirteç sorma');
  //
  // Bu uygulama bir tarayıcıdan gelen isteği karşılarken, kullanıcının access token'ının
  // hâlâ geçerli olup olmadığını burada soruyor. JWT'nin kendi süresi dolmamış olsa BİLE
  // oturum iptal edilmişse cevap `active: false` -- imzayı yerel doğrulamakla arasındaki
  // fark tam olarak bu.
  const probe = await app.identity.introspectToken('gecersiz-ornek-belirtec');
  console.log('   uydurma belirteç aktif mi?', probe.active === true ? 'EVET (beklenmiyor!)' : 'hayır');

  // Yalnızca BU uygulamanın audience'ındaki oturumları görebiliyor: IdentityService,
  // istemci kimliğine göre kapsıyor, yani başka bir RP'nin oturumları sorulamıyor.

  console.log('\n[5] Kapanış');
  await app.close();
  console.log('   bağlantı kapatıldı, yenileme durduruldu');
  console.log('\nOK -- uygulama iki sisteme de tek kimlikle bağlandı.\n');
}

main().catch((err) => {
  // Hangi YARININ düştüğü söyleniyor. "Bağlanamadı" tek başına, veritabanının kapalı olması
  // ile OAuth sırrının yanlış olmasını aynı şeye benzetir; ikisi çok farklı iki iş.
  console.error(`\nBAŞARISIZ${err.half ? ` (${err.half} tarafı)` : ''}: ${err.message}`);
  if (err.cause) console.error(`  sebep: ${err.cause.message}`);
  process.exit(1);
});
