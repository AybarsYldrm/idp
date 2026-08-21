'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { joinFitfak, JoinError } = require('../client/join-fitfak');
const { IdentityClient } = require('../client/identity-client');
const pairing = require('../core/pairing');

// BİR UYGULAMANIN İKİ SİSTEME DE TEK KİMLİKLE BAĞLANMASI.
//
// İki yarısı da zaten vardı: @fitfak/database'in `joinAsService()` veritabanı tarafını,
// client/identity-client.js IdP tarafını çözüyordu. Eksik olan, ikisinin AYNI KİMLİK altında
// birleştiği yerdi -- ve o boşluk gerçek bir hataya yol açtı:
//
//   IdP, uygulamayı TEK bir adla kaydediyor ve SPIFFE kimliğini o addan türetiyor
//   (`spiffe.build(trustDomain, 'service', name)`, ad olduğu gibi). Uygulama tarafı ise adın
//   `-service` ekini KIRPIYORDU. Yani `smtp-service` adlı bir uygulama için IdP
//   `spiffe://…/service/smtp-service` veriyor, uygulama `…/service/smtp` istiyor ve kayıt
//   servisi -- verilenden başka bir kimlik istendiği için -- reddediyordu.
//
// Tek adla kaydın bütün amacı elle tutturulacak bir şey bırakmamaktı; bir taraftaki tek bir
// düzenli ifade onu geçersiz kıldı. Buradaki kontroller o tekliği sınıyor.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

async function rejects(label, fn, matcher = null) {
  let err = null;
  try { await fn(); } catch (e) { err = e; }
  check(label, err !== null && (!matcher || matcher.test(err.message)));
  return err;
}

function tmpDir(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

async function main() {
  console.log('\n1. Ad, üç sistemin de kabul ettiği biçimde olmalı');

  {
    for (const bad of ['', 'Buyuk-Harf', 'a', 'nokta.li', 'bosluk li', '-onde-tire']) {
      // eslint-disable-next-line no-await-in-loop
      await rejects(`'${bad}' reddediliyor`, () => joinFitfak({ name: bad }), /uygulama adı|ÜÇ yerde/);
    }
    const err = await rejects('gerekçe söyleniyor', () => joinFitfak({ name: 'A' }));
    check('üç kullanım yerini de sayıyor',
      /OAuth/.test(err.message) && /veritabanı/.test(err.message) && /SPIFFE/.test(err.message));
  }

  console.log('\n2. Hiçbir yarıya bağlanmayan bir katılım yok');

  {
    await rejects('ikisi de kapalıysa reddediliyor',
      () => joinFitfak({ name: 'dns-resolver', needsDatabase: false, needsIdp: false }),
      /katılacak bir şey yok/);
  }

  console.log('\n3. Adresler KEŞFEDİLİYOR, sırlar keşfedilmiyor');

  {
    const dir = tmpDir('join-pair-');
    await pairing.publishIdp({
      dir,
      issuer: 'https://session.fitfak.net',
      issuanceUrl: 'https://trust.fitfak.net/pki/ra/issue',
      anchorsUrl: 'https://trust.fitfak.net/pki/ra/anchors',
      raClientId: 'ra', raClientSecret: 'ra-secret',
      panelClientId: 'panel', panelClientSecret: 'panel-secret',
      rootFingerprint: 'AA:BB', rootCertPem: '-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n',
      trustDomain: 'fitfak.net',
    });

    // Adres eşleştirme dizininden geliyor; eksik olan tek şey uygulamanın KENDİ sırrı.
    const err = await rejects('adres bulunuyor, sır bulunmuyor',
      () => joinFitfak({
        name: 'dns-resolver', needsDatabase: false, pairingDir: dir, oauthClientSecret: '',
      }),
      /OAuth istemci sırrı yok/);
    check('hata adresi DEĞİL sırrı işaret ediyor', !/adresi bilinmiyor/.test(err.message));
    check('sırrın nereden geldiğini söylüyor', /yönetim panelinde.*bir kez/i.test(err.message));
    // Paylaşılan bir dizinden okunabilen bir sır, o makinedeki her sürecin sırrıdır.
    check('ve neden keşfedilmediğini', /her süreç/.test(err.message));

    // Sır elde varken IdP yarısı tek başına kuruluyor: bir uygulama yalnızca belirteç
    // doğrulamak için de bağlanabilmeli, veritabanına hiç dokunmadan.
    const app = await joinFitfak({
      name: 'dns-resolver',
      needsDatabase: false,
      pairingDir: dir,
      oauthClientSecret: 'oauth-secret',
    });
    check('IdP yarısı tek başına kurulabiliyor', app.identity instanceof IdentityClient);
    check('adres keşfedildi', app.issuer === 'https://session.fitfak.net');
    check('güven alanı keşfedildi', app.trustDomain === 'fitfak.net');
    check('OAuth istemci kimliği ADIN kendisi', app.identity.clientId === 'dns-resolver');
    check('veritabanı istenmediği için yok', app.db === null && app.handle === null);

    // Kök sertifika güven ÇIPASI olarak geçiyor. Geçmeseydi, IdP'nin sertifikası bu
    // dağıtımın kendi kökünden çıktığı için her çağrı sertifika hatasıyla düşerdi.
    check('kök sertifika istemciye çipa olarak veriliyor',
      typeof app.identity.ca === 'string' && app.identity.ca.includes('BEGIN CERTIFICATE'));
    check('ve çağırana da bildiriliyor', app.trustAnchorsPem === app.identity.ca);
    check('kök parmak izi taşınıyor', app.rootFingerprint === 'AA:BB');
    await app.close();
  }

  console.log('\n4. Adres hiçbir yerden çıkmıyorsa bunu söylüyor');

  {
    const empty = tmpDir('join-empty-');
    const err = await rejects('adres yoksa hata',
      () => joinFitfak({
        name: 'dns-resolver', needsDatabase: false, pairingDir: empty, oauthClientSecret: 's',
      }),
      /adresi bilinmiyor/);
    check('eşleştirme dizinini adıyla gösteriyor', err.message.includes(pairing.pairingDir(empty)));
    check('ve açık ayarın adını veriyor', /FITFAK_IDP_ISSUER/.test(err.message));
    check('hangi yarı olduğu işaretli', err.half === 'idp');
  }

  console.log('\n5. TEK AD -- SPIFFE kimliği iki tarafta da aynı');

  {
    // ASIL KONTROL. IdP'nin türettiği ile uygulamanın istediği aynı olmalı. Ayrıştıkları hâl
    // gerçekten yaşandı ve `-service` ile biten HER uygulamayı etkiliyordu.
    const { spiffe } = require('@fitfak/database');
    const registry = require('../core/application-registry');
    const dir = tmpDir('join-name-');
    await pairing.publishIdp({
      dir, issuer: 'https://session.fitfak.net', trustDomain: 'fitfak.net',
      issuanceUrl: '', anchorsUrl: '', raClientId: '', raClientSecret: '',
      panelClientId: '', panelClientSecret: '', rootFingerprint: '', rootCertPem: '',
    });

    for (const name of ['smtp-service', 'dns-resolver', 'tunnel']) {
      // IdP'nin kaydederken ürettiği (core/application-registry.js ile aynı ifade)
      const granted = spiffe.build('fitfak.net', 'service', name).uri;
      // Uygulamanın bağlanırken beklediği
      // eslint-disable-next-line no-await-in-loop
      const app = await joinFitfak({
        name, needsDatabase: false, pairingDir: dir, oauthClientSecret: 's',
      });
      check(`'${name}': ${granted}`, app.spiffeId === granted);
      // Ve veritabanı tarafının türettiği de aynı olmalı -- üç ifade, tek sonuç.
      check(`'${name}': veritabanı tarafı da aynı`, spiffe.forService('fitfak.net', name).uri === granted);
      // eslint-disable-next-line no-await-in-loop
      await app.close();
    }

    // Kayıt defterinin ad kuralı ile buradaki kural aynı olmalı: biri diğerinin kabul ettiği
    // bir adı reddederse, panelde kaydedilebilen ama bağlanamayan bir uygulama olur.
    check('ad kuralı kayıt defteriyle aynı', registry.ApplicationRegistry !== undefined);
  }

  console.log('\n6. Bekleyen biçim ayrı bir seçenek');

  {
    const source = fs.readFileSync(path.join(__dirname, '..', 'client', 'join-fitfak.js'), 'utf8');
    // Yanlış yapılandırıldığında ÇIKMASI gereken bir araç ile ilk başlatılabilmesi gereken
    // uzun ömürlü bir servis farklı şeyler istiyor. İkisini tek davranışa indirmek, birinin
    // ya hiç başlamamasına ya sessizce dönmesine yol açardı.
    check('joinFitfakWhenReady var', /function joinFitfakWhenReady/.test(source));
    check('ve neden ayrı olduğu yazılı', /Ayrı bir seçenek/.test(source));
    // Sır okumak eşleştirme dizininden YAPILMAMALI ve bu bir kural olarak yazılı olmalı.
    check('sırların keşfedilmediği yazılı', /SIRLAR ORADAN OKUNMUYOR/.test(source));
  }

  console.log('\n7. Hata hangi yarıda olduğunu söylüyor');

  {
    const err = new JoinError('x', { half: 'database' });
    check('JoinError yarıyı taşıyor', err.half === 'database');
    // "Bağlanamadı" tek başına, veritabanının kapalı olması ile OAuth sırrının yanlış olmasını
    // aynı şeye benzetir; ikisi çok farklı iki iş.
    const dbErr = await rejects('veritabanı yarısı işaretleniyor',
      () => joinFitfak({
        name: 'dns-resolver',
        needsIdp: false,
        stateDir: tmpDir('join-nodb-'),
        pairingDir: tmpDir('join-nopair-'),
        enrolmentSecret: '',
      }));
    check('half === database', dbErr.half === 'database');
  }

  console.log(`\nOK - yığına katılma: ${checks} kontrol geçti.`);
}

main().catch((e) => { console.error('\nFAILED:', e.message); process.exit(1); });
