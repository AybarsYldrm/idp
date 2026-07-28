# Çalıştırma

İki süreç var: veritabanı ve IdP. Sıra önemli — IdP, veritabanına bağlanmadan
açılmaz.

## 0. Bağımlılıklar

`@fitfak/idp` üç kardeş pakete bağlıdır. Yayınlanana kadar yan yana checkout
ve symlink:

```sh
mkdir -p node_modules/@fitfak
ln -s /path/to/ssl       node_modules/@fitfak/ssl
ln -s /path/to/database  node_modules/@fitfak/database
ln -s /path/to/grpc      node_modules/@fitfak/grpc
ln -s /path/to/qr        node_modules/@fitfak/qr
```

Node 20+.

## 1. Veritabanı sunucusu

Sunucunun bir TLS kimliği olmak zorunda. **Yumurta-tavuk sorununun kırıldığı
yer burası**: IdP kendini kanıtlayamaz çünkü sertifikası yoktur, ama bağlanacağı
sunucuyu doğrulamak ZORUNDADIR — yoksa enrolment kanıtını o adresi dinleyen
herkese vermiş olur. Zincirin bu ucu, karşı tarafa hiç soru sormadan
doğrulanabilir olmalı.

```js
const {
  createDatabaseServer, createSharedSecretAttestor, createRenewalAttestor,
  createCompositeAttestor, createIdpTokenAttestor, generateEnrolmentSecret,
  createFitfakSslCaBackend,
} = require('@fitfak/database');
const ssl = require('@fitfak/ssl');

const ca = ssl.CertificateAuthority.create({ useIntermediate: true, organization: 'FITFAK', country: 'TR' });
const idpSecret = generateEnrolmentSecret();     // BİR KEZ üretin, IdP'ye elden verin
console.log('FITFAK_IDP_DB_ENROLMENT_SECRET =', idpSecret.toString('base64'));
console.log('FITFAK_IDP_DB_CA_FINGERPRINT   =', ca.ca ? ca.ca.fingerprint256 : '(CA parmak izi)');

const server = createDatabaseServer({
  baseDir: '/var/lib/fitdb',
  principals: { 'idp-service': { roles: ['admin'] } },
  enrollment: {
    caBackend: createFitfakSslCaBackend({ ca, ssl }),
    attestor: createCompositeAttestor([
      // İlk halka: IdP henüz yokken kimlik soracak kimse yok.
      createSharedSecretAttestor({
        enrolments: {
          'idp-service': {
            secret: idpSecret, subject: { CN: 'idp-service' },
            altNames: ['idp-service'], roles: ['admin'], maxUses: 1,
          },
        },
      }),
      // IdP ayağa kalktıktan SONRA: her yeni servis kimliğini ondan alır.
      createIdpTokenAttestor({
        introspectionUrl: 'https://session.fitfak.net/oauth/introspect',
        clientId: process.env.DB_OAUTH_CLIENT_ID,
        clientSecret: process.env.DB_OAUTH_CLIENT_SECRET,
        services: {
          'dns-resolver': { requiredScope: 'service:enrol', subject: { CN: 'dns-resolver' }, roles: ['reader'] },
        },
      }),
      createRenewalAttestor({ roleResolver: () => ['admin'] }),
    ]),
  },
});

server.listen(8443, { host: '0.0.0.0', tls: serverTlsOptions });
```

`requestCert: true, rejectUnauthorized: false` tek portun iki kanalı birden
sunmasını sağlar: sertifikası olmayan istemci el sıkışmayı tamamlar, ama
`EnrollmentService` dışındaki her şey `mtls` ister ve transport bunu handler
çalışmadan ÖNCE uygular.

## 2. IdP

```sh
# Zorunlu
export FITFAK_IDP_DB_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
export FITFAK_IDP_DB_TARGET=https://db.internal.fitfak.net:8443
export FITFAK_IDP_DB_CA_FINGERPRINT='AA:BB:...'      # ya da FITFAK_IDP_DB_CA_PATH

# YALNIZCA ilk çalıştırmada
export FITFAK_IDP_DB_ENROLMENT_SECRET='...'

# E-posta (doğrulama kodları ve güvenlik uyarıları için)
export SMTP_HOST=mail.fitfak.net SMTP_USER=network@fitfak.net SMTP_PASS='...'

# Dinleme adresleri
export FITFAK_IDP_BIND_IDP=127.0.0.1        # session.fitfak.net
export FITFAK_IDP_BIND_TRUST=127.0.0.2      # trust.fitfak.net
export FITFAK_IDP_BIND_ADMIN=127.0.0.3      # one.fitfak.net
export FITFAK_IDP_BIND_STATUS=31.58.245.241 # status. / time.trust.fitfak.net

node oauth-server.js
```

İlk açılışta: bootstrap TLS → güven çıpaları → enrolment → mTLS. Sertifika
`.identity/` altına yazılır (0600). **Bundan sonra
`FITFAK_IDP_DB_ENROLMENT_SECRET` ortamdan kaldırılabilir**: sonraki açılışlar
diskteki sertifikadan devam eder, yenileme mTLS üzerinden yapılır. Sır gerçekten
tek kullanımlıktır (`maxUses: 1`) ve bu, ancak yeniden başlatma onu harcamadığı
için mümkün.

## `.identity/` dizinini yedekleyin

İki dosya var ve ikisi de 0600:

| Dosya | İçerik | Kaybolursa |
|---|---|---|
| `identity.json` | mTLS sertifikası ve özel anahtar | Yeniden enrolment gerekir (yeni bir sır) |
| `database.json` | `dbId` + veritabanı istemci sırrı | **Veritabanı bir daha AÇILAMAZ** |

İkincisi kritiktir: istemci sırrı sunucuda SAKLANMAZ, veritabanı oluşturulurken
bir kez döner. Bu dosyayı yedeklemeden `.identity/` dizinini silmeyin.

## Yüzeyler

Her mantıksal host AYRI bir adrese bağlanır. Ayrım Host header'ıyla değil soket
seviyesinde yapılır — Host, istemcinin yazdığı bir dizedir.

| Adres | Host | Ne sunar |
|---|---|---|
| 127.0.0.1:80 | session.fitfak.net | `/login` `/portal` `/profile` `/consent` `/cookies` OAuth, oturum |
| 127.0.0.2:80 | trust.fitfak.net | ACME, `/device/certificate`, `/policy`, `/ct/v1/*` |
| 127.0.0.3:80 | one.fitfak.net | `/admin*` — yalnızca burada |
| 31.58.245.241:80 | status.trust.fitfak.net | `/ocsp` `/crl` `/crl/root` CA yayını |
| 31.58.245.241:80 | time.trust.fitfak.net | RFC 3161 TSA (ayrı süreç, bkz. `@fitfak/ssl/examples/timestamp-server.js`) |

`status.` ve `time.` düz HTTP'dir ve öyle olmalıdır: bunlar sertifikaların
içindeki AIA/CDP adresleridir. HTTPS olsaydı, bir sertifikanın iptal durumunu
sorgulamak için önce başka bir sertifikayı doğrulamak gerekirdi.

`one.fitfak.net` ayrı adreste olduğu için güvenlik duvarıyla dışarıya tamamen
kapatılabilir. Aynı porttaki bir yol olsaydı, tüm koruma `requireAdmin`
kontrolüne bağlı kalırdı.

## Testler

```sh
npm test                  # hepsi
npm run test:srp          # SRP-6a: kripto, tarayıcı eşdeğerliği, uç noktalar
npm run test:device       # cihaz bağlama, oturum tazeleme
npm run test:ct           # Certificate Transparency
npm run test:revocation   # OCSP/CRL zinciri (openssl ile doğrulanır)
npm run test:redirect     # açık yönlendirme
npm run test:routing      # temiz URL'ler, kimlik kapıları
npm run test:admin        # yüzey ayrımı
npm run test:image        # görsel yükleme saldırıları
npm run test:profile      # profil, hesap silme
npm run test:consent      # OAuth onay ekranı, kapsam sınırları, prompt=none
npm run test:cookies      # çerez kategorileri (zorunlu / istatistik)
npm run test:hardening    # köken kapısı (CSRF), kullanıcı kotası
npm run test:db           # IdP <-> veritabanı, canlı gRPC sunucusuna karşı
```

`pki-acme-demo`'nun ACME bölümü, 127.0.0.1'e çözümlenen bir `*.fitfak.net` adı
ister: http-01 doğrulaması GERÇEK bir DNS çözümlemesi yapar ve ACME servisi
politika gereği yalnızca `*.fitfak.net` kabul eder. Böyle bir ad yoksa o bölüm
sebebini yazıp atlanır — testin geri kalanı (sertifika, RBAC, iptal, OCSP, CRL)
her durumda koşar. Tam akışı çalıştırmak için:

```sh
echo '127.0.0.1 acme-test.fitfak.net' | sudo tee -a /etc/hosts
node test/pki-acme-demo.js
```

`mtls-demo` ve `http-transport-demo` TLS materyali gerektirdiği için bu ortamda
çalışmaz.

## Önce yapılması gerekenler

`SECURITY-ROTATION.md` — depoya işlenmiş üç canlı kimlik bilgisi ve hâlâ takipli
olan `certs/ca.key`. Sonuncusu bir CA anahtarıdır: depoyu okuyabilen herkes
istediği common name'i taşıyan bir istemci sertifikası üretebilir, ve
veritabanının kimlik modeli tam olarak o adı principal sayar. Kod tarafı
temizlendi; rotasyon kod değişikliğiyle çözülmez.
