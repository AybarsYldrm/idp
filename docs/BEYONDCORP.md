# Kısa ömürlü kimlik mimarisi

BeyondCorp modelinde kimlik, kısa ömürlü sertifika üretimi, ve IdP ile veritabanı arasındaki
sıralama. Veritabanı tarafındaki mühürleme mekanizması için `@fitfak/database`'deki
`docs/ZERO-TRUST.md`.

---

## Temel fikir

> **Sertifika bir kimlik değildir. Doğrulanmış bir oturumun geçici bir yetkisidir.**

Klasik PKI'da sertifika kimliğin kendisidir: bir yıl yaşar, kimlik bilgisi olarak dolaşır ve
yanlış ellere geçtiğinde onu durdurmanın tek yolu iptaldir. İptalin çalışması için doğrulayıcının
CRL'i indirmiş ya da OCSP'ye ulaşabiliyor olması gerekir — yani iptal, ağın ve önbelleklerin izin
verdiği hızda yayılır. Pratikte bu saatlerdir.

BeyondCorp bunu tersine çevirir. Sertifika, kimliğin kanıtlandığı **anda** üretilir ve dakikalar
sonra kendiliğinden ölür. Bir kimlik bilgisinin çalınması hâlâ kötüdür, ama çalanın elindeki şey
beş dakika sonra hiçbir şeydir. İptal mekanizması artık "CRL yayılsın" değil, **yenilememek** — ve
yenilemeyi reddetmek anında etkilidir, çünkü karar üretim anında, tek bir yerde verilir.

Bunun getirdiği yükümlülük: **her yenilemede yetki yeniden doğrulanır.** Yenilemeyi "aynı şeyi bir
kez daha imzala" olarak ele almak, kısa ömürlülüğün tek faydasını yok eder — sertifika kısa yaşar
ama ardındaki karar bir yıl önce verilmiş olur. NIST SP 800-207'nin "sürekli doğrulama" ilkesi
budur ve `services/workload-identity-service.js`'teki `assertStillAuthorised` onun uygulandığı yer.

---

## Bileşenler

| Modül | Sorumluluğu | Kasıtlı olarak YAPMADIĞI |
|---|---|---|
| `core/ca-vault.js` | Kök ve ara CA'ları şifreli sır deposunda tutmak, amaca göre ayırmak | HSM olmak |
| `core/pki-issuer.js` | Politika: hangi profil ne kadar yaşar, hangi ara CA imzalar, kimlik nereye yazılır | Bayt üretmek (o `@fitfak/ssl`'in işi) |
| `core/certificate-profiles.js` | Saf profil tablosu | Kriptoya bağımlı olmak |
| `core/spiffe.js` | Kimlik biçimleri | İkinci bir ayrıştırıcı olmak (kaynak `@fitfak/database`) |
| `core/db-bootstrap.js` | CA deposunu açmak, veritabanını sağlamak, mTLS'e geçmek | Enrolment yapmak (IdP CA'nın kendisi) |
| `core/oauth-redirect.js` | Yönlendirme tutamakları, yapılandırılmış kodlar | Kodu tahmin edilemez yapmak (o rastgelelikten geliyor) |
| `services/workload-identity-service.js` | JIT üretim, sürekli doğrulama, anahtar tekilliği | İmzalamak |
| `services/certificate-service.js` | Uzun ömürlü sertifikalar, RBAC kapısı | Kısa ömürlüleri yönetmek |

---

## Sertifika otoritesi

### Anahtarlar nerede duruyor

Eskiden dört dosya:

```
.certs/root_ca.key   0600
.certs/root_ca.crt
.certs/sub_ca.key    0600
.certs/sub_ca.crt
```

Bu izinler korumanın **tamamıydı**. O kullanıcı olarak dosya sistemini okuyabilen her şey kök
anahtarı okur: bir yedekleme işi, bir konteyner imaj katmanı, bir yan konteynere bağlanmış birim,
fazla geniş bir glob ile çalışan bir log toplayıcı, `docker cp`, süreçteki başka bir yerdeki
dizin-aşımı hatası. Ve dosya otoritenin kendisi olduğu için, bir kopyası otoritenin bir
kopyasıdır — üstelik bunun olduğunu anlamanın bir yolu yoktur.

Artık aynı malzeme `secrets` koleksiyonunda bir kayıt: motorun DDK'sından türetilmiş bir anahtarla
diskte şifreli, sürümlenmiş, okuması diğer her kayıtla aynı kimlik doğrulamalı yoldan geçen. Veri
dizininin bir kopyası kök sır olmadan işe yaramaz.

**Dürüst olmak gerekirse bu bir HSM değildir.** Anahtar imzalarken bu sürecin belleğinde çözülür.
Canlı bir sürecin belleğini okuyabilen bir saldırganı tehdit modeline dahil ediyorsanız cevap,
anahtarı hiç dışarı vermeyen bir imzalayıcıdır (TPM/PKCS#11/KMS) — bunun daha zayıf bir sürümü
değil. Buradaki kazanç, çok daha yaygın olan başarısızlığı ortadan kaldırması: anahtarın, kimsenin
fark etmeden kopyalanabileceği bir dosyada *durması*.

### Neden birden fazla ara CA

Kök yalnızca ara CA imzalar. Geri kalan her şeyi bir ara CA imzalar ve her **amaç** için ayrı bir
ara CA vardır:

```
                        FITFAK Root CA G1
                               │
      ┌────────────┬───────────┼───────────┬──────────────┐
      ▼            ▼           ▼           ▼              ▼
 workload-ca   client-ca   server-ca   email-ca      signing-ca
 (workload)    (tls-client)(tls-server)(email)       (code-signing,
                                                     timestamping, ocsp)
```

Bir CA kısıtlanabilir (isim kısıtları, EKU kısıtları, yol uzunluğu) ve kısıtlar ancak
kısıtladıkları şey darsa bir anlam ifade eder. Her şeyi imzalayan tek bir ara CA hiçbir şeye
kısıtlanamaz. Ayrıca ele geçirilme sınırlanmış olur: iş yükü ara CA'sını emekliye ayırmak iş yükü
sertifikalarını geçersiz kılar ve e-posta sertifikalarına dokunmaz.

Her amaç için **tam olarak bir** aktif ara CA olmalıdır. İki tane olursa aynı türden iki talep
farklı zincirlere bağlanır ve birinin iptali nüfusun yarısını kapsar — o yüzden `findIssuerForPurpose`
iki aday bulduğunda bir tanesini seçmez, hata verir.

Admin panelinden yeni ara CA üretilebilir: `POST /admin/pki/authorities`.

### Neden CA uzak veritabanında değil

Bu bir tercih değil, bir kilitlenmenin çözümü:

```
veritabanı mühürlü açılır ve IdP ona bir sunucu sertifikası verene kadar kimseye hizmet etmez
    ↓
IdP o sertifikayı üretmek için CA'sına ihtiyaç duyar
    ↓
CA uzak veritabanındaysa IdP oraya bağlanmak zorundadır
    ↓
ama orası mühürlü
```

Her veritabanı yeniden başlatmasında bu kilit yeniden kurulurdu. O yüzden CA, IdP'nin yanında
duran **gömülü** bir fitdb örneğindedir (`.ca-store/`): aynı şifreleme, aynı sürümleme, aynı
erişim yolu — ama ağ yok, dolayısıyla bağımlılık yok. Uygulama verisi (kullanıcılar, oturumlar)
uzak veritabanında kalır.

---

## Sertifika profilleri

| Profil | Ömür | İmzalayan | SPIFFE zorunlu | Kullanım |
|---|---|---|---|---|
| `session` | 5 dk | client-ca | ✔ | Tarayıcıda oturum açmış kullanıcı |
| `workload` | 5 dk | workload-ca | ✔ | Arka uç servis, otomasyon |
| `device` | 10 dk | client-ca | ✔ | Kayıtlı cihaz |
| `service-identity` | 1 saat | client-ca | ✔ | Servisler arası mTLS |
| `client-auth` | 365 gün | client-ca | — | Klasik istemci sertifikası |
| `server-auth` | 90 gün | server-ca | — | TLS sunucu (ACME) |
| `smime` | 730 gün | email-ca | — | S/MIME |
| `code-signing` | 1095 gün | signing-ca | — | Kod/belge imzalama |

Ömür farkları amaca göre: bir imza, sertifikanın süresi dolduktan **sonra** da doğrulanabilir
olmalıdır (dolayısıyla uzun), bir oturum yetkisi ise oturumdan uzun yaşamamalıdır (dolayısıyla
dakikalar).

`service-identity` neden dakikalar değil saatler: bir arka uç servisi kendi kendini yeniler ve
yenileme başarısız olduğunda geri dönmek için zamana ihtiyaç duyar. Beş dakika, tek bir yavaş CA
turunu bir kesintiye dönüştürür.

### SPIFFE kimlik biçimleri

```
spiffe://fitfak.net/service/idp          uzun ömürlü sunucu tarafı iş yükü
spiffe://fitfak.net/workload/dns-resolver
spiffe://fitfak.net/device/<deviceId>
spiffe://fitfak.net/user/<userId>
spiffe://fitfak.net/session/<sessionId>  BeyondCorp'un asıl durumu
spiffe://fitfak.net/agent/<agentId>
```

Kimlik **SAN'daki URI'de** taşınır, CN'de değil. RFC 6125 §6.4.4 CN'i kimlik olarak on yıl önce
terk etti; birlikte çalışılmaya değer her iş yükü kimliği uygulaması (SPIRE, Istio) SAN'a bakar,
ve CN'e bakan bir yetkilendirme, başka hiçbir şeyin doğrulamadığı bir alana bakıyor demektir.

`session/<sessionId>` biçimi bilinçli: sertifika kullanıcının kendisini değil, o kullanıcının **bu**
oturumunu temsil eder. Oturum iptal edildiğinde sertifika yenilenmez ve kullanıcının diğer
oturumları etkilenmez.

---

## Üretim akışı

```
İstemci                                          trust.fitfak.net
   │
   │  1. YENİ anahtar çifti üret (her seferinde — asla yeniden kullanma)
   │  2. CSR oluştur
   │
   │  POST /identity/session/certificate  { csrPem }
   │  Cookie: oturum çerezi
   │ ──────────────────────────────────────────────▶│
   │                                                │  3. SÜREKLİ DOĞRULAMA
   │                                                │     ├ oturum hâlâ canlı mı?
   │                                                │     ├ hesap hâlâ etkin mi?
   │                                                │     └ cihaz hâlâ kayıtlı mı?
   │                                                │        herhangi biri hayırsa → 401/403
   │                                                │
   │                                                │  4. Kimliği TÜRET (istekten okuma!)
   │                                                │     spiffe://fitfak.net/session/<sid>
   │                                                │
   │                                                │  5. workload-ca / client-ca ile imzala
   │                                                │     notBefore = şimdi − 60 sn
   │                                                │     notAfter  = şimdi + 5 dk
   │                                                │
   │                                                │  6. SKID'i kaydet (tekillik)
   │                                                │     aynı anahtarla ikinci kez → 409
   │
   │  { certPem, chainPem, spiffeId, notAfter,      │
   │    renewAfter }   ← ömrün YARISI               │
   │ ◀──────────────────────────────────────────────│
   │
   │  7. renewAfter geldiğinde: 1'e dön (YENİ anahtar ile)
```

Kimliğin **isteğin içinden okunmaması** her üç ön yüzün de ortak özelliği:

- `issueForSession` — kimlik oturum çerezinden çözülen `sessionId`'den türer
- `issueForDevice` — kayıtlı `deviceId`'den türer
- `issueForWorkload` — jetondan **değil**, `WORKLOAD_REGISTRY` yapılandırmasından türer

Sonuncusu en kritik: bir erişim jetonu "bu çağıran yetkili" der, yapılandırma "neye yetkili" der.
İkisini birleştirip ismi jetondan okumak, keyfi bir `sub` üretebilen herkesin sistemdeki herhangi
bir kimliğe bürünebilmesi demek olurdu.

### Neden her seferinde yeni anahtar

Aynı anahtarı yeniden sertifikalandırmak, o anahtar bir kez sızdıysa sızıntıyı bir ömür daha
taşımaktır — yani kısa ömürlülüğün tek faydasını ortadan kaldırır. `workload_certificates`
tablosundaki `skidHex` kör indeksi bunu zorlar: **canlı** bir sertifikası olan bir açık anahtar
ikinci kez sertifikalandırılamaz.

Kontrolün "canlı" ile sınırlı olması bilinçli. Süresi üç gün önce dolmuş bir sertifikanın
anahtarının yeniden kullanılması kötü bir alışkanlıktır ama bir güvenlik sınırı değildir — o
sertifika zaten ölü. Kaydı süresiz tutmak ise, iki buçuk dakikada bir yenilenen bir filoda
sınırsız büyüyen bir tablo demek; süpürme (`sweepExpired`) bunu bir günle sınırlıyor.

---

## IdP ↔ veritabanı sıralaması

```
0. YEREL CA DEPOSU     IdP kök ve ara CA'larını açar (.ca-store/). Ağ yok.
                       │
1. SUNUCU KİMLİĞİ      IdP, VERİTABANI İÇİN bir TLS sunucu sertifikası üretir.
                       Kendi kimliği için de bir istemci sertifikası üretir —
                       CA kendisi olduğu için enrolment'a gerek yok.
                       │
2. DENETİM DÜZLEMİ     Mühürlü veritabanına bağlanır. İki taraf da paylaşılan
                       denetim sırrıyla kendini kanıtlar. Sertifika + anahtar +
                       güven çıpaları kurulur.
                       Veritabanı: SEALED → PROVISIONED (bellek içi, süre sınırlı)
                       │
3. mTLS                IdP kendi istemci sertifikasıyla geri bağlanır.
                       Veritabanı: PROVISIONED → OPEN
                       │
4. KARARLI DURUM       Diğer servisler enrolment ile girer. Veritabanı onların
                       sertifikalarını IdP'nin /pki/ra/issue ucundan ister;
                       kendisi hiçbir şey imzalamaz.
```

Adım 2 ile 3 arasında bir **süre sınırı** vardır. IdP orada takılırsa veritabanı malzemeyi siler
ve yeniden mühürlenir.

Adım 2'nin iki yönlü kimlik doğrulaması hayatidir: o mesaj bir **özel anahtar taşıyor**. Tek yönlü
olsaydı, araya giren biri IdP'nin veritabanı için ürettiği anahtarı teslim alır ve o andan sonra
veritabanını taklit edebilirdi. Ayrıntı `@fitfak/database`'deki `docs/ZERO-TRUST.md`'de.

### Kayıt otoritesi (RA) ucu

Veritabanı bir CA değildir ve olmamalıdır. Bağlanacak bir servisi doğrular, hangi kimliği
alabileceğine karar verir, ve imzayı IdP'ye sorar:

```
POST /pki/ra/issue
x-client-id: fitdb-registration-authority
x-client-secret: ...

{ "csrPem": "...", "spiffeId": "spiffe://fitfak.net/service/smtp", "subject": { "CN": "smtp-service" } }
```

IdP, RA'nın iddiasını olduğu gibi kabul **etmez**: her RA'nın vouch edebileceği SPIFFE yolu
yapılandırmada sınırlıdır (`FITFAK_IDP_RA_CLIENTS`). Aynı sınır veritabanı tarafında da var
(`spiffePrefix`), yani birindeki bir hata diğeri tarafından yakalanır. Bu kontrol olmadan
veritabanını ele geçirmek CA'yı ele geçirmekle aynı şey olurdu.

---

## Oturum açma yöntemleri

| Yöntem | Birinci faktör | İkinci faktör | Notlar |
|---|---|---|---|
| Parola (SRP-6a) | SRP — parola sunucuya hiç gelmez | TOTP / WebAuthn / e-posta kodu | Karmaşıklık kuralı istemcide (PAKE'nin bedeli) |
| Parolasız | WebAuthn + UV | — | UV tek başına possession + knowledge kanıtlar |
| WebAuthn (UV yok) | WebAuthn | TOTP ya da ikinci assertion | Tek başına yalnızca possession |
| Device code (RFC 8628) | Başka cihazda tam giriş | — | Kod artık URL'de taşınmıyor (aşağıya bkz.) |
| Makineler | OAuth 2.0 client credentials | — | `/identity/workload/certificate` |

### E-posta kurtarma kodu — çözdüğü somut sorun

Kullanıcı hesabını yalnızca WebAuthn ile korumuş. Anahtarı evdeki bilgisayarına bağlı. Başka bir
cihazdan girmeye çalışıyor. O cihazda anahtar **yok ve olmayacak**. Sonuç: parolasını bilse bile
hesabına giremiyor — ve bu, en güvenli yöntemi seçtiği için başına geliyor.

Bu faktör diğerlerinden **zayıftır** ve ona bir eşit gibi davranılmıyor:

- yalnızca doğrulanmış bir e-posta adresi olan hesaplarda çalışır
- parola faktörü zaten kanıtlanmış olmak zorunda (`mfaChallengeToken` gerekiyor) — tek başına bir
  giriş yolu değil, ikinci faktörün ikamesi
- kullanılan her seferinde kullanıcıya **ayrıca** bildirim gider
- dönen oturum `viaRecovery` işaretli gelir; giriş ekranı kullanıcıyı bu cihaza bir faktör
  eklemeye yönlendirir

Kod, kullanıcı açıkça istediğinde gönderilir — her ikinci faktör ekranında değil. Her girişte bir
e-posta göndermek, çoğu zaman kullanılmayacak bir kod için posta kutusunu doldurur ve gerçekten
önemli olan güvenlik bildirimlerini gürültünün içinde kaybeder.

### Device code: kod artık URL'de değil

RFC 8628 §3.3.1'in `verification_uri_complete` alanı, kullanıcının kodu elle yazmasını
gerektirmesin diye vardır — tipik olarak bir QR kodun içine konur. Ama kodu adrese koymak onu
adres çubuğuna, tarayıcı geçmişine, `Referer` başlığına ve omzunuzun üzerinden bakan herkese
koyar; ve o kod, onaylandığı anda bir oturuma dönüşecek olan şeydir.

```
öncesi:  https://session.fitfak.net/device?user_code=K7QM-P3XZ
sonrası: https://session.fitfak.net/device/link/9f2a...   ← tek kullanımlık, opak
```

`/device/link/<tutamak>` ilk açılışta **tüketilir**: sunucu kodu kısa ömürlü, `HttpOnly`,
`__Host-` önekli bir çereze koyar ve sorgu dizesi olmayan `/device`'a yönlendirir. QR akışı aynen
çalışır; sızan bir adres ikinci kez işe yaramaz. Onaydan sonra çerez de düşer.

---

## OAuth: yönlendirme tutamakları

Eskiden yetkilendirme isteği:

```
/oauth/authorize?client_id=dns&redirect_uri=https://example.com/oauth/callback&...
```

`redirect_uri` istemcinin **yazdığı** bir metindi ve sunucu onu kayıtlı adres listesiyle
karşılaştırıyordu. Karşılaştırma doğru yazılmıştı, ama şeklin kendisi iki şeyi davet ediyor:

1. Kayıt sırasında girilen örnek değer (`https://example.com/oauth/callback`) hiçbir zaman fark
   edilmiyor — ve `example.com` gerçekten kayıtlı bir alan adıdır, sahibi de siz değilsiniz.
2. Listeyle karşılaştırma bir **kontrol**. Kontroller unutulabilir, yanlış normalleştirilebilir,
   bir refactor'da atlanabilir. Açık yönlendirme zafiyetlerinin çoğu tam olarak burada doğar.

Artık her kayıtlı adresin bir **tutamağı** var:

```
/oauth/authorize?client_id=dns&ru=r1.k7Qm9xR2...&code_challenge=...
```

Fark yapısaldır: kayıtlı **olmayan** bir adres artık istekte *görünemez*. "Kayıtlı mı" kontrolü
bir `if` bloğu değil, bir veritabanı aramasının başarısız olması hâline gelir. RFC 6749
uyumluluğu için `redirect_uri` hâlâ kabul ediliyor — standart istemciler onu göndermek zorunda —
ama iki biçim de aynı kayda çözülür ve ikisi birden verilip farklı kayıtları gösterirlerse istek
reddedilir.

Kayıt sırasında reddedilenler: yer tutucu alan adları (`example.com`, `.invalid`, `your-app.com`
ve arkadaşları), joker karakterler, parça (`#`), kullanıcı bilgisi
(`https://kurban.com@saldirgan.com/`), ve yerel olmayan `http`.

### Yapılandırılmış yetkilendirme kodu

```
1.AQwAJTy6TH2ioEi_CAv2o-ijwi4...
│ └─ sürüm baytı ‖ istemci referansı (8B) ‖ yönlendirme referansı (8B) ‖ 32B rastgelelik
└─── sürüm etiketi
```

**Bu yapı güvenlik eklemez.** Kodun güvenliği tamamen (a) rastgele kısmın tahmin edilemezliğinden,
(b) tek kullanımlık olmasından ve (c) PKCE'den gelir. Yapının kazandırdığı şey operasyoneldir:
yanlış istemcinin gönderdiği bir kod depoya hiç gitmeden reddedilir, bir destek kaydındaki kod
hangi uygulamaya ait olduğunu söyler, ve sürüm öneki biçimi ileride kırmadan değiştirmeye izin
verir. Bunları güvenlik özelliği gibi sunmak yanlış olurdu.

---

## Tehdit modeli

**Kapsam içinde**

| Tehdit | Karşılık |
|---|---|
| Sertifika çalınması | 5 dakikada geçersizleşir; iptalin yayılmasını beklemez |
| Yetki geri alındıktan sonra erişimin sürmesi | Her yenilemede sürekli doğrulama; yenilenmeme dakikalar içinde etkili |
| Sızmış bir anahtarın ömrünü uzatma | Canlı sertifikası olan anahtar ikinci kez sertifikalandırılamaz |
| Çağıranın kendine kimlik seçmesi | Kimlik doğrulanmış bağlamdan türer, istekten okunmaz |
| Jeton üretebilen birinin herhangi bir kimliğe bürünmesi | İş yükü adı yapılandırmadan, jetondan değil |
| RA'nın ele geçirilmesinin CA'yı ele geçirmesi | Her RA'nın SPIFFE yolu iki tarafta da sınırlı |
| Başka güven alanı için sertifika üretimi | `_resolveSpiffeId` reddeder |
| Kök anahtarın dosya kopyasıyla sızması | Şifreli sır deposunda; disk kopyası kök sır olmadan işe yaramaz |
| Açık yönlendirme | Kayıtlı olmayan adres istekte görünemez |
| Yetkilendirme kodunun çalınması | Tek kullanımlık + 60 sn + PKCE (S256 zorunlu) |
| Cihaz kodunun adres çubuğundan sızması | Tek kullanımlık opak tutamak, `HttpOnly` çerez |
| WebAuthn kullanıcısının kilitlenmesi | E-posta kurtarma kodu (bildirimli, işaretli) |
| Kullanıcı numaralandırma | Kayıt/sıfırlama yanıtları hem içerik hem süre olarak aynı |

**Kapsam dışı, açıkça**

- **Canlı sürecin bellek dökümü.** CA anahtarı imzalarken bu sürecin belleğinde çözülür. Cevap
  TPM/PKCS#11/KMS'tir, farklı bir depo değil.
- **E-posta hesabının ele geçirilmesi.** Kurtarma yolu oradan geçer. Bu yüzden ayrı bildirim
  gönderiliyor ve oturum işaretleniyor — engellenemiyor, ama görünür kılınıyor.
- **Kullanıcının cihazının ele geçirilmesi.** Kısa ömürlü sertifika, cihazdaki bir saldırganın
  yenileme yapmasını engellemez.
- **Trafik analizi.** Kör indeksler değerleri gizler, erişim desenlerini değil.

### Tekrar (replay) analizi

| Yakalanan | Neden tekrar edilemez |
|---|---|
| Yetkilendirme kodu | Tek kullanımlık (sonuç ne olursa olsun tüketilir), 60 sn, PKCE doğrulayıcısı olmadan işe yaramaz |
| Cihaz bağlantı tutamağı | İlk açılışta tüketilir |
| E-posta kurtarma kodu | 10 dk, 5 deneme, başarıda tüketilir |
| Kısa ömürlü sertifika | 5 dk sonra doğrulanmaz |
| Denetim düzlemi mesajları | Nonce + zaman damgası + TLS exporter bağlaması (bkz. `docs/ZERO-TRUST.md`) |
| Enrolment kanıtı | Aynı yapı, artı CSR parmak izi — geçerli bir kanıt başka bir açık anahtarla eşleştirilemez |

Uygulama katmanı tekrarı DTLS/TLS sıra numaralarına ve oturum yönetimine bırakılıyor,
sertifikanın içine kodlanmıyor — sertifikaya standart dışı anlam yüklemek, tam olarak kaçınılan
şey.

---

## Önerilen varsayılanlar

| Ayar | Değer | Gerekçe |
|---|---|---|
| Oturum/iş yükü sertifikası ömrü | 5 dk | İptalin yayılma süresinden kısa |
| Cihaz sertifikası ömrü | 10 dk | Aynı, biraz daha az gürültü |
| Servis kimliği ömrü | 1 saat | Yenileme hatası için geri dönüş payı |
| Yenileme zamanı | Ömrün %50'si | %66, 5 dk'lık sertifikada 100 sn bırakır — tek bir yavaş tur kesinti demek |
| `notBefore` geri tarihleme | 60 sn | Saati bir saniye geride olan doğrulayıcı reddetmesin |
| Kısa ömür alt/üst sınır | 60 sn / 1 saat | Altı geri tarihlemeyle örtüşür, üstü iptalle yarışmayı bırakır |
| Kayıt saklama | 24 saat | Tekillik penceresi + olay incelemesi; sonrası süpürülür |
| Kısa ömürlülerde CT | Kapalı | 5 dk'lık bir sertifika log'a yazıldığında zaten ölmek üzere; önsertifika turu üretimi ikiye katlar |
| TLS | 1.3 | Kanal bağlaması exporter'a dayanıyor |
| PKCE | S256 zorunlu | `plain` kabul edilmiyor |

---

## Kullanım

### Tarayıcıda: oturum kimliği

```js
// 1. HER SEFERİNDE yeni anahtar çifti
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
const csrPem = await buildCsr(keyPair);

// 2. Kısa ömürlü sertifika iste
const res = await fetch('https://trust.fitfak.net/identity/session/certificate', {
  method: 'POST',
  credentials: 'include',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ csrPem }),
});
const { certPem, chainPem, spiffeId, renewAfter } = await res.json();

// 3. renewAfter geldiğinde 1'e dön — YENİ anahtarla
setTimeout(rotate, new Date(renewAfter) - Date.now());
```

### Arka uç servis: iş yükü kimliği

```js
const res = await fetch('https://trust.fitfak.net/identity/workload/certificate', {
  method: 'POST',
  headers: {
    authorization: `Bearer ${accessToken}`,      // scope: identity:workload
    'content-type': 'application/json',
  },
  body: JSON.stringify({ workloadName: 'dns-resolver', instanceId: process.env.POD_NAME, csrPem }),
});
// → spiffe://fitfak.net/workload/dns-resolver/<instance>, 5 dakika
```

`workloadName` yapılandırmada kayıtlı olmak zorunda (`FITFAK_IDP_WORKLOADS`). Jeton mükemmel olsa
bile kayıtlı olmayan bir isim reddedilir.

### Uygulamanın veritabanına bağlanması

Diğer uygulamalar için hiçbir şey değişmiyor — IdP'den normal şekilde `client.crt`/`key` alıp
bağlanıyorlar. Tek fark, IdP ayağa kalkmadan önce denerlerse `FAILED_PRECONDITION` almaları ve
hata mesajının sebebi söylemesi.

```js
const { enroll, connectDatabase } = require('@fitfak/database');

const identity = await enroll({
  target: 'https://db.fitfak.net:51572',
  serviceName: 'dns-resolver',
  csrProvider: createFitfakSslCsrProvider(),
  trust: { pinnedFingerprints: [rootFingerprint] },
  // Sır yerine IdP jetonu: IdP ayaktayken tercih edilen yol.
  bootstrap: { token: accessToken },
  altNames: ['spiffe://fitfak.net/service/dns-resolver'],
});
identity.startAutoRenewal();

const handle = await connectDatabase({ target, identity });
const db = await handle.openDatabase({ dbId, clientSecret });
```

### Yeni bir ara CA üretmek

```bash
curl -X POST https://one.fitfak.net/admin/pki/authorities \
  -H 'content-type: application/json' \
  -d '{ "name": "partner-ca",
        "commonName": "FITFAK Partner Federation CA G1",
        "purposes": ["tls-client"] }'
```

Bir amaç için ikinci bir aktif ara CA üretmek, o amacın çözümlenmesini belirsiz kılar ve
`findIssuerForPurpose` hata verir. Önce eskisini emekliye ayırın.

---

## Ortam değişkenleri

| Değişken | Zorunlu | Açıklama |
|---|---|---|
| `FITFAK_IDP_DB_SECRET` | ✔ | Veritabanı kök sırrı. CA deposunun şifrelemesi de buradan türer. |
| `FITFAK_IDP_REDIRECT_HANDLE_SECRET` | ✔ | Yönlendirme tutamaklarının türetildiği sır. Değiştirmek tüm tutamakları değiştirir. |
| `FITFAK_IDP_DB_CONTROL_SECRET` | uzak modda ✔ | Veritabanının denetim düzlemi sırrı. `db-server.js` açılışta yazdırır. |
| `FITFAK_TRUST_DOMAIN` | — | Varsayılan `fitfak.net`. |
| `FITFAK_IDP_CA_STORE_DIR` | — | CA deposu; varsayılan `.ca-store`. |
| `FITFAK_IDP_CA_DIR` | — | ESKİ dosyalar; yalnızca bir kereliğine içe aktarma için okunur. |
| `FITFAK_IDP_DB_SERVER_NAMES` | — | Veritabanı için üretilecek sertifikanın SAN'ları. |
| `FITFAK_IDP_WORKLOADS` | — | İş yükü adı → gerekli kapsam eşlemesi (JSON). |
| `FITFAK_IDP_RA_CLIENTS` | — | Kayıt otoritesi → izin verilen SPIFFE yolu (JSON). |

---

## Göç: dosyadan kasaya

İlk açılışta `.certs/root_ca.key` ve `.certs/sub_ca.key` varsa otomatik olarak kasaya alınır.
**Dosyalar silinmez** — içe aktarmanın çalıştığını kimse doğrulamadan bir kök anahtarın tek
kopyasını silen bir göç, bir PKI'yı kaybedebilen bir göçtür.

Doğruladıktan sonra elle:

```bash
shred -u .certs/root_ca.key .certs/sub_ca.key
```

Silmeden önce `FITFAK_IDP_DB_SECRET`'ın yedeğinin olduğundan emin olun — o sır olmadan kasadaki
anahtar da okunamaz.

Eski ara CA'ya kasaya girerken **hiçbir amaç atanmaz**: hâlâ geçerli olan sertifikalar
doğrulanabilir kalsın diye zincirde durur, ama yeni talepler amaca göre ayrılmış yeni ara CA'lara
gider. Ona eski geniş yetkisini vermek, ayrımı ilk günden anlamsız kılardı.

---

## SPIFFE/SPIRE'a geçiş

Kimlik modeli SPIFFE'nin kendisi, bir yaklaşımı değil: gramer SPIFFE-ID şartnamesine göre
doğrulanıyor (nokta segmentleri, yüzde kodlaması ve kanonik olmayan yazımlar dahil — çoğu
uygulamanın kaçırdığı yerler), kimlik URI SAN'da duruyor, güven alanı birinci sınıf bir alan.

SPIRE'a geçmek **üretim** tarafını değiştirir (attestor'lar ve CA backend'i); **doğrulayan** taraf
(`subjectField: 'spiffe'` ile `createPrincipalResolver`) değişmeden çalışmaya devam eder, çünkü
zaten standart bir SPIFFE SVID okuyor.

SPIFFE uyumlu **olmayan** ve bilerek öyle olan kısım: enrolment protokolü bu yığının kendisi,
SPIRE'ın Node/Workload API'si değil. SPIRE'a geçmek onu değiştirir. Bu boyuttaki bir dağıtım için
makul bir takas, ve SPIFFE biçimli kimlik sayesinde değişiklik, bir kimliği *tüketen* hiçbir şeye
dokunmak zorunda kalmıyor.
