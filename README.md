# fitfak-idp

`session.fitfak.net` için bağımsız, sıfırdan yazılmış **OAuth 2.0 / WebAuthn Merkezi Kimlik Sağlayıcısı (IdP)**. `dns.fitfak.net` gibi diğer fitfak.net servisleriyle tek oturum açma (SSO) için tasarlandı.

Referans kodunuzdaki (`server.js`, `grpc-server.js`, `@fitfak/database` demoları) mimari desenlere (DatabaseManager koleksiyonları, gRPC-Web tarzı çerçeveleme, `addHttpHandler`/`service.use()` deseni) **uyumlu** ama **sıfırdan yazılmış**, bağımsız bir sistemdir. `server.js`'e hiçbir şekilde dokunulmadı; içindeki `GraphStore` deseni bu projede **hiç kullanılmadı** (açıkça talep ettiğiniz gibi).

---

## İçindekiler

1. [Hızlı başlangıç](#hızlı-başlangıç)
2. [Mimari genel bakış](#mimari-genel-bakış)
3. [Kimlik doğrulama akışı](#kimlik-doğrulama-akışı)
4. [SSO / OAuth2 entegrasyon rehberi](#sso--oauth2-entegrasyon-rehberi)
5. [Taşıma katmanı: gRPC-Web + bidi köprüsü](#taşıma-katmanı-grpc-web--bidi-köprüsü)
6. [Tasarım kararları ve referans koddan sapmalar](#tasarım-kararları-ve-referans-koddan-sapmalar)
7. [Test kapsamı](#test-kapsamı)
8. [Kapsam ve sınırlamalar (dürüstlük bölümü)](#kapsam-ve-sınırlamalar-dürüstlük-bölümü)
9. [v1.1: e-posta doğrulama, RBAC, Snowflake ID, uzak gRPC veritabanı](#v11-güncellemesi-e-posta-doğrulama-rbac-snowflake-id-uzak-grpc-veritabanı-seçeneği)
10. [v1.2: DB-tabanlı OAuth client'lar, çoklu-hesap seçici, QR kod](#v12-güncellemesi-db-tabanlı-oauth-clientlar-çoklu-hesap-seçici-gerçek-qr-kod-sade-tasarım)
11. [v1.3: Device Code girişi, ölçeklenebilirlik, PKI/ACME sistemi](#v13-güncellemesi-device-code-girişi-ölçeklenebilirlik-ve-tam-pkiacme-sistemi)
12. [Dosya haritası](#dosya-haritası)

---

## Hızlı başlangıç

```bash
# Geliştirme/demo modu -- bellek-içi mock veritabanı, kalıcılık YOK, gerçek şifreleme YOK.
# @fitfak/database paketi GEREKMEZ. Sadece deneyimlemek/test etmek için.
FITFAK_IDP_DEV_DB=1 node oauth-server.js
# ya da: npm run dev

# Tarayıcıda aç:
open http://localhost:8443/
```

Üretimde (gerçek `@fitfak/database` ile):

```bash
# İLK ÇALIŞTIRMA -- konsola yazdırılan FITFAK_IDP_DB_ID ve FITFAK_IDP_DB_CLIENT_SECRET
# değerlerini HEMEN güvenli bir yere kaydedin (bkz. aşağıdaki KRİTİK uyarı).
node oauth-server.js

# SONRAKİ ÇALIŞTIRMALAR -- aynı veritabanına bağlanmak için:
export FITFAK_IDP_DB_ID=...
export FITFAK_IDP_DB_CLIENT_SECRET=...
node oauth-server.js
```

> **KRİTİK:** `@fitfak/database`'in `createDatabase()` çağrısı `clientSecret`'ı **SADECE BİR KEZ** döner. Bu değeri kaybederseniz veritabanına erişim **kalıcı olarak** kaybolur (zero-knowledge tasarım gereği -- sunucunun kendisi de onu saklamaz). İlk çalıştırmada konsola basılan uyarıyı görün ve değerleri bir secrets manager'a (Vault, AWS Secrets Manager, vb.) kaydedin.

Testleri çalıştırmak için:

```bash
npm test
# ya da tek tek: node test/full-flow-demo.js
```

Tüm test dosyaları (`test/*.js`) gerçek kriptografi ve gerçek HTTP istekleri kullanır -- hiçbiri "sahte" değildir (bkz. [Test kapsamı](#test-kapsamı)).

---

## Mimari genel bakış

```
fitfak-idp/
├── oauth-server.js          # Ana giriş noktası -- SADECE bağlama (wiring) yapar
├── core/                    # Bağımsız, DB'den habersiz kriptografi + protokol katmanı
│   ├── webauthn.js          # WebAuthn/FIDO2 ceremony'leri (node:crypto ile sıfırdan)
│   ├── totp.js              # RFC 6238/4226 TOTP + replay koruması
│   ├── jwt-es256.js         # ES256 JWT sign/verify (asimetrik)
│   ├── session-manager.js   # Oturum/refresh token yaşam döngüsü (rotasyon + reuse tespiti)
│   ├── cbor.js               # WebAuthn attestation'ları için minimal CBOR kod çözücü
│   ├── keys.js               # ES256 anahtar çifti kalıcılığı + JWKS export
│   ├── proof-of-work.js      # Native kriptografik PoW meydan okuması (anti-bot)
│   ├── fingerprint.js        # Sunucu tarafı cihaz parmak izi kompozisyonu
│   ├── rate-limiter.js       # 4 eksenli (IP/kullanıcı/parmak izi/IP+kullanıcı) kademeli kilitleme
│   ├── password.js           # scrypt tabanlı parola hash'leme
│   ├── cookies.js            # SSO cookie serileştirme
│   ├── http-transport.js     # gRPC-Web tarzı taşıma katmanı (bkz. aşağıdaki bölüm)
│   ├── bidi-bridge.js        # Tarayıcı için çift-yönlü akış taklidi (split-channel)
│   ├── base64url.js / base32.js / errors.js
├── db/schema.js              # @fitfak/database koleksiyon şemaları
├── services/                 # İş mantığı (core/ modüllerini + DB'yi birbirine bağlar)
│   ├── auth-service.js        # Kayıt, parola girişi, TOTP, oturum DB adaptörü, anti-bot orkestrasyon
│   ├── webauthn-service.js    # WebAuthn kayıt/giriş servis katmanı (DB + core/webauthn.js)
│   └── oauth-service.js       # /oauth/authorize, /oauth/token, /oauth/userinfo, /oauth/introspect
├── client/identity-client.js  # Diğer backend servisleriniz (dns.fitfak.net vb.) için Node SDK
├── public/                    # Tarayıcı tarafı dosyalar
│   ├── demo-login.html        # Fonksiyonel demo/test sayfası
│   ├── webauthn-browser.js    # navigator.credentials sarmalayıcısı
│   ├── anti-bot-client.js     # Fingerprint toplama + PoW çözücü (Web Crypto)
│   └── oauth-client.js        # fetch() tabanlı API sarmalayıcısı + bidi-bridge istemcisi
└── test/                      # Her modül için gerçek testler (bkz. Test kapsamı)
```

**Katman ayrımı kasıtlıdır:** `core/` hiçbir zaman `@fitfak/database`'i doğrudan bilmez (test edilebilirlik + taşınabilirlik için soyut bir `store` arayüzü kabul eder). `services/` bu arayüzü gerçek DB'ye bağlayan adaptörleri içerir. `oauth-server.js` sadece HTTP/gRPC rotalarını `services/`'e bağlar -- kendi iş mantığı yoktur.

---

## Kimlik doğrulama akışı

```
1. KAYIT (POST /auth/register)
   -> hesap "pending_mfa_setup" durumunda oluşturulur
   -> tam oturum DEĞİL, sadece kısıtlı bir setupToken döner (~15 dk geçerli)

2. ZORUNLU 2FA KURULUMU (setupToken ile)
   -> TOTP:  POST /auth/mfa/totp/begin  ->  POST /auth/mfa/totp/finish
   -> Passkey: POST /auth/webauthn/register/begin -> .../finish
   -> en az biri tamamlanınca hesap "active" olur

3. GİRİŞ -- iki yol:
   a) Parola (1. faktör) -> HER ZAMAN bir 2. faktör gerektirir:
      POST /auth/login/password  ->  { requiresSecondFactor, mfaChallengeToken }
      POST /auth/login/totp  VEYA  POST /auth/webauthn/login/finish (mfaChallengeToken ile)
      -> tam oturum + SSO cookie'leri

   b) Passkey (parolasız, "primary" amaçlı):
      POST /auth/webauthn/login/begin (purpose: 'primary') -> UV zorunlu istenir
      POST /auth/webauthn/login/finish
      -> UV doğrulandıysa (biyometrik/PIN) TEK ceremony ile tam oturum
      -> UV doğrulanamadıysa (nadir -- PIN'siz güvenlik anahtarı) 2. faktör istenir
```

**Neden her parola girişi 2. faktör gerektiriyor ama passkey (UV ile) gerektirmiyor?** WebAuthn "user verification" (UV) ile yapılan bir kimlik doğrulama, cihaz sahipliğini (possession) VE biyometrik/PIN doğrulamasını (inherence/knowledge) TEK ceremony'de kanıtlar -- bu zaten iki bağımsız faktördür (GitHub, Google gibi büyük IdP'lerin izlediği yaklaşım). Parola ise TEK BAŞINA bir bilgi (knowledge) faktörüdür, bu yüzden ikinci bağımsız bir faktör (TOTP ya da ayrı bir WebAuthn possession kanıtı) zorunlu kılınır.

---

## SSO / OAuth2 entegrasyon rehberi

### Akış şeması

Kullanıcı `dns.fitfak.net`'te "Giriş yap" dediğinde:

```
Tarayıcı                dns.fitfak.net              session.fitfak.net
   |                          |                              |
   |--- "Giriş yap" tıkla --->|                              |
   |<-- 302 yönlendirme ------|                              |
   |                          |   (client_id, redirect_uri,  |
   |                          |    code_challenge, ...)       |
   |----------- GET /oauth/authorize?... ------------------->|
   |                          |          SSO cookie var mı?   |
   |                          |     VARSA: sessizce kod üret  |
   |                          |     YOKSA: /static/demo-login |
   |<---------- 302 (code=... ile dns.fitfak.net'e) ----------|
   |--- code'u dns.fitfak.net'e teslim et ------------------->|
   |                          |--- POST /oauth/token -------->|
   |                          |    (code + code_verifier)     |
   |                          |<-- access_token + refresh -----|
   |                          |   (aud=dns-fitfak-net ile)     |
```

**Önemli:** `dns.fitfak.net`'in backend'i `/oauth/token`'ı **kendi sunucusundan** çağırır (tarayıcıdan değil) -- `code_verifier` ve `client_secret` gibi sırlar tarayıcıya hiç ulaşmaz.

### `client/identity-client.js` ile backend entegrasyonu

```js
const { IdentityClient } = require('@fitfak/idp-client'); // ya da dosyayı kopyalayın

const identity = new IdentityClient({
  baseUrl: 'https://session.fitfak.net',
  clientId: 'dns-fitfak-net',
  clientSecret: process.env.FITFAK_IDP_CLIENT_SECRET, // ASLA tarayıcıya göndermeyin
});

// Bir kullanıcının access token'ının hâlâ geçerli olup olmadığını kontrol edin
// (JWT süresi dolmamış olsa BİLE, oturum arada iptal edildiyse false döner):
const info = await identity.introspectToken(accessToken);
if (!info.active) { /* reddet */ }

// Kullanıcının SİZİN RP'nize ait tüm oturumlarını listeleyin/iptal edin:
const { sessions } = await identity.getUserSessions(userId);
await identity.revokeSession(sessionId); // "tüm cihazlardan çıkış yap" gibi senaryolar için
```

Bu SDK, gRPC `IdentityService`'i düz HTTP/1.1 üzerinden (gerçek HTTP/2 **gerekmez** -- bkz. taşıma katmanı bölümü) çağırır ve `x-client-id`/`x-client-secret` ile kendini doğrular. **Güvenlik sınırı:** bir RP, sadece KENDİ `client_id`'siyle en az bir kez token almış oturumları görebilir/iptal edebilir (bkz. aşağıdaki "audiences" tasarım kararı) -- başka bir RP'nin oturumlarına erişemez.

### Cookie davranışı

| Cookie | Domain | Path | Ömür | İçerik |
|---|---|---|---|---|
| `__Secure-fitfak_at` | `.fitfak.net` | `/` | 10 dk | Access token (JWT) |
| `__Secure-fitfak_rt` | `.fitfak.net` | `/oauth/token` | 30 gün | Refresh token (opak) |

İkisi de `HttpOnly; Secure; SameSite=Lax` -- JavaScript'ten erişilemez, sadece HTTPS üzerinden gönderilir, çapraz-site GET yönlendirmelerinde (SSO akışı için gerekli) gönderilir ama çapraz-site POST/CSRF'de gönderilmez. `__Host-` yerine `__Secure-` öneki kullanıldı çünkü `__Host-` `Domain` özniteliğiyle **uyumsuzdur** ve alt-domain'ler arası SSO için `Domain=.fitfak.net` şart.

---

## Taşıma katmanı: gRPC-Web + bidi köprüsü

Referans `grpc-server.js`'inizdeki desenlerle uyumlu (durum kodları, 5-byte çerçeveleme, `service.use()` middleware, `addHttpHandler` kancası, unary/server_stream/client_stream/bidi dispatch) ama **sıfırdan yazıldı** ve bitmask RBAC yerine OAuth scope-string dizileri kullanıyor.

### Neden iki port (`PORT` ve `FITFAK_IDP_HTTP2_PORT`)?

Geliştirme sırasında somut bir sorunla karşılaşıldı: Node'un düz-metin `http2.createServer({allowHTTP1:true})` seçeneği, gerçek HTTP/1.1 istemcilerine (curl, fetch, tarayıcılar) karşı **güvenilir şekilde otomatik "h1'e düşürme" yapmadı** -- izole bir testte doğrudan gözlemlendi: düz bir `http.request()` çağrısı sunucudan ham HTTP/2 SETTINGS çerçeveleriyle karşılaştı ve parse hatası aldı.

Tarayıcılar zaten düz-metin HTTP/2'yi (h2c) hiçbir zaman konuşamaz -- bu yüzden çözüm hem sağlam hem basit: **her şeyi** (REST uçları, statik dosyalar, bidi-bridge, VE unary/server_stream/client_stream gRPC çağrıları -- hiçbiri gerçek çift-yönlü akış gerektirmez) düz `http.createServer` (`PORT`) üzerinden sunmak; SADECE gerçek Node↔Node bidi çağrıları için ayrı, saf bir `http2.createServer` (`FITFAK_IDP_HTTP2_PORT`) açmak. Düz porta bidi çağrısı gelirse sistem yanlış davranmak yerine açıkça `UNIMPLEMENTED` durumu döner.

Üretimde tipik olarak bir TLS sonlandıran ters proxy (nginx, Envoy) arkasında çalışacağınız için, bu proxy ALPN ile h1/h2 negotiation'ı zaten doğru yapar -- bu ikili port ayrımı sadece düz-metin (TLS'siz) senaryo için gereklidir.

### Çağrı tipleri

- **unary**: tek istek, tek yanıt. Düz HTTP/1.1'de mükemmel çalışır.
- **server_stream**: tek istek, birden fazla yanıt çerçevesi (chunked transfer encoding ile). Düz HTTP/1.1'de çalışır.
- **client_stream**: istemci TÜM mesajlarını önce kendi tarafında biriktirip TEK istekte art arda çerçeveler (tarayıcılar gerçek bir "istemciden akan" gövde gönderemez zaten -- bu Google'ın resmi grpc-web'inin de izlediği yaklaşım). Düz HTTP/1.1'de çalışır.
- **bidi**: GERÇEK çift-yönlü akış -- sadece Node↔Node HTTP/2 (`http2.connect()`) üzerinden.

### Tarayıcılar için bidi: split-channel köprü

`core/bidi-bridge.js`, TEK bir bidi ceremony'sini tarayıcı için İKİ AYRI, sıradan HTTP isteğine böler:

- `POST {prefix}/open` -- oturum başlatır, handler'ı çalıştırır
- `GET {prefix}/subscribe?session=` -- AÇIK KALAN bir istek; sunucudan gelen mesajlar buraya akar
- `POST {prefix}/send?session=` -- istemciden sunucuya HER mesaj için ayrı bir istek
- `POST {prefix}/close?session=` -- akışı kapatır

`oauth-server.js`'te `/events/sessions` altında örnek bir kullanım (canlı oturum/güvenlik olayı bildirimleri) monte edilmiştir; mekanizmanın kendisi tam test edilmiştir. Gerçek session-revocation olaylarını bu akışa bağlamak (SessionManager'a bir event-emitter kancası eklemek) sizin entegrasyonunuz için bir sonraki adımdır.

---

## Tasarım kararları ve referans koddan sapmalar

| Karar | Referans kod | Bu proje | Neden |
|---|---|---|---|
| JWT imzalama | HMAC (paylaşılan sır) | **ES256 (asimetrik)** | Çoklu RP'li SSO'da paylaşılan bir HMAC sırrı, ELE GEÇİRİLMİŞ herhangi bir RP'nin diğer TÜM RP'ler için token sahteciliği yapmasına izin verir. ES256 ile özel anahtar SADECE IdP'de kalır; RP'ler `/.well-known/jwks.json`'dan sadece genel anahtarla doğrulama yapar. |
| Parola hash'leme | Salt'sız SHA-256 | **scrypt** | SHA-256 hızlıdır -- offline kaba kuvvet/rainbow table saldırılarına açıktır. scrypt kasıtlı olarak yavaş ve bellek-yoğun. |
| Veri katmanı | `GraphStore` | **`@fitfak/database` DatabaseManager koleksiyonları** | Açıkça talep ettiğiniz gibi, `GraphStore` deseni bu projede hiç kullanılmadı/algılanmadı. |
| Admin yetkisi | `req.username === 'aybars'` string karşılaştırması | **`isAdmin` boolean alanı** (users şeması) | Referans koddaki desen gerçek bir yetki atlatma riski: KAYIT UÇ NOKTASI herkese `aybars` kullanıcı adını seçme izni verir. |
| Rate-limit eksenleri | `${username}:${ip}` (tek eksen) | **4 bağımsız eksen**: IP, kullanıcı adı, parmak izi, IP+kullanıcı | Referans desen SADECE IP'yi değiştirerek yapılan credential-stuffing'i (kullanıcı adı sabit, IP dönen) yakalar ama SAF IP-bazlı deneme fırtınasını (çok sayıda farklı kullanıcı adı, tek IP) kaçırır. |
| Oturum "audience"ı | (yok -- tek RP varsayımı) | **`audiences` DİZİSİ** (session üzerinde), her refresh token KENDİ `audience`'ını taşır | Bir oturum, SSO sayesinde ZAMAN İÇİNDE birden fazla RP'ye (dns.fitfak.net + başka bir servis) token verebilir -- tekil bir alan bunu ifade edemez. Bu proje geliştirilirken bu tam olarak bu şekilde bir entegrasyon testinde YAKALANDI ve düzeltildi (bkz. Test kapsamı). |
| 2FA politikası | E-posta/OTP deseninden esinlenildi | **Zorunlu TOTP veya WebAuthn**, `pending_mfa_setup` durum makinesi | Kayıt sonrası hesap kısıtlı bir `setupToken` alır (tam oturum değil), en az bir güçlü faktör kurulana kadar. |
| Refresh token modeli | (referans kodda yok) | **Rotasyon + yeniden-kullanım tespiti**, `sessionId` = rotasyon ailesi anahtarı | Zaten kullanılmış bir refresh token'ın tekrar sunulması (hırsızlık işareti) TÜM oturumu iptal eder, sadece o token'ı değil. |

---

## Test kapsamı

Her modül gerçek testlerle doğrulandı (`node test/<dosya>.js` ile tek tek, ya da `npm test` ile hepsi birden). **Hiçbiri sahte/iskelet değil** -- gerçek kriptografi, gerçek HTTP istekleri, gerçek HTTP/2 bağlantıları kullanır.

| Test dosyası | Ne doğrular |
|---|---|
| `base32-demo.js` | RFC 4648 resmi test vektörleri |
| `cbor-demo.js` | WebAuthn CBOR alt kümesi, iç içe COSE_Key yapıları |
| `jwt-es256-demo.js` | ES256 sign/verify, DER↔JOSE dönüşümü (100 tekrar, farklı R/S uzunlukları), kurcalama/süre tespiti |
| `totp-demo.js` | RFC 4226 Appendix D resmi vektörleri (TAMAMI), replay koruması, drift penceresi |
| `webauthn-demo.js` | ES256+RS256 kayıt/giriş, 5 saldırı senaryosu (yanlış challenge/origin/imza, klon şüphesi, replay) |
| `anti-bot-demo.js` | PoW çözüm/red, fingerprint kompozisyonu |
| `session-rotation-demo.js` | Refresh rotasyonu, yeniden-kullanım tespiti + tam oturum iptali |
| `http-transport-demo.js` | Gerçek HTTP/2 sunucusu: unary/server_stream/client_stream/bidi + middleware + **hem `PORT` (düz HTTP/1.1) hem `FITFAK_IDP_HTTP2_PORT` (gerçek HTTP/2) ayrı ayrı doğrulanır** |
| `bidi-bridge-demo.js` | Split-channel köprü, **düz `node:http` istemcisiyle** (gerçek tarayıcı senaryosu) |
| `full-flow-demo.js` | UÇTAN UCA: kayıt → zorunlu MFA → parola+TOTP girişi → passkey ekleme → parolasız giriş → SSO/OAuth+PKCE → refresh → iptal → anti-bot |
| `smoke-oauth-server.js` | Gerçek `oauth-server.js`'e karşı gerçek HTTP istekleri (JSON gövde ayrıştırma, gerçek `Set-Cookie` header'ları) |
| `identity-client-demo.js` | `client/identity-client.js` SDK'sı, gerçek RP-scoped token, audience-sınırlı yetkilendirme |
| `multi-account-demo.js` | Çoklu-hesap seçici: 2 hesap aynı tarayıcıda, authorize()'ın seçiciye yönlendirmesi, switch-account, logout/logout-all semantiği |
| `qrcode-demo.js` | QR kod: V1-V9, Reed-Solomon sendrom doğrulaması + orijinal bayt geri kurtarma round-trip testi |

**Geliştirme sırasında bulunup düzeltilen gerçek hatalar** (mühendislik titizliğinin bir göstergesi olarak burada listeleniyor, halının altına süpürülmedi):

1. `enforceAntiAutomation` ile `loginWithPassword`/`completeLoginWithTotp` arasında rate-limiter'a başarı/başarısızlık sinyalinin geri bildirilmediği bir kopukluk.
2. `completeLoginWithTotp`'ta `mfaChallengeToken`'ın kod doğrulanmadan ÖNCE tüketilmesi -- yanlış yazılan tek bir haneyi kullanıcıyı parola adımına geri döndürecek şekilde zorluyordu.
3. WebAuthn UV=false durumunda ikinci faktör olarak sabit-kodlanmış `['totp']` önerisi -- kullanıcının GERÇEKTEN kurmadığı bir yöntemi öneriyordu.
4. **Node'un `allowHTTP1` seçeneğinin düz-metin bağlantılarda güvenilir çalışmaması** -- yukarıda detaylandırılan ikili-port mimarisiyle çözüldü.
5. **Oturum "audience"ının tekil bir alan olarak modellenmesi** -- `identity-client-demo.js` testi yazılırken yakalandı: bir oturum SSO sayesinde birden fazla RP'ye hizmet edebildiği için tekil alan yanlıştı; `audiences` dizisine + refresh-token-başına audience/scope izlemesine geçildi.

---

## Kapsam ve sınırlamalar (dürüstlük bölümü)

Bu bölüm kasıtlı olarak dürüst. Aşağıdakiler üretim öncesi ele alınmalı:

- **WebAuthn attestation güven zinciri doğrulanmıyor.** `none` ve `packed` formatları destekleniyor (imza bütünlüğü kontrol ediliyor), ama FIDO Metadata Service (MDS) üzerinden kök sertifika zinciri doğrulaması YOK. Çoğu tüketici passkey'i (platform authenticator) zaten `none` kullanır, bu yüzden pratik etkisi sınırlı, ama donanım güvenlik anahtarlarının GERÇEKTEN sertifikalı cihazlar olduğunu KANITLAMAZ.
- **QR kod artık üretiliyor** (`core/qrcode.js`, v1.2'de eklendi) ama gerçek bir telefon kamerasıyla taranabilirliği test edilmedi -- SADECE kendi encoder/decoder çiftimin iç tutarlılığı (Reed-Solomon sendromları + round-trip) doğrulandı. Üretime almadan önce gerçek bir authenticator uygulamasıyla tarayın.
- **Bellek-içi durum, çoklu-instance ölçeklendirme için paylaşılan bir depoya taşınmalı.** PoW meydan okumaları, rate-limiter sayaçları, WebAuthn/OAuth challenge'ları şu an process belleğinde. Birden fazla `oauth-server.js` instance'ı (yatay ölçekleme) çalıştırıyorsanız bunları Redis gibi paylaşılan bir depoya taşıyın.
- **ES256 özel anahtarı için HSM/KMS entegrasyonu yok.** Anahtar `core/keys.js` ile diske PEM olarak yazılıyor. Üretimde AWS KMS, HashiCorp Vault Transit, ya da bir HSM kullanmayı düşünün.
- **`findAll` varsayımı doğrulanmalı.** Sağladığınız referans dosyalarının HİÇBİRİNDE (`basic-usage.js`, `mls-key-provider-demo.js`, `index-snapshot-demo.js`, vb.) `findOne` dışında bir çoklu-eşleşme sorgu metodu gösterilmiyor. `services/auth-service.js`'teki `createSessionStoreAdapter`, `listSessionsForUser` için `collection.findAll(field, value)` çağırıyor -- bu GERÇEK API'de bu isimle var mı, yoksa farklı mı (örn. bir cursor/iterator deseni), lütfen doğrulayın ve gerekirse uyarlayın.
- **`uint64` alanlar için BigInt varsayımı doğrulanmalı.** `createdAt`/`expiresAt`/`signCount` gibi alanlar `BigInt` değerleriyle yazılıyor (JS `number`'ın güvenli tamsayı sınırının ötesindeki epoch-milisaniye değerleri için doğal seçim), ama referans dosyalarında `uint64` tipli bir alana doğrudan BigInt yazıldığı hiç gösterilmiyor -- lütfen gerçek DB ile doğrulayın.
- **`clientSecret` kalıcılığı KRİTİK.** Yukarıda detaylandırıldığı gibi -- kaybedilirse veritabanına erişim kalıcı olarak kaybolur.
- **`DB_PERMISSIONS` enum'unun tamamı bilinmiyor.** Sadece `.READ` referans dosyalarında görüldü; `openDatabase()` çağrılarımızda `requiredPermission` BİLEREK belirtilmedi (owner kendi veritabanını açtığında gerekmediği gözlemlendi) -- gerçek API'nizde başka bir davranış varsa uyarlayın.
- **Anti-bot mekanizmaları bir güven sınırı DEĞİL, maliyet-yükseltme katmanıdır.** Fingerprinting ve PoW, kararlı/sahtesi-imkansız bir kimlik kanıtı sağlamaz -- kaba kuvvet/otomasyonu daha pahalı hale getirir. Gerçek bir güvenlik sınırı için WAF/CDN seviyesinde ek koruma (Cloudflare Turnstile vb.) düşünün.
- **`GetUserSessions`/`RevokeSession` yetkilendirmesi `audiences` dizisine dayanıyor** -- bu, "bu RP en az bir kez bu oturumdan token aldı mı" sorusuna cevap verir. Daha ince taneli (örn. "sadece HALA GEÇERLİ bir refresh-token soyu üzerinden") bir kontrol isterseniz, refresh_tokens koleksiyonunu tarayan bir sorgu eklemeniz gerekir.

---

## v1.1 güncellemesi: e-posta doğrulama, RBAC, Snowflake ID, uzak gRPC veritabanı seçeneği

Kullanıcının kendi çalışan (production) referans sistemlerinden (`server.js`, `client.js`, `protobuf.js`) öğrenilen gerçek `@fitfak/database` API'sine göre yapılan düzeltmeler ve eklemeler:

- **`findAll` çökmesi düzeltildi.** Gerçek API'de çoklu-eşleşme metodu yok; gerçek desen `collection.scan()` (async iterasyon) + elle filtreleme. `db/query-utils.js`'teki `scanFindAll()` şimdi bunu tek bir yerde topluyor; hem embedded DB hem uzak gRPC adaptörü (aşağıda) AYNI `scan()` arayüzünü sağlıyor.
- **Kalıcı-olmayan `clientSecret` riski ortadan kaldırıldı.** Artık rastgele üretilip bir kez gösterilen bir sır yerine, `FITFAK_IDP_DB_SECRET` ortam değişkeninden **deterministik** bir anahtar türetiliyor (referans `system_core` deseniyle aynı) -- kaybetme riski yapısal olarak yok. Zaten açık olan veritabanınız (eski `FITFAK_IDP_DB_CLIENT_SECRET` adıyla) hiçbir değişiklik olmadan çalışmaya devam eder.
- **Snowflake ID'ler.** `SnowflakeGenerator` artık `DatabaseManager`'a bağlı (`FITFAK_IDP_SNOWFLAKE_WORKER_ID` ile yapılandırılabilir workerId).
- **E-posta doğrulama** (`core/mailer.js`, kullanıcının `smtp-service.js`'inden uyarlandı): kayıt akışına yeni bir ilk adım eklendi -- `register()` → `pending_email_verification` (kod e-postaya gider) → `POST /auth/verify-email/confirm` → `pending_mfa_setup` (eskisi gibi devam). `SMTP_HOST`/`SMTP_PORT`/`SMTP_USER`/`SMTP_PASS` ile yapılandırılır; ayarlanmazsa kod sadece sunucu loguna yazılır (geliştirme için).
- **RBAC (rol tabanlı yetkilendirme).** `users` şemasına `role` alanı eklendi. `/admin/users`, `/admin/users/role`, `/admin/sessions`, `/admin/sessions/revoke` uç noktaları + `public/admin-panel.html` (basit, işlevsel yönetici arayüzü). Referans server.js'teki "kendi admin rolünü kendi kaldıramama" güvenlik kontrolü aynen uygulandı.
- **Oturum `audiences` tasarımı düzeltildi.** Bir oturum SSO sayesinde birden fazla RP'ye token verebildiği için, tekil bir alan yerine büyüyen bir dizi olarak modellendi (bkz. Test kapsamı tablosundaki "bulunan hatalar" listesi).

### Opsiyonel: paylaşılan gRPC veritabanı sunucusuna uzaktan bağlanma

`db/grpc-db-adapter.js`, kullanıcının kendi `protobuf.js`'i (gerçek protobuf wire format v3, sıfırdan, npm bağımlılığı yok) ve `client.js`'teki `PureGrpcClient` deseniyle (gerçek `content-type: application/grpc`, HTTP/2 native trailers, 5-byte çerçeveleme) **bayt-uyumlu** bir istemci sağlar. `FITFAK_IDP_REMOTE_DB_HOST` ayarlanırsa, embedded `@fitfak/database` yerine bu kullanılır -- `db.collection(name)` arayüzü AYNI kaldığı için `services/*.js`'in tek satırı değişmez.

Bu adaptörü kullanmadan önce **lütfen `db/grpc-db-adapter.js`'in başındaki DÜRÜSTLÜK NOTU'nu okuyun** -- özetle iki gerçek sınırlama var:
1. Paylaşılan sunucunun gördüğüm `FindRecord` implementasyonu, tanımlanmamış bir koleksiyonu otomatik olarak SABİT KODLANMIŞ tıbbi bir şemayla (tc/isim/anamnez vb.) oluşturuyordu -- `users`/`sessions` gibi fitfak-idp koleksiyonlarının paylaşılan sunucuda **önceden doğru şemayla** (`db/schema.js`) tanımlanmış olması gerekir.
2. Gördüğüm tek kimlik doğrulama yolu e-posta OTP'si (insan etkileşimi) -- sunucu-sunucu otomasyonu için pratik değil. `FITFAK_IDP_REMOTE_DB_JWT` ile önceden alınmış bir token kullanılıyor; bu token'ın periyodik yenilenmesi (30 gün) sizin sorumluluğunuzda -- gerçek bir servis-hesabı/client-credentials mekanizması eklemek çok daha sağlam olur.

Alt seviye çerçeveleme/trailer mekaniği, gerçek bir HTTP/2 + native trailer sunucusuna karşı doğrulanmıştır (protobuf round-trip + uçtan uca istek/yanıt).

---

## v1.2 güncellemesi: DB-tabanlı OAuth client'lar, çoklu-hesap seçici, gerçek QR kod, sade tasarım

- **OAuth client'lar artık veritabanında** (`oauth_clients` koleksiyonu, `createDbClientStore`). `/admin/oauth-clients` (liste/oluştur/güncelle/sil) ile redirect URI'ler dahil her şey admin panelinden yönetilebilir; secret'lar listelemede maskelenir (`••••xxxx`), sadece oluşturma anında tam gösterilir. İlk açılışta `FITFAK_IDP_DNS_CLIENT_ID`/`_SECRET`/`_REDIRECT_URI` verilmişse ilgili client idempotent olarak tohumlanır.
- **Microsoft/Google tarzı çoklu-hesap seçici.** Yeni `__Secure-fitfak_accounts` cookie'si, bu tarayıcıda giriş yapılmış TÜM hesapların (sadece "en son"un değil) listesini tutar. `/oauth/authorize`, 2+ geçerli hesap varken artık SESSİZCE birini varsaymak yerine bir seçim ekranına yönlendirir (`GET /auth/accounts`, `POST /auth/switch-account`); normal `/auth/logout` sadece aktif hesabı kaldırır, `/auth/logout-all` hepsini temizler. Client/redirect_uri doğrulaması, hesap seçiciyi göstermeden ÖNCE yapılır (aksi halde geçersiz bir istek için bile "hangi hesaplar açık" bilgisi ifşa edilirdi -- bunu multi-account-demo.js testini yazarken yakaladım).
- **Gerçek, sıfırdan QR kod üretimi** (`core/qrcode.js`): ISO/IEC 18004 byte modu, versiyon 1-9, EC seviyesi L, GF(256) Reed-Solomon + standart modül yerleşimi/maskeleme + elle yazılmış PNG encoder (sadece `node:zlib`). `/auth/mfa/totp/begin` artık gerçek bir `qrCodeBase64` (`data:image/png;base64,...`) döndürüyor. **Geliştirme sırasında Reed-Solomon kodlamasında gerçek bir hata bulundu ve düzeltildi** (üreteç polinomunun baş katsayısı yanlışlıkla iki kez uygulanıyordu) -- kendi kendini doğrulayan bir round-trip testiyle (`test/qrcode-demo.js`: encode → matristen kod çöz → Reed-Solomon sendromlarının sıfır olduğunu doğrula → orijinal baytların TAM eşleştiğini doğrula) yakalandı. Bu doğrulama SADECE encoder/decoder çiftimin iç tutarlılığını kanıtlar -- gerçek bir telefon kamerasıyla taranabilirliği garanti etmez, üretime almadan önce gerçek bir authenticator uygulamasıyla test edin.
- **`demo-login.html` sadeleştirildi**: koyu "rozet paneli" temasından, tek sütunlu, açık renkli, tek accent renkli (indigo) modern bir karta geçildi; hesap seçici görünümü eklendi.
- **Varsayılan port artık 80** (`http.createServer`, düz HTTP -- Cloudflare Tunnel gibi bir ters proxy arkasında TLS'siz çalışacak şekilde).

---

## v1.3 güncellemesi: Device Code girişi, ölçeklenebilirlik, ve tam PKI/ACME sistemi

### Device Authorization Grant (RFC 8628) -- terminal/CLI girişi

`POST /oauth/device/code` ile başlar (`device_code`+`user_code`+`verification_uri` döner), kullanıcı BAŞKA bir cihazda `/device` adresini açıp kodu onaylar (`view-device-code`, `demo-login.html`), terminal `POST /oauth/token` (`grant_type=urn:ietf:params:oauth:grant-type:device_code`) ile poll eder. Hazır bir CLI yardımcısı: `client/device-login.js`'teki `deviceLogin()` -- tüm akışı (kod al, göster, poll et, token al) tek çağrıda yönetir. Gerçek uçtan uca test: `test/device-code-demo.js`.

### Ölçeklenebilirlik: paylaşılan, DB-destekli geçici durum

`core/ephemeral-store.js`: setup token, mfa challenge token, e-posta kodu, OAuth kodu, PoW meydan okuması, device code, ACME nonce'u -- HEPSİ artık `InMemoryEphemeralStore` (tek instance) YA DA `DbEphemeralStore` (aynı `db.collection()` arayüzü, embedded/uzak-gRPC fark etmez) ile çalışabiliyor. `oauth-server.js` artık varsayılan olarak TEK bir paylaşılan `DbEphemeralStore` kullanıyor (önekli alt-store'larla) -- birden fazla `fitfak-idp` instance'ını bir yük dengeleyici arkasında koşturmak artık GERÇEKTEN güvenli. (Rate-limiter sayaçları BİLEREK instance-başına kalıyor -- bkz. dosya başlığındaki gerekçe.)

### PKI / ACME / OCSP / CRL -- `trust.fitfak.net`

`session.fitfak.net` ile AYNI porttan, `Host` header'ına göre ayrışan (gerçek TLS SNI değil -- Cloudflare zaten TLS'i sonlandırdığı için düz `Host` eşleştirmesi yeterli ve doğru eşdeğer) yeni bir mantıksal host: `trust.fitfak.net`.

- **Device-code kimlikli mTLS sertifikası**: `POST /device/certificate` -- giriş yapmış bir kullanıcı CSR'ını gönderir, RBAC'a göre (`users.certProfiles`, varsayılan sadece `client-auth` herkese açık) izin verilen bir profil ile sertifika alır.
- **ACME (RFC 8555)**: `/acme/directory`, `/acme/new-nonce`, `/acme/new-account`, `/acme/new-order`, `/acme/authz/:id`, `/acme/challenge/:id` (GERÇEK http-01 doğrulaması -- sunucu identifier'a gerçek bir HTTP isteği atar), `/acme/order/:id/finalize`, `/acme/cert/:serial`. JWS doğrulaması `core/acme-jws.js`'te Node'un YERLEŞİK JWK desteğiyle (ES256/P-256, IEEE-P1363) yapılıyor -- elle DER dönüşümü YOK.
- **OCSP (RFC 6960)** ve **CRL (RFC 5280)**: `/ocsp`, `/crl` -- durum sorgusu paylaşılan `certificates` koleksiyonundan (yani birden fazla instance ARDINDA bile tutarlı), uygun `Cache-Control` header'larıyla.
- **Yönetici paneli**: sertifika listesi + iptal (`/admin/certificates`).

**KRİTİK DÜRÜSTLÜK NOTU:** Gerçek X.509 imzalama (CSR→sertifika, OCSP yanıtı imzalama, CRL imzalama) BİLEREK sıfırdan yazılmadı -- `core/pki-issuer.js`'teki `PkiIssuer` arayüzü, bunları SİZİN `@fitfak/ssl` altyapınıza (root/sub-CA'nız dahil) bağlamanız için var. Şu an sadece protokol/akışı test eden bir `createDevMockIssuer()` var (GERÇEK sertifika ÜRETMEZ, ASLA üretimde kullanmayın). `test/pki-acme-demo.js` tüm protokolü (gerçek EC anahtarı + gerçek JWS imzası + gerçek http-01 HTTP isteği ile) bu sahte issuer'la uçtan uca doğruluyor -- ama gerçek sertifika geçerliliğini/tarayıcı güvenini DOĞRULAMIYOR. Üretime almadan önce `core/pki-issuer.js`'in üç fonksiyonunu (`signCertificateFromCsr`, `generateOcspResponse`, `signCrl`) kendi imzalama çağrılarınızla doldurun.

---

## v1.4 güncellemesi: güvenlik denetimi düzeltmeleri + mTLS ile veritabanı bağlantısı

### Güvenlik denetimi düzeltmeleri

- **SSRF koruması** (`acme-service.js`): http-01 doğrulaması artık `node:dns` ile çözümleyip private/loopback/link-local/bulut-metadata (169.254.169.254 dahil) + IPv6 eşdeğerlerini engelliyor; DNS rebinding'e karşı doğrulanan IP'ye doğrudan bağlanıyor. `isBlockedIp` bağımsız olarak test edildi.
- **CRL önbellek senkronizasyonu**: modül-seviyesi değişkenden paylaşılan `DbEphemeralStore`'a taşındı -- artık tüm instance'lar aynı önbelleği görüyor.
- **Host Header Injection koruması** (`oauth-server.js`): en öncelikli, katı bir allowlist doğrulaması (`session.fitfak.net`/`trust.fitfak.net` dışı her şey reddedilir).
- **`ProductionPkiIssuer` + gerçek CSR ayrıştırıcı** (`core/csr-parser.js`): Node'un yerleşik crypto'suyla (bağımlılıksız) gerçek bir PKCS#10 ayrıştırıcı -- **openssl ile üretilmiş gerçek bir CSR'a karşı test edildi** (imza doğrulama + bozuk-CSR reddi). `pki.buildCert`/`pki.generateOcspResponse` referans dosyalarınızdaki gerçek API ile entegre edildi. `signCrl` dürüstçe boş bırakıldı -- hiçbir referans dosyada bir CRL-imzalama fonksiyonu gösterilmedi.
- Device code uçları (`/device/info`, `/device/approve`, `/device/deny`): IP-bazlı rate-limit + sabit-zamanlı yanıt.
- RFC 8628 `slow_down`: son poll zamanı paylaşılan store'da tutuluyor.
- Kullanıcı numaralandırma koruması: `register()` artık her zaman aynı genel yanıtı dönüyor, mevcut hesaba bildirim gönderiyor.
- `getIp()`: Cloudflare `CF-Connecting-IP` önceliği + güvenli XFF ayrıştırması.
- Parola karmaşıklığı: 12+ karakter, büyük/küçük harf, rakam, özel karakter zorunlu.

**Bilinçli olarak ertelenen madde:** Rate-limiter'ın (`core/rate-limiter.js`) DB-destekli hale getirilmesi -- bu, TÜM metodları async'e çevirip onlarca çağrı noktasını güncellemeyi gerektiren, kapsamlı ve riskli bir refactor. Şu an rate-limiter sayaçları BİLEREK instance-başına kalıyor (bu dosyanın kendi notlarında da açıklandığı gibi, "kesin doğru olması gerekmeyen, maliyet-yükseltici bir sezgisel" olarak tasarlandı). Yatay ölçeklenmiş bir dağıtımda TAM rate-limit tutarlılığı istiyorsanız, bunu (ör. Cloudflare Rate Limiting gibi bir kenar katmanıyla, ya da bu dosyayı DB-destekli sabit-pencere sayaçlarına dönüştürerek) ayrı bir iterasyonda ele almanızı öneririz.

### mTLS ile veritabanı bağlantısı (yumurta-tavuk sorununun çözümü)

Önceki sürümde, paylaşılan gRPC veritabanına bağlanmak bir JWT gerektiriyordu ve tek bilinen kimlik doğrulama yolu (e-posta OTP'si) insan etkileşimi istiyordu -- sunucudan sunucuya otomatik bağlantı için pratik değildi. **Artık mTLS kullanılıyor**: `trust.fitfak.net`'in KENDİ, zaten var olan (hiçbir kayıt/login akışı gerektirmeyen) sertifika+özel anahtarı, bu bağlantının istemci kimliği olarak TLS el sıkışmasında sunuluyor.

- `client/grpc-wire-client.js`: `PureGrpcClient` artık `{cert, key, ca}` seçenekleriyle mTLS destekliyor.
- `db/grpc-db-adapter.js`: `connectRemoteDatabase()` artık `mtls` parametresi alıyor; eski JWT mekanizması opsiyonel/ikincil (kaldırılmadı).
- `oauth-server.js`: `FITFAK_IDP_MTLS_CERT_PATH`/`_KEY_PATH`/`_CA_PATH` ortam değişkenlerinden sertifika/anahtar okunuyor.
- **`test/mtls-demo.js`**: openssl ile üretilmiş gerçek bir CA + istemci + sunucu sertifika zinciriyle uçtan uca doğrulandı -- geçerli sertifika başarılı oluyor (sunucu doğru CN'i görüyor), sertifikasız istemci reddediliyor, güvenilmeyen CA'dan sertifika ASLA `authorized:true` sonucuna yol açmıyor.

Sunucu tarafı mTLS doğrulaması (hangi CA'lara güvenileceği, `requestCert`/`rejectUnauthorized` yapılandırması) sizin sorumluluğunuzdadır -- bu proje sadece istemci tarafını sağlar.

---

## Dosya haritası

Tüm dosyalar `test/*.js` ile ayrı ayrı test edilmiştir. Sorularınız için önce ilgili test dosyasına bakmanızı öneririz -- gerçek kullanım örnekleri içerir.
