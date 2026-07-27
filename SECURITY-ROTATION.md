# Sır rotasyonu — ACİL

Bu depoya **canlı kimlik bilgileri işlenmişti**. Koddan kaldırıldılar, ancak
**git geçmişinde duruyorlar**: depoyu klonlayan ya da herhangi bir eski commit'i
görebilen herkes bunlara erişebilir. Kaldırma commit'i bunu değiştirmez.

Aşağıdaki üç kimlik bilgisi **yanmış** kabul edilmeli ve **döndürülmelidir**.

| Ne | Nerede duruyordu | Etkisi |
|---|---|---|
| `FITFAK_IDP_DB_SECRET` | `oauth-server.js` | **En ciddi olanı.** Veritabanı kök sırrı. Veri dizininin bir kopyasıyla birlikte, şifrelenmiş her kaydı çözmeye yeter — kullanıcılar, oturumlar, TOTP sırları, sertifika özel anahtarları. |
| SMTP parolası (`network@fitfak.net`) | `oauth-server.js` | Kurumsal alan adından e-posta gönderme yetkisi. Kimlik doğrulama e-postalarını taklit etmek, oltalama ve parola sıfırlama akışlarını ele geçirmek için kullanılabilir. |
| Kasa kimliği + sırrı (`355024942087016448`) | `src/client.js` | O kasanın tüm içeriğini çözer. |
| **CA özel anahtarı** (`AybarsRootCA`) | `certs/ca.key` (hâlâ takipli) | **Bunlar hâlâ depoda.** Aşağıya bakın. |

## `certs/` altındaki özel anahtarlar

`certs/ca.key`, `certs/server.key` ve `certs/client.key` depoya işlenmiş
**gerçek özel anahtarlardır** ve hâlâ takip ediliyorlar:

```
certs/ca.crt      O = Aybars Network, CN = AybarsRootCA   (2036'ya kadar geçerli)
certs/server.crt  CN = localhost                          (bu CA tarafından imzalı)
certs/client.crt  bu CA tarafından imzalı istemci sertifikası
```

`ca.key` bir **CA özel anahtarıdır**. Depoyu okuyabilen herkes bu anahtarla
`AybarsRootCA`'ya güvenen her şey için **istediği adı taşıyan sertifika
üretebilir** — istediği CN'e sahip bir istemci sertifikası dahil. Veritabanının
kimlik modeli "istemci sertifikasının CN'i kimliktir" üzerine kurulu olduğundan,
bu anahtar veri düzlemine istenen principal olarak girme yetkisidir.

Bu, tam olarak endişelendiğiniz senaryodur: *"kaçığın teki elde ettiği bir
sertifika ile bizi zora sokmasın."* Elde etmesi gerekmiyor; depoda duruyor.

**Bu dosyalar bilerek silinmedi** — `server.crt`/`server.key` ilk açılış
(bootstrap) için kullanılıyor olabilir ve altınızdan çekmek istemedim. Yapılması
gereken:

1. Yeni bir CA hiyerarşisi üretin (`core/pki-issuer.js` ilk çalıştırmada
   `.certs/` altında otomatik üretir — bu dizin artık `.gitignore` içinde).
2. Veritabanı sunucusunun TLS kimliğini ve IdP'nin istemci kimliğini yeni
   hiyerarşiden verin.
3. `AybarsRootCA`'yı her yerden güven listesinden **çıkarın**.
4. `git rm --cached certs/*.key` ile takipten düşürün (dosyalar diskte kalır).
5. Geçmişi de temizlemek isterseniz aşağıdaki `filter-repo` adımına ekleyin —
   ama bu, 1-3. adımların yerine geçmez.

## Yapılması gerekenler

**1. Veritabanı kök sırrı.** Yeni bir sır üretin ve veritabanı anahtarını yeniden
sarmalayın. `@fitfak/database` bunu O(1) yapar — kayıtlar yeniden şifrelenmez,
yalnızca DDK yeni KEK altında yeniden sarmalanır:

```js
await manager.rewrapDatabaseKey({ dbId, oldKeyProvider, newKeyProvider });
```

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Eski sırla üretilmiş bir disk kopyası hâlâ eski sırla çözülebilir. Rotasyon,
**bundan sonrasını** korur; halihazırda sızmış bir kopyayı geri alamaz. Veri
dizininin yedeklerinin nerede olduğunu ayrıca gözden geçirin.

**2. SMTP parolası.** Posta sağlayıcısında değiştirin. Değiştirene kadar bu
adresten gönderilmiş e-postalara güvenilmemelidir.

**3. Kasa sırrı.** Yukarıdaki gibi yeniden sarmalayın.

## Geçmişi temizlemek

Sırları git geçmişinden gerçekten silmek, geçmişi yeniden yazmayı gerektirir
(`git filter-repo` ya da BFG) ve tüm klonların yeniden alınmasını zorunlu kılar.
Bu, **rotasyonun yerine geçmez** — sadece ona ek olarak yapılır. Depo herhangi
bir noktada başkasının erişimine açıksa, rotasyon tek gerçek çözümdür.

```sh
git filter-repo --replace-text <(printf '%s\n' \
  '5JJgguLeLoTilFaguwVLxEUjczbcI1J0+q1h9Oedlp0=***REMOVED***' \
  'VlROU2VXSXlOVzVWUjBaN***REMOVED***' \
  'vXfLbDApVcznu90cZIy3+1vlgCfBlnIbGDQkNhgLXmE=***REMOVED***')
```

## Bundan sonra

`core/config.js` her sırrı ortamdan okur, varsayılan vermez ve eksik/kısa bir
değerde **açılışta durur**. Sessiz bir varsayılan en kötü sonucu verir: sistem
çalışır görünür ve gerçekte korumasızdır.

Gereken değişkenler için `core/config.js` içindeki `load()` fonksiyonuna bakın;
üretimde en azından şunlar gerekir:

```sh
FITFAK_IDP_DB_SECRET=            # base64, >= 32 bayt
FITFAK_IDP_DB_TARGET=            # uzak veritabanı (boşsa gömülü motor)
FITFAK_IDP_DB_CA_FINGERPRINT=    # ya da FITFAK_IDP_DB_CA_PATH
FITFAK_IDP_DB_ENROLMENT_SECRET=  # yalnızca İLK çalıştırmada
SMTP_HOST= SMTP_USER= SMTP_PASS=
```

`FITFAK_IDP_DB_ENROLMENT_SECRET` ilk enrolment'tan sonra ortamdan
kaldırılabilir: sertifika `.identity/` altına yazılır ve sonraki açılışlar
oradan devam eder, yenileme ise mTLS üzerinden yapılır.
