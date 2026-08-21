'use strict';

const ssl = require('@fitfak/ssl');
const { policyForProfile } = require('./pki-policy');
const { AppError } = require('./errors');
const spiffe = require('./spiffe');
const { openCaVault } = require('./ca-vault');
const { OCSP_URL, STATUS_BASE, caIssuersUrlFor, crlUrlFor } = require('./pki-urls');
const {
  PROFILE_MAP, PKI_PURPOSES, MIN_SHORT_LIVED_SECONDS, MAX_SHORT_LIVED_SECONDS, BACKDATE_SECONDS,
} = require('./certificate-profiles');

// trust.fitfak.net'in imzalama tarafı.
//
// Bu dosya yalnızca POLİTİKA kurar: hangi profil ne kadar yaşar, hangi ara CA
// tarafından imzalanır, hangi politika OID'ini taşır, hangi adresleri gösterir,
// kimliği nereye yazar. Baytların üretimi @fitfak/ssl'in işi, anahtarların
// saklanması core/ca-vault.js'in işi.
//
// İki şey değişti ve ikisi de mimari:
//
//   1. ANAHTARLAR DOSYADA DEĞİL. Kök ve ara CA'lar veritabanının şifreli sır
//      deposunda duruyor (core/ca-vault.js). Bu dosya artık hiçbir şey okumuyor
//      ya da yazmıyor; kasadan bir imzalayıcı istiyor.
//
//   2. KISA ÖMÜRLÜ SERTİFİKALAR VAR. Google BeyondCorp modelinde bir iş yükü
//      sertifikası dakikalarla ölçülür ve KENDİ SÜRESİNİN DOLMASI iptal
//      mekanizmasıdır -- çünkü bir iptalin yayılmasından daha hızlı geçersizleşir.
//      Bu, CRL/OCSP'yi gereksiz kılmaz ama nadir kılar: normal işleyişte hiçbir
//      şey iptal edilmez, yalnızca yenilenmez.


// AIA caIssuers ve CRL dağıtım noktası, İMZALAYAN OTORİTEYE göre değişir.
//
// Bu, düzeltilmiş bir hatadır. Önceki hâlde iki sabit adres vardı:
//
//     const CA_ISSUERS_URL = `${STATUS_BASE}/intermediate.crt`;
//     const CRL_URL        = `${STATUS_BASE}/crl`;
//
// ve her uç sertifikaya bunlar gömülüyordu. Tek bir ara CA varken doğruydu. Artık BEŞ tane var
// (her amaç için ayrı, gerekçe core/ca-vault.js'de) ve iki sabit adres iki ayrı şeyi bozuyordu:
//
//   ZİNCİR KURULAMIYOR. Eksik ara sertifikayı AIA'dan tamamlamaya çalışan bir doğrulayıcı
//   /intermediate.crt'yi çeker ve orada BAŞKA bir ara CA'yı bulur. Sertifikanın AKI'si onu
//   göstermediği için zincir kurulmaz. Hata mesajı "unable to get local issuer certificate"
//   olur ve doğru ara sertifikayı zaten gönderen sunucularda sorun GÖRÜNMEZ -- yalnızca
//   zinciri eksik gönderen bir eşle konuşulduğunda ortaya çıkar.
//
//   İPTAL SESSİZCE ETKİSİZ. RFC 5280 §6.3.3: bir CRL yalnızca KENDİ yayıncısının verdiği
//   sertifikalar hakkında konuşur. e-posta CA'sının imzaladığı bir sertifikanın iptalini
//   iş yükü CA'sının imzaladığı bir listede aramak, hiçbir şey bulmamak demektir -- ve
//   doğrulayıcı bunu "iptal edilmemiş" olarak okur. İptal kaydı üretilir, yayınlanır ve
//   dikkate alınmaz.
//
// Adresler otoritenin KASADAKİ ADIYLA (workload-ca, email-ca, ...) kuruluyor. Parmak izi ya da
// SKID de kullanılabilirdi; ad, bir operatörün bir sertifikanın içindeki adrese bakıp onu hangi
// otoritenin verdiğini okuyabilmesini sağlıyor.
// Kurucular core/pki-urls.js'de, onları ÇÖZEN durum sunucusuyla aynı dosyada (dosyanın başındaki
// require). Burada ayrıca tanımlamak, iki tarafın sessizce ayrışabildiği eski hâle dönmek olurdu.

class ProductionPkiIssuer {
  constructor({ vault, ctLog = null, trustDomain = spiffe.TRUST_DOMAIN }) {
    this.vault = vault;
    this.ctLog = ctLog;
    this.trustDomain = trustDomain;
    // Zincirler amaca göre önbelleklenir. Kısa ömürlü sertifikaların ima ettiği
    // üretim hızında (her iş yükü, ömrün yarısında bir) her imzalamada zinciri
    // yeniden kurmak, kasadan okuma başına bir tur demektir.
    this._chains = new Map();
  }

  /**
   * Kasayı açar, eksik otoriteleri üretir, diskteki eski malzemeyi içeri alır.
   *
   * Eski `new ProductionPkiIssuer(caDir)` biçimi kasıtlı olarak KALDIRILDI: o
   * imza senkron çalışıyordu ve dosyadan okuyordu; ikisi de artık doğru değil ve
   * geriye dönük bir sarmalayıcı bırakmak, hangi kurulumun anahtarı nereden
   * aldığını belirsiz kılardı.
   */
  static async open({ db, caDir = null, ctLog = null, trustDomain = spiffe.TRUST_DOMAIN, logger = console }) {
    const { vault } = await openCaVault({ db, caDir, ssl, trustDomain, logger });
    const issuer = new ProductionPkiIssuer({ vault, ctLog, trustDomain });
    await issuer._loadPublicViews();
    return issuer;
  }

  /**
   * `rootCA` ve `subCA`: SENKRON okunabilen, ÖZEL ANAHTAR İÇERMEYEN görünümler.
   *
   * OCSP ve CRL servisleri ile durum sunucusu bir sertifikanın PEM'ine ve SKID'ine
   * senkron erişmek istiyor -- "bu sorgu ara CA hakkında mı, uç sertifika hakkında
   * mı" gibi kararlar için. Onlara kasadan tam bir imzalayıcı vermek, kök ve ara
   * CA özel anahtarlarını süreç boyunca sıcak tutmak demek olurdu; oysa kasanın
   * bütün amacı, o anahtarların yalnızca imzalanırken çözülmesi.
   *
   * Buradaki nesnelerde `privateKey` YOKTUR ve olmaması bilinçlidir: bunlarla
   * yanlışlıkla bir şey imzalamak mümkün değil. İmzalamak isteyen
   * `vault.loadSigner(...)` çağırmak zorunda ve o çağrı, denetlenmesi gereken tek
   * yerdir.
   */
  async _loadPublicViews() {
    const root = await this.vault.getAuthority('root');
    const leafIssuer = await this.vault.findIssuerForPurpose(PKI_PURPOSES.TLS_CLIENT);

    const view = (authority) => ({
      name: authority.name,
      certPem: authority.certPem,
      subject: authority.subject,
      fingerprint: authority.fingerprint,
      notAfter: authority.notAfter,
      skid: skidOf(authority.certPem),
    });

    this.rootCA = view(root);
    this.subCA = view(leafIssuer);
    return this;
  }

  /** Bir amaç için istemcilere dağıtılacak zincir (ara + kök). */
  async getChainPem(purpose = PKI_PURPOSES.TLS_CLIENT) {
    if (this._chains.has(purpose)) return this._chains.get(purpose);
    const issuer = await this.vault.findIssuerForPurpose(purpose);
    const value = await this.getChainPemForAuthority(issuer.name);
    this._chains.set(purpose, value);
    return value;
  }

  /**
   * Bir otoritenin zinciri, ADIYLA -- amaçtan geçmeden.
   *
   * `/chain.pem` bunu kullanıyor. Önceden o adres HER ZAMAN varsayılan istemci zincirini
   * döndürüyordu: bir TLS sunucusunun eksik halkasını arayan doğrulayıcı, adresi takip edip
   * `client-ca`'yı alıyor ve zinciri yine kuramıyordu. Yanlış ara sertifikayı 200 ile
   * döndürmek, hiç döndürmemekten daha kötüdür -- doğrulayıcı aradığını bulduğunu sanır.
   *
   * Bilinmeyen otorite için `null`: çağıran 404 döndürebilsin, uydurma bir ada varsayılan
   * zinciri servis etmek yerine.
   */
  async getChainPemForAuthority(name) {
    const cacheKey = `authority:${name}`;
    if (this._chains.has(cacheKey)) return this._chains.get(cacheKey);
    if (!(await this.vault.getAuthority(name))) return null;
    const chain = (await this.vault.getChainPem(name)).map((pem) => pem.trim()).join('\n');
    const value = `${chain}\n`;
    this._chains.set(cacheKey, value);
    return value;
  }

  /** Yalnızca kök(ler): bir eşin sabitlediği ya da güven çıpası olarak kurduğu şey. */
  async getTrustAnchorsPem() { return this.vault.getTrustAnchorsPem(); }

  /**
   * Bir otoritenin sertifikası, ADIYLA.
   *
   * Durum sunucusu bunu AIA caIssuers adresine gelen istekleri karşılamak için kullanıyor.
   * Özel anahtar YÜKLENMİYOR: yayınlanacak olan sertifikadır ve `loadSigner` çağırmak, yalnızca
   * açık veri sunmak için kök ya da ara anahtarı belleğe çözmek olurdu.
   */
  async getAuthorityCertPem(name) {
    const authority = await this.vault.getAuthority(name);
    return authority ? authority.certPem : null;
  }

  /** Sertifikalara gömülen adreslerin üretildiği yer -- durum sunucusu aynı biçimi çözüyor. */
  static caIssuersUrlFor(name) { return caIssuersUrlFor(name); }
  static crlUrlFor(name) { return crlUrlFor(name); }

  /**
   * Bir otoritenin SKID'i, adıyla.
   *
   * OCSP yanıtı üretirken "bu ara CA'nın kendisi iptal edilmiş mi" sorusu buna dayanıyor: iptal
   * kayıtları SKID ile bulunuyor ve doğru otoritenin SKID'ine bakmayan bir kontrol, iptal edilmiş
   * BAŞKA bir ara CA yüzünden geçerli sertifikaları iptal ilan ederdi -- ya da tersi.
   */
  async getAuthoritySkidHex(name) {
    const certPem = await this.getAuthorityCertPem(name);
    if (!certPem) return null;
    const skid = skidOf(certPem);
    return Buffer.isBuffer(skid) ? skid.toString('hex') : String(skid || '');
  }

  /** Uç sertifika imzalayan otoritelerin adları -- her birinin kendi iptal listesi var. */
  async listIssuingAuthorityNames() {
    const authorities = await this.vault.listAuthorities();
    return authorities.filter((a) => a.name !== 'root').map((a) => a.name);
  }

  async getRootPem() { return (await this.vault.getAuthority('root')).certPem; }

  /**
   * Bir CSR'den uç sertifika üretir.
   *
   * Subject, CSR'den DEĞİL, `subjectOverride` ile verilen doğrulanmış hesap
   * bilgisinden kurulur. Sertifikada yazan kimlik, başvuranın yazdığı değil,
   * IdP'nin doğruladığı kimliktir -- CSR'ye istenen her şey yazılabilir.
   *
   * @param {object}  opts
   * @param {string}  opts.csrPem
   * @param {string}  opts.profile
   * @param {object} [opts.subjectOverride]  { cn, email, sans }
   * @param {string} [opts.spiffeId]         SAN'a URI olarak yazılacak iş yükü kimliği
   * @param {number} [opts.validitySeconds]  profilin varsayılanını daraltır (uzatamaz)
   */
  async signCertificateFromCsr({
    csrPem, profile = 'client-auth', subjectOverride = {}, spiffeId = null, validitySeconds = null,
    checkKeyUniqueness = null,
  }) {
    const mapping = PROFILE_MAP[profile];
    if (!mapping) {
      throw new AppError('unknown_profile',
        `Bilinmeyen sertifika profili '${profile}'. Kullanılabilir: ${Object.keys(PROFILE_MAP).join(', ')}`,
        { httpStatus: 400 });
    }

    // CSR baytları İSTEMCİDEN gelir. Ayrıştırma hatası bir SUNUCU hatası değil,
    // bir istek hatasıdır: 500 dönmek, istemcinin gönderdiği bozuk baytı bizim
    // arızamız gibi gösterir ve arayan taraf düzeltebileceği bir şey olduğunu
    // anlayamaz.
    let csr;
    try {
      csr = ssl.parseCSR(csrPem);
    } catch (err) {
      throw new AppError('invalid_csr', `CSR okunamadı: ${err.message}`, { httpStatus: 400 });
    }
    if (!ssl.verifyCSR(csr)) {
      throw new AppError('invalid_csr',
        'CSR öz-imzası geçersiz -- anahtar sahipliği kanıtlanamadı', { httpStatus: 400 });
    }

    const parsedSpiffeId = this._resolveSpiffeId({ mapping, profile, spiffeId });

    // Anahtar tekilliği, İMZALAMADAN ÖNCE.
    //
    // Bu kontrol daha önce bir seçenek olarak GEÇİLİYOR ama hiç OKUNMUYORDU:
    // ACME servisi `checkKeyUniqueness` callback'ini yolluyor, yanındaki yorum
    // "pki.js motoru sertifika basmadan önce bu callback'i çağırır" diyor ve
    // imzalayıcı onu sessizce yok sayıyordu. Hiç çalışmayan bir kontrol,
    // olmayan bir kontrolden daha kötüdür: koruma gibi okunur.
    //
    // SKID, CSR'nin açık anahtarından imzalamadan ÖNCE hesaplanabilir -- zaten
    // sertifikaya da oradan yazılır -- yani kontrolün burada olması için bir
    // engel yoktu.
    //
    // AMA KONTROL, ETKİNLEŞTİRİLDİĞİ GÜN HER İSTEĞİ REDDEDİYORDU. Aday SKID şöyle
    // hesaplanıyordu:
    //
    //     skidOfPublicKeyPem(csr.publicKeyPem || ssl.parseCSR(csrPem).publicKeyPem)
    //
    // `parseCSR` `publicKeyPem` DİYE BİR ALAN DÖNDÜRMÜYOR. İkinci ayrıştırma da aynı
    // `undefined`'ı veriyor, ve `skidOfPublicKeyPem` onu "CSR'nin açık anahtarı okunamadı"
    // diye 400'e çeviriyordu. Bu geri dönüşü yalnızca ACME kullanıyor (tek `checkKeyUniqueness`
    // geçiren yol), yani GEÇERLİ bir CSR ile yapılan her ACME sertifika talebi, CSR'nin
    // okunamadığını söyleyen bir hatayla düşüyordu -- CSR'de bir sorun olmadığı hâlde.
    //
    // Artık SKID, ayrıştırılmış CSR'nin açık anahtarından, @fitfak/ssl'in sertifikaya YAZARKEN
    // kullandığı yolun aynısıyla hesaplanıyor. Aynı kaynaktan gelmesi şart: kontrolün baktığı
    // değer ile sertifikada duran değer ayrışırsa, tekillik kaydı hiçbir zaman eşleşmez.
    if (typeof checkKeyUniqueness === 'function') {
      const candidateSkid = skidOfCsr(csr);
      if (await checkKeyUniqueness(candidateSkid.toString('hex'))) {
        throw new AppError('key_already_certified',
          'Bu açık anahtar için zaten bir sertifika üretilmiş. Yeni bir anahtar çifti ve CSR oluşturun.',
          { httpStatus: 409 });
      }
    }

    const email = subjectOverride.email || null;
    const requestedCn = subjectOverride.cn || email || 'FITFAK Unified Endpoint';

    // SAN: kimliğin GERÇEKTEN taşındığı yer.
    //
    // CSR'nin kendi SAN'ları BİLEREK taşınmıyor -- taşınsaydı başvuran, kendi
    // seçtiği bir alan adını ya da kendi seçtiği bir SPIFFE kimliğini sertifikaya
    // yazdırabilirdi ve bu tam olarak kaçınmak istediğimiz şey.
    //
    // CN'i de buradan alıyoruz: bir TLS sunucu sertifikasında CN, SAN'lardan biri olmalı ve
    // hangisi olacağına SAN listesini kuran taraf karar verebilir.
    const { sans, commonName } = this._buildSans({
      mapping, profile, parsedSpiffeId, email, commonName: requestedCn, subjectOverride,
    });

    const subject = { C: 'TR', O: 'FITFAK Global Trust Network', CN: commonName };
    if (email) subject.emailAddress = email;

    const { notBefore, notAfter } = this._validityWindow({ mapping, validitySeconds });
    const serialNumberHex = ssl.newSerial();
    // Adı ayrıca tutuluyor: sertifikaya gömülecek AIA ve CRL adresleri ondan kuruluyor ve
    // çağırana da dönüyor, ki iptal kaydı hangi listeye ait olduğunu bilsin.
    const issuerName = (await this.vault.findIssuerForPurpose(mapping.purpose)).name;
    const issuer = await this.vault.loadSigner(issuerName);

    const baseOptions = {
      profile: mapping.sslProfile,
      subjectOverride: subject,
      includeCsrSans: false,
      sans,
      serialNum: serialNumberHex,
      notBefore,
      notAfter,
      policies: policyForProfile(profile),
      ocspUrl: OCSP_URL,
      caIssuersUrl: caIssuersUrlFor(issuerName),
      // Hem OCSP hem CRL veriliyor. OCSP tazedir ama tek bir servise bağlıdır;
      // CRL bayattır ama önbelleklenebilir ve responder ulaşılamazken de çalışır.
      // Yalnızca birini vermek, o biri düştüğünde doğrulayıcıyı "iptal durumu
      // bilinmiyor" ile baş başa bırakır.
      crlUrls: [crlUrlFor(issuerName)],
    };

    const sctExtension = mapping.shortLived ? null : await this._maybeLogToCt(csr, issuer, baseOptions);

    const issued = ssl.issueCertificateFromCSR(csr, issuer, {
      ...baseOptions,
      ...(sctExtension ? { extraExtensions: [sctExtension] } : {}),
    });

    const skid = issued.skid;
    return {
      certPem: `${issued.pem.trim()}\n${await this.getChainPem(mapping.purpose)}`,
      leafPem: issued.pem,
      chainPem: await this.getChainPem(mapping.purpose),
      serialNumberHex: typeof serialNumberHex === 'bigint' ? serialNumberHex.toString(16) : String(serialNumberHex),
      skidHex: Buffer.isBuffer(skid) ? skid.toString('hex') : String(skid),
      // Kaydedilmesi gereken: bir iptal, ancak DOĞRU listeye düştüğünde etkilidir ve o liste
      // sertifikayı kimin imzaladığına bağlıdır. Kayıtta durmazsa, iptal anında hangi CA'nın
      // listesine yazılacağı tahmin edilmek zorunda kalınır.
      issuerName,
      spiffeId: parsedSpiffeId ? parsedSpiffeId.uri : null,
      profile,
      shortLived: !!mapping.shortLived,
      notBefore,
      notAfter,
    };
  }

  /**
   * Sertifikaya yazılacak SAN listesi -- ve bir TLS SUNUCU sertifikasının onsuz üretilemeyeceği
   * kural.
   *
   * BU BİR DÜZELTME VE DÜZELTTİĞİ ŞEY SESSİZDİ. Uç sertifika üretimi `includeCsrSans: false`
   * ile çalışıyor (doğru: başvuran kendi alan adını yazdıramamalı) ve SAN'lar yalnızca
   * `subjectOverride.sans`'tan geliyor. `server-auth` profilini kullanan İKİ çağıran onu
   * hiç geçirmiyordu:
   *
   *   * ACME finalize -- doğrulanmış alan adlarını `subjectOverride.cn`'e koyuyor, SAN'a değil
   *   * certificate-service -- kullanıcı adını CN yapıyor, SAN olarak yalnızca e-posta koyuyor
   *
   * Çıkan şey, dNSName TAŞIMAYAN bir TLS sunucu sertifikasıydı. RFC 6125 §6.4.4'ten beri
   * hiçbir modern istemci CN'e bakmaz: Chrome, Firefox, Windows schannel ve Go'nun crypto/tls'i
   * SAN'ı olmayan bir sunucu sertifikasını doğrudan reddeder. Sertifika üretilir, PEM olarak
   * döner, zinciri doğrulanır ve yalnızca bir TLS el sıkışmasında -- onu üreten koddan bir ağ
   * hattı ötede -- işe yaramadığı anlaşılır. ACME ile alınan bir sertifikanın öyle çıkması,
   * tam olarak "CSR gönderiyorum, saçma bir şey geliyor" demektir.
   *
   * Kural: bir TLS sunucu sertifikası, kapsadığı adları AÇIKÇA verilmiş SAN'lardan alır ve
   * hiçbiri yoksa ÜRETİLMEZ.
   *
   * CN'den TÜRETİLMİYOR ve bu bilinçli. Türetmek ilk bakışta yardımcı görünüyor -- ACME
   * kimliği zaten CN'e yazılıyor -- ama CN'e yazılan şey her çağrı yerinde alan adı değil.
   * certificate-service.js oraya KULLANICI ADINI koyuyordu; türetme olsaydı `DNS:alice` diye
   * bir SAN üretilir ve ortaya "geçerli görünen, hiçbir sunucuyu adlandırmayan" bir sertifika
   * çıkardı. Yani düzeltilmeye çalışılan saçmalığın biraz daha ikna edici bir hâli.
   *
   * Adı doğrulayan taraf onu SAN olarak da geçirir: ACME sipariş kimliklerinden (http-01 ile
   * doğrulanmış), certificate-service istekteki `dnsNames`'ten, db-bootstrap yapılandırmadaki
   * sunucu adlarından. Üçü de artık öyle yapıyor.
   */
  _buildSans({ mapping, profile, parsedSpiffeId, email, commonName, subjectOverride }) {
    const sans = [];
    const seen = new Set();
    const push = (entry) => {
      const normalized = normalizeSanEntry(entry, profile);
      if (!normalized) return;
      const key = `${normalized.type}:${String(normalized.value).toLowerCase()}`;
      // Aynı ad iki kez yazılırsa sertifika hâlâ geçerlidir ama bazı denetleyiciler bunu
      // bulgu olarak işaretler; ayrıca CN'i SAN'a eklemenin doğal sonucu tam olarak budur.
      if (seen.has(key)) return;
      seen.add(key);
      sans.push(normalized);
    };

    if (parsedSpiffeId) push(spiffe.toSanEntry(parsedSpiffeId));
    if (email) push({ type: 'email', value: email });
    for (const extra of subjectOverride.sans || []) push(extra);

    if (mapping.sslProfile === 'tls-server') {
      const serverNames = sans.filter((s) => s.type === 'dns' || s.type === 'ip');
      if (serverNames.length === 0) {
        throw new AppError('server_san_required',
          `'${profile}' bir TLS sunucu sertifikasıdır ve doğrulayıcılar sunucu adını yalnızca `
          + "SAN'da arar (RFC 6125 §6.4.4 -- CN on yıldır kimlik olarak okunmuyor). Bu istekte "
          + 'hiçbir dNSName ya da iPAddress yok, yani üretilecek sertifika hiçbir TLS el '
          + "sıkışmasında kabul edilmezdi. `subjectOverride.sans` içinde en az bir "
          + "{ type: 'dns', value: ... } girdisi verin.",
          { httpStatus: 400 });
      }
      // CN, SAN'lardan biri olmalı. İkisinin farklı şeyler söylediği bir sertifika teknik
      // olarak geçerlidir ama okuyan insanı yanıltır ve bir denetim kaydında hangisinin
      // "gerçek" olduğu sorusunu doğurur. Doğrulayıcının baktığı SAN'dır, o yüzden CN ona uyar.
      const cnMatchesSan = commonName && sans.some((s) => s.value === commonName);
      return { sans, commonName: cnMatchesSan ? commonName : serverNames[0].value };
    }

    return { sans, commonName };
  }

  _resolveSpiffeId({ mapping, profile, spiffeId }) {
    if (!spiffeId) {
      if (mapping.requiresSpiffeId) {
        // Kimliğini SAN'da taşıyan bir profil, SAN'ı olmadan üretilirse ortaya
        // doğrulanabilir hiçbir kimlik taşımayan bir sertifika çıkar -- ve SPIFFE
        // kimliğine bakan bir doğrulayıcı için o sertifika işe yaramaz, CN'e geri
        // düşen biri içinse yetkilendirmeyi taşıyan alanı düşürmüş çalışan bir
        // kimlik bilgisi olur.
        throw new AppError('spiffe_id_required',
          `'${profile}' profili kimliğini SAN'daki URI'de taşır; spiffeId zorunludur`,
          { httpStatus: 400 });
      }
      return null;
    }

    const parsed = spiffe.parse(spiffeId);
    if (parsed.trustDomain !== this.trustDomain) {
      // Başka bir güven alanı için sertifika üretmek, o alanın PKI'sını taklit
      // etmektir. Federasyon bir karardır ve kimse bakmadığı için gerçekleşen
      // federasyon, federasyon değildir.
      throw new AppError('foreign_trust_domain',
        `'${parsed}' '${parsed.trustDomain}' güven alanına ait; bu otorite yalnızca '${this.trustDomain}' için imzalar`,
        { httpStatus: 403 });
    }
    return parsed;
  }

  _validityWindow({ mapping, validitySeconds }) {
    const notBefore = new Date(Date.now() - BACKDATE_SECONDS * 1000);

    if (!mapping.seconds) {
      return { notBefore, notAfter: new Date(Date.now() + mapping.days * 86400000) };
    }

    let seconds = mapping.seconds;
    if (validitySeconds) {
      // Çağıran ömrü yalnızca DARALTABİLİR. Uzatabilseydi, profilin ömrü bir
      // varsayılan olurdu; kısa ömürlülüğün tek anlamı ise onun bir SINIR olması.
      seconds = Math.min(Number(validitySeconds), mapping.seconds);
    }
    seconds = Math.max(MIN_SHORT_LIVED_SECONDS, Math.min(MAX_SHORT_LIVED_SECONDS, seconds));

    return { notBefore, notAfter: new Date(Date.now() + seconds * 1000) };
  }

  /**
   * Certificate Transparency (RFC 6962).
   *
   * SCT sertifikanın İÇİNE yazılır, ama SCT'yi almak için sertifikayı log'a
   * göndermek gerekir. RFC 6962 bu döngüyü ÖNSERTİFİKA ile kırar: aynı seri ve
   * aynı içerikle, ama "poison" uzantısıyla (kritik ve hiçbir istemcinin
   * tanımadığı, dolayısıyla hiçbir yerde geçerli sayılmayan) bir sertifika
   * imzalanır, log onu kabul edip SCT döner, sonra AYNI TBS poison yerine SCT
   * listesiyle yeniden imzalanır.
   *
   * KISA ÖMÜRLÜ SERTİFİKALAR LOG'A YAZILMAZ. İki nedeni var ve ikisi de pratik:
   * beş dakikalık bir sertifika log'a yazıldığında zaten süresi dolmak üzeredir,
   * yani izleyicilere hiçbir şey söylemez; ve önsertifika turu, üretim gecikmesini
   * ikiye katlar -- ömrün yarısında bir yenilenen bir filoda bu, sürekli bir yük.
   * CT'nin çözdüğü sorun (bir CA'nın sessizce yanlış sertifika üretmesi) burada
   * sertifikanın kendisinin dakikalar içinde yok olmasıyla sınırlanır.
   */
  async _maybeLogToCt(csr, issuer, baseOptions) {
    if (!this.ctLog) return null;

    const precert = ssl.issueCertificateFromCSR(csr, issuer, {
      ...baseOptions,
      extraExtensions: [ssl.buildPoisonExtension()],
    });
    const issuerSpkiDer = new (require('node:crypto').X509Certificate)(issuer.certPem)
      .publicKey.export({ type: 'spki', format: 'der' });
    const sct = await this.ctLog.add({ certDer: precert.der, issuerSpkiDer, precert: true });
    return ssl.buildSctListExtension([sct]);
  }

  /**
   * OCSP yanıtı üretir. Yanıt, uç sertifikaları imzalayan ara CA ile imzalanır --
   * OCSP yanıtını imzalayan anahtar, sorulan sertifikanın YAYINCISI olmalıdır
   * (RFC 6960 §4.2.2.2), aksi halde istemci yanıtı "unauthorized" sayar.
   */
  async generateOcspResponse({
    ocspRequestDer, statusLookup, purpose = PKI_PURPOSES.TLS_CLIENT, authority = null,
  }) {
    const pki = require('@fitfak/ssl/src/pki');
    const ocspRequest = pki.parseOcspRequest(ocspRequestDer);
    // `authority` verildiğinde amaç aranmıyor. Sorgu bir sertifika HAKKINDA ve o sertifikayı
    // hangi CA'nın imzaladığı kayıtta duruyor; amaçtan geriye türetmek, aynı amaca hizmet eden
    // ikinci bir CA eklendiği gün yanlış cevabı vermeye başlardı.
    const issuerName = authority || (await this.vault.findIssuerForPurpose(purpose)).name;
    const issuer = await this.vault.loadSigner(issuerName);
    const responderCertDer = ssl.certInfoFromPem(issuer.certPem).certDer;

    const statusMap = statusLookup instanceof Map
      ? statusLookup
      : new Map(Object.entries(statusLookup || {}));

    return pki.generateOcspResponse(ocspRequest, issuer, issuer, responderCertDer, statusMap);
  }

  /**
   * İki ayrı CRL üretilir ve bu ayrım anlamlıdır:
   *
   *   scope 'leaf' -> ara CA tarafından imzalanır, uç sertifikaların iptallerini taşır
   *   scope 'root' -> kök CA tarafından imzalanır, ARA CA'ların iptallerini taşır
   *
   * Bir CRL yalnızca KENDİ yayıncısının verdiği sertifikalar hakkında konuşabilir.
   * Uç sertifikaların iptallerini kök anahtarıyla imzalamak, kök o sertifikaların
   * yayıncısı olmadığı için doğrulayıcılar tarafından geçerli sayılmaz -- iptal
   * sessizce etkisiz kalır.
   */
  async signCrl({ revokedCerts, scope = 'leaf', purpose = PKI_PURPOSES.TLS_CLIENT, authority = null }) {
    const pki = require('@fitfak/ssl/src/pki');
    // Her ara CA'nın KENDİ listesi var, ve bu bir tercih değil bir gereklilik: RFC 5280 §6.3.3'e
    // göre bir CRL yalnızca kendi yayıncısının verdiği sertifikalar hakkında konuşur. Tek bir
    // "uç sertifikalar listesi" üretmek, o listeyi imzalayan CA'nın vermediği her sertifika için
    // sessizce etkisiz kalırdı.
    const signerName = authority || (scope === 'root'
      ? 'root'
      : (await this.vault.findIssuerForPurpose(purpose)).name);
    const signer = await this.vault.loadSigner(signerName);

    const revokedList = (revokedCerts || []).map((cert) => ({
      serial: typeof cert.serialNumberHex === 'bigint'
        ? cert.serialNumberHex
        : BigInt(`0x${String(cert.serialNumberHex).replace(/^0x/, '')}`),
      date: cert.revokedAt ? new Date(Number(cert.revokedAt)) : new Date(),
      reason: cert.reasonCode || 0,
    }));

    const crlPem = pki.generateCRL(signer, revokedList);
    return Buffer.from(
      crlPem.split('\n').filter((l) => l && !l.startsWith('-----')).join(''),
      'base64',
    );
  }
}

// RFC 1123 ana makine adı, isteğe bağlı joker etiketle. Tek etiketli adlar (`localhost`) de
// geçerli: bu dağıtımın veritabanı sunucu adları arasında var ve bir SAN olarak yazılması
// gereken şey ne yazıyorsa odur, ne yazması gerektiğini düşündüğümüz şey değil.
const DNS_LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const DNS_NAME_RE = new RegExp(`^(?:\\*\\.)?${DNS_LABEL}(?:\\.${DNS_LABEL})*$`, 'i');
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

function isDnsName(value) {
  const text = String(value || '');
  return text.length > 0 && text.length <= 253 && DNS_NAME_RE.test(text) && !IPV4_RE.test(text);
}

function isIpAddress(value) {
  const text = String(value || '');
  // IPv6 burada yalnızca kabaca tanınıyor: SAN'a yazan taraf @fitfak/ssl ve iPAddress
  // kodlaması IPv4 için tanımlı. Tanımak, IPv6'yı sessizce bir dNSName'e çevirmemek için.
  return IPV4_RE.test(text) || (text.includes(':') && /^[0-9a-f:.]+$/i.test(text));
}

/**
 * Bir SAN girdisini kanonik `{ type, value }` biçimine indirir.
 *
 * Düz dize de kabul ediliyor ve TÜRÜ ÇIKARSANIYOR. Çağıranların bir kısmı zaten öyle
 * geçiriyordu (`altNames: serverNames`) ve tür alanı olmayan bir girdinin sessizce düşmesi,
 * SAN'sız sertifikayı üreten hatanın ta kendisiydi -- düşen bir SAN hiçbir yerde hata vermez,
 * yalnızca sertifikada olmaz.
 */
function normalizeSanEntry(entry, profile) {
  if (!entry) return null;

  if (typeof entry === 'string') {
    const value = entry.trim();
    if (!value) return null;
    if (value.startsWith('spiffe://') || value.includes('://')) return { type: 'uri', value };
    if (value.includes('@')) return { type: 'email', value };
    if (isIpAddress(value)) return { type: 'ip', value };
    if (isDnsName(value)) return { type: 'dns', value };
    return null;
  }

  const type = String(entry.type || '').toLowerCase();
  const value = typeof entry.value === 'string' ? entry.value.trim() : '';
  if (!value) return null;
  if (!['dns', 'ip', 'email', 'uri'].includes(type)) {
    // @fitfak/ssl bilinmeyen bir türde `SAN: bilinmeyen tür` diye fırlatır ve o hata
    // imzalamanın ortasından gelir. Burada yakalamak, arayana ne yollamış olduğunu söyler.
    throw new AppError('invalid_san',
      `'${profile}' isteğinde tanınmayan SAN türü '${entry.type}'; dns, ip, email ya da uri olmalı`,
      { httpStatus: 400 });
  }
  if (type === 'dns' && !isDnsName(value)) {
    throw new AppError('invalid_san',
      `'${value}' geçerli bir alan adı değil; dNSName olarak yazılamaz`, { httpStatus: 400 });
  }
  return { type, value };
}

/**
 * Bir sertifikanın Subject Key Identifier'ı.
 *
 * RFC 5280 §4.2.1.2 (yöntem 1) SKID'i subjectPublicKey BIT STRING'inin SHA-1'i
 * olarak tanımlar -- yani HAM anahtar baytlarının, tüm SubjectPublicKeyInfo
 * yapısının değil. EC için bu, sıkıştırılmamış nokta: 0x04 || X || Y.
 *
 * SPKI DER'i geçirmek sessizce BAŞKA bir değer üretir; ve o değer hiçbir yerde
 * hata vermez, yalnızca "bu OCSP sorgusu ara CA hakkında mı" gibi
 * karşılaştırmaların hiçbir zaman eşleşmemesine yol açar.
 */
function skidOf(certPem) {
  return skidFromJwk(new (require('node:crypto').X509Certificate)(certPem)
    .publicKey.export({ format: 'jwk' }));
}

/**
 * Bir CSR'nin açık anahtarının SKID'i -- @fitfak/ssl sertifikaya yazarken ne hesaplıyorsa o.
 *
 * RSA ve EC ayrı hesaplanır (RFC 5280 §4.2.1.2 yöntem 1 ikisinde de subjectPublicKey BIT
 * STRING'inin SHA-1'i, ama o baytlar anahtar türüne göre farklı kurulur). Yalnızca EC'yi
 * hesaplamak, bir RSA CSR'sinde sessizce yanlış bir değer üretirdi -- ve o değer hiçbir yerde
 * hata vermez, yalnızca tekillik kaydının hiçbir zaman eşleşmemesine yol açar.
 */
function skidOfCsr(csr) {
  const key = csr && csr.publicKey;
  if (!key) {
    throw new AppError('invalid_csr',
      "CSR'nin açık anahtarı okunamadı; anahtar tekilliği kontrol edilemez", { httpStatus: 400 });
  }
  return key.keyType === 'rsa'
    ? ssl.asn1.computeRsaSKID(key.n, key.e)
    : ssl.asn1.computeEcSKID(key.publicKeyBuf);
}

/** Aynı hesap, bir sertifika yerine bir açık anahtar PEM'inden. */
function skidOfPublicKeyPem(publicKeyPem) {
  if (!publicKeyPem) {
    throw new AppError('invalid_csr',
      'CSR\'nin açık anahtarı okunamadı; anahtar tekilliği kontrol edilemez', { httpStatus: 400 });
  }
  return skidFromJwk(require('node:crypto').createPublicKey(publicKeyPem).export({ format: 'jwk' }));
}

function skidFromJwk(jwk) {
  const point = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(jwk.x, 'base64url'),
    Buffer.from(jwk.y, 'base64url'),
  ]);
  return ssl.asn1.computeEcSKID(point);
}

module.exports = {
  ProductionPkiIssuer,
  skidOf,
  skidOfCsr,
  skidOfPublicKeyPem,
  PROFILE_MAP,
  PKI_PURPOSES,
  // Adresler core/pki-urls.js'de ve buradan yeniden dışa veriliyor: onları bu modülden alan
  // çağıranlar var ve tek başına taşımak, iki yerden farklı cevap alınabilen bir durum yaratırdı.
  // CRL_URL ve CA_ISSUERS_URL artık SABİT DEĞİL -- imzalayan otoriteye göre değişiyorlar, o
  // yüzden burada bir değer değil bir kurucu var.
  STATUS_BASE,
  OCSP_URL,
  caIssuersUrlFor,
  crlUrlFor,
  MIN_SHORT_LIVED_SECONDS,
  MAX_SHORT_LIVED_SECONDS,
  BACKDATE_SECONDS,
};
