'use strict';

const crypto = require('node:crypto');

const base64url = require('./base64url');

// IdP'nin KENDİ sayfaları arasındaki dönüş adresleri.
//
// Önceki hâl `?return_to=%2Fadmin` idi ve iki ayrı sorunu vardı:
//
//   1. AÇIK YÖNLENDİRME YÜZEYİ. Adres çubuğundan gelen bir yol, doğrulanmadan kullanıldığında
//      kullanıcı gerçek alan adında giriş yapar ve saldırganın sayfasına iner. Bu, hem sunucu
//      hem sayfa tarafında `safeRedirect` ile kapatılmıştı -- ama kapatılmış olması, yüzeyin
//      var olmadığı anlamına gelmiyor: her yeni çağrı yerinde tekrar doğru yapılması gereken
//      bir şey var demektir, ve o çağrı yerlerinden biri unutulduğunda kimse fark etmez.
//
//   2. YOL ADRES ÇUBUĞUNDA GÖRÜNÜYOR. Kullanıcının nereye gitmeye çalıştığı, tarayıcı
//      geçmişine, ekran görüntüsüne ve omzunun üstünden bakan birine yazılıyor. `/admin`
//      gibi bir yol için bu, sistemin iç yapısını da söyler.
//
// Buradaki çözüm OAuth yönlendirme tutamaklarıyla AYNI: adres bir listede kayıtlı, ve URL'de
// yolun kendisi değil ona karşılık gelen opak bir TUTAMAK taşınıyor.
//
//     /login?return_to=%2Fadmin        ->    /login?ru=fru.9pQ2m4Kx...
//
// Fark yalnızca görsel değil: bir tutamak ancak bu listede varsa çözülür. Listede olmayan bir
// değer hiçbir yere çözülmez, yani doğrulanacak bir şey de yoktur. Açık yönlendirme,
// engellenmesi gereken bir şey olmaktan çıkıp ifade edilemez bir şey haline geliyor.
//
//
// TUTAMAK NEDEN RASTGELE DEĞİL DE TÜRETİLMİŞ
//
// Aynı hedef her zaman aynı tutamağı almalı. Rastgele üretilip saklansaydı, bir yeniden
// başlatma tüm tutamakları değiştirir ve dışarıda paylaşılmış her bağlantı kırılırdı. HMAC ile
// türetmek, sırrı bilen herkesin aynı cevabı hesaplamasını sağlıyor -- durum tutmadan.
//
// Sır, OAuth yönlendirme tutamaklarıyla AYNI sır (`config.redirectHandleSecret`). Ayrı bir sır
// daha iyi bir yalıtım vermezdi: ikisi de yalnızca "bu değer bizim ürettiğimiz mi" sorusunu
// cevaplıyor ve ikisinin de sızması aynı şeyi mümkün kılıyor -- yani hiçbir şeyi, çünkü tutamak
// gizli bir değer değil, KAYITLI bir değer.

const HANDLE_PREFIX = 'fru';

/**
 * Bu dağıtımın iç sayfaları.
 *
 * Liste KAPALI ve öyle kalmalı. Bir yolun buraya eklenmesi, "giriş sonrası kullanıcı buraya
 * gönderilebilir" demektir; açık bırakılan bir liste ise açık yönlendirmenin kendisidir.
 */
// Her hedef bir YOL ve bir YÜZEY taşır. Yüzey, o sayfanın hangi mantıksal host üzerinde
// dinlediğidir -- ve bu bilgi olmadan yönlendirme sessizce kırılıyordu.
//
// KIRILAN ŞEY ŞUYDU. `/admin` yalnızca one.fitfak.net'te (ADMIN_IP) bağlı. Oturumsuz bir
// kullanıcı oraya girdiğinde sunucu GÖRELİ bir adres yolluyordu:
//
//     location: /login?ru=fru.xxxx
//
// Tarayıcı göreli adresi BULUNDUĞU kökene göre çözer, yani kullanıcı
// one.fitfak.net/login'e gidiyordu -- ve `/login` yalnızca session.fitfak.net'te bağlı.
// Yönetici giriş yapamıyordu. Ters yönde de aynısı: giriş sayfası tutamağı çözüp
// `location.href = '/admin'` dediğinde, o an session.fitfak.net'te olduğu için
// session.fitfak.net/admin'e gidiyordu ve orada da /admin yok.
//
// Yani yönetim paneline giriş, her iki yönde de 404 ile bitiyordu ve hiçbir şey bunu
// söylemiyordu: iki adres de tek başına doğru görünüyor.
//
// Çözüm, yüzeyler arası her yönlendirmeyi MUTLAK adres yapmak. Aynı yüzey içindeki
// yönlendirmeler göreli kalıyor -- oraya mutlak adres koymak, yerel bir kurulumu
// yapılandırmadaki dış hostname'e göndermek olurdu.
const SURFACES = Object.freeze({ IDP: 'idp', ADMIN: 'admin', TRUST: 'trust' });

const DESTINATIONS = Object.freeze({
  portal: { path: '/portal', surface: SURFACES.IDP },
  profile: { path: '/profile', surface: SURFACES.IDP },
  consent: { path: '/consent', surface: SURFACES.IDP },
  cookies: { path: '/cookies', surface: SURFACES.IDP },
  device: { path: '/device', surface: SURFACES.IDP },
  admin: { path: '/admin', surface: SURFACES.ADMIN },
});

const DEFAULT_DESTINATION = '/portal';

/** Giriş sayfası HER ZAMAN kimlik yüzeyindedir; yönlendirmelerin mutlak olup olmayacağı buna bağlı. */
const LOGIN_SURFACE = SURFACES.IDP;

class InternalRedirects {
  /**
   * @param {object} opts
   * @param {Buffer|string} opts.secret       tutamakların türetildiği sır
   * @param {object} [opts.destinations]      ad -> yol
   */
  constructor({ secret, destinations = DESTINATIONS, origins = {} }) {
    if (!secret) throw new Error('[internal-redirects] tutamakları türetmek için bir sır gerekli');
    this.secret = secret;
    // Yüzey -> dış köken. Verilmeyen bir yüzey için köken YOK ve o yüzeye giden adres göreli
    // kalıyor: yapılandırılmamış bir hostname uydurmak, yerel bir kurulumu üretim adresine
    // göndermek olurdu.
    this.origins = { ...origins };
    this.byName = new Map();
    this.byPath = new Map();
    this.byHandle = new Map();

    for (const [name, value] of Object.entries(destinations)) {
      // Düz dize de kabul: eski çağrı yerleri ve testler `{ portal: '/portal' }` veriyor.
      const entry = typeof value === 'string'
        ? { path: value, surface: SURFACES.IDP }
        : { path: value.path, surface: value.surface || SURFACES.IDP };
      const handle = this._derive(entry.path);
      this.byName.set(name, entry);
      this.byPath.set(entry.path, handle);
      this.byHandle.set(handle, { name, path: entry.path, surface: entry.surface });
    }
  }

  /**
   * Bir yolu, üzerinde bulunulan yüzeyden BAKILDIĞINDA doğru olan adrese çevirir.
   *
   * Aynı yüzeydeyse göreli, farklı yüzeydeyse mutlak. Bu ayrım tek bir yerde olmalı: her
   * çağrı yerinde "bu hangi hostta?" diye düşünmek, o sorulardan birinin bir gün yanlış
   * cevaplanması demektir -- ve yanlış cevap 404 olarak, giriş yapmaya çalışan bir yöneticinin
   * ekranında ortaya çıkıyor.
   */
  _addressFor(path, surface, fromSurface) {
    if (!surface || surface === fromSurface) return path;
    const origin = this.origins[surface];
    return origin ? `${String(origin).replace(/\/+$/, '')}${path}` : path;
  }

  _derive(target) {
    const digest = crypto.createHmac('sha256', this.secret)
      .update(`${HANDLE_PREFIX} ${target}`)
      .digest();
    return `${HANDLE_PREFIX}.${base64url.encode(digest.subarray(0, 18))}`;
  }

  /**
   * Bir yolun tutamağı.
   *
   * Kayıtlı olmayan bir yol için `null` döner -- ve çağıranın bunu bir hata değil, "dönülecek
   * özel bir yer yok" olarak okuması gerekir. Kayıtsız bir yola tutamak üretmek, listeyi kapalı
   * tutmanın bütün anlamını ortadan kaldırırdı.
   */
  handleFor(target) {
    if (!target) return null;
    // Sorgu ve parça atılıyor: tutamak bir SAYFAYI gösterir, o sayfaya yapılmış belirli bir
    // isteği değil. Aksi halde her sorgu dizesi ayrı bir tutamak olurdu ve liste kapalı olmazdı.
    const path = String(target).split('?')[0].split('#')[0];
    return this.byPath.get(path) || null;
  }

  /** Adıyla: `redirects.handleForName('admin')`. */
  handleForName(name) {
    const entry = this.byName.get(name);
    return entry ? this.byPath.get(entry.path) : null;
  }

  /** Bir yolun hangi yüzeye ait olduğu; bilinmiyorsa null. */
  surfaceOf(target) {
    if (!target) return null;
    const path = String(target).split('?')[0].split('#')[0];
    for (const entry of this.byName.values()) if (entry.path === path) return entry.surface;
    return null;
  }

  /**
   * Tutamaktan yola.
   *
   * Bilinmeyen bir tutamak `null` döner. Çağıran o durumda varsayılana düşer -- bir hata
   * göstermek yerine, çünkü kullanıcı için "bağlantı eskimiş" ile "bir yerde bir hata var"
   * arasındaki fark yoktur ve ikisinin de doğru cevabı aynıdır: onu bir yere götürmek.
   */
  resolve(handle) {
    if (!handle) return null;
    const found = this.byHandle.get(String(handle));
    return found ? found.path : null;
  }

  /**
   * Giriş sonrası gidilecek yer: tutamak çözülürse orası, yoksa varsayılan.
   *
   * Tek çıkış noktası olması kasıtlı. Her çağrı yerinde "çöz, null ise varsayılana düş" yazmak,
   * o iki satırdan birinin bir yerde unutulacağı anlamına gelir.
   */
  destinationFor(handle, fallback = DEFAULT_DESTINATION) {
    const found = this.byHandle.get(String(handle || ''));
    if (!found) return fallback;
    // Bu, GİRİŞ SAYFASININ çözdüğü adres ve giriş sayfası her zaman kimlik yüzeyinde çalışır.
    // `/admin` için göreli bir yol döndürmek, tarayıcıyı session.fitfak.net/admin'e gönderirdi
    // -- orada /admin yok, çünkü yönetim yüzeyi one.fitfak.net'te.
    return this._addressFor(found.path, found.surface, LOGIN_SURFACE);
  }

  /**
   * Bir sayfaya, dönüş tutamağı ekli giriş bağlantısı.
   *
   * Giriş sayfası kimlik yüzeyinde. Hedef BAŞKA bir yüzeydeyse -- yani istek one.fitfak.net'e
   * gelmişse -- göreli bir `/login` adresi tarayıcıyı one.fitfak.net/login'e gönderir ve orada
   * giriş sayfası yoktur. O yüzden bağlantı mutlak oluyor.
   */
  loginUrl(target, extra = {}) {
    const params = new URLSearchParams();
    const handle = this.handleFor(target);
    if (handle) params.set('ru', handle);
    for (const [key, value] of Object.entries(extra)) {
      if (value !== undefined && value !== null && value !== '') params.set(key, String(value));
    }
    const query = params.toString();
    const path = query ? `/login?${query}` : '/login';
    // `fromSurface` hedefin yüzeyi: giriş oraya DÖNECEK, yani kullanıcı şu an oradadır.
    return this._addressFor(path, LOGIN_SURFACE, this.surfaceOf(target) || LOGIN_SURFACE);
  }

  /** Panel/teşhis için. Sırrı ya da türetme yolunu AÇMAZ, yalnızca eşlemeyi. */
  list() {
    return [...this.byHandle.entries()].map(([handle, entry]) => ({ ...entry, handle }));
  }
}

function createInternalRedirects(options) { return new InternalRedirects(options); }

module.exports = {
  InternalRedirects, createInternalRedirects,
  DESTINATIONS, DEFAULT_DESTINATION, HANDLE_PREFIX, SURFACES, LOGIN_SURFACE,
};
