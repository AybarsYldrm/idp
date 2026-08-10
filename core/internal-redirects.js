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
const DESTINATIONS = Object.freeze({
  portal: '/portal',
  profile: '/profile',
  admin: '/admin',
  consent: '/consent',
  cookies: '/cookies',
  device: '/device',
});

const DEFAULT_DESTINATION = '/portal';

class InternalRedirects {
  /**
   * @param {object} opts
   * @param {Buffer|string} opts.secret       tutamakların türetildiği sır
   * @param {object} [opts.destinations]      ad -> yol
   */
  constructor({ secret, destinations = DESTINATIONS }) {
    if (!secret) throw new Error('[internal-redirects] tutamakları türetmek için bir sır gerekli');
    this.secret = secret;
    this.byName = new Map(Object.entries(destinations));
    this.byPath = new Map();
    this.byHandle = new Map();

    for (const [name, target] of this.byName) {
      const handle = this._derive(target);
      this.byPath.set(target, handle);
      this.byHandle.set(handle, { name, path: target });
    }
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
    const target = this.byName.get(name);
    return target ? this.byPath.get(target) : null;
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
    return this.resolve(handle) || fallback;
  }

  /** Bir sayfaya, dönüş tutamağı ekli bağlantı. */
  loginUrl(target, extra = {}) {
    const params = new URLSearchParams();
    const handle = this.handleFor(target);
    if (handle) params.set('ru', handle);
    for (const [key, value] of Object.entries(extra)) {
      if (value !== undefined && value !== null && value !== '') params.set(key, String(value));
    }
    const query = params.toString();
    return query ? `/login?${query}` : '/login';
  }

  /** Panel/teşhis için. Sırrı ya da türetme yolunu AÇMAZ, yalnızca eşlemeyi. */
  list() {
    return [...this.byHandle.entries()].map(([handle, entry]) => ({ ...entry, handle }));
  }
}

function createInternalRedirects(options) { return new InternalRedirects(options); }

module.exports = {
  InternalRedirects, createInternalRedirects,
  DESTINATIONS, DEFAULT_DESTINATION, HANDLE_PREFIX,
};
