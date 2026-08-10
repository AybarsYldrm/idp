'use strict';

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');

// Veritabanı henüz yokken IdP'nin çalışabilmesi.
//
// Sıralama şudur ve kaçınılmazdır: veritabanı mühürlü açılır ve IdP ona bir sunucu sertifikası
// verene kadar kimseye hizmet etmez. Yani IdP, veritabanına yazamadığı bir pencerede ayakta
// olmak zorundadır -- ve o pencerede yönetici giriş yapıp ilk yapılandırmayı (kendi hesabı,
// ilk uygulamalar) yapabilmelidir. Aksi halde sistem kendini açamayan bir kilit olur.
//
// Bu modül o pencereyi kapatır: yazmalar bellekte tutulur, bağlantı kurulduğu anda gerçek
// veritabanına SIRAYLA tekrar oynatılır ve ondan sonra her şey doğrudan geçer.
//
//
// NE OLDUĞU VE NE OLMADIĞI
//
// Bu bir ÖNBELLEK DEĞİL, bir AÇILIŞ TAMPONUDUR. Farkı önemli:
//
//   - Kalıcı değildir. Süreç boşaltmadan önce ölürse o pencerede yazılan her şey kaybolur.
//     Bunu diske yazmak, kimlik verisinin şifresiz bir dosyada durması demek olurdu -- ki
//     kök anahtarları oradan çıkarmak için harcanan çabanın tam tersi.
//   - Genel amaçlı bir çevrimdışı mod değildir. Veritabanı saatlerce erişilemezse tampon
//     sınırsız büyür; bir üst sınır var ve dolduğunda yazmalar REDDEDİLİR, sessizce
//     düşürülmez.
//   - Okumalar yalnızca tamponu görür. Veritabanında zaten var olan bir kayıt, bağlantı
//     kurulana kadar görünmez. Açılış penceresinde veritabanı zaten boş olduğu için bu
//     pratikte sorun değil, ama "bu tampon bir kopya değil" cümlesinin karşılığı budur.
//
//
// KİMLİK YENİDEN YAZIMI
//
// Tamponda üretilen kimlikler gerçek veritabanınınkiler değildir; boşaltma sırasında motor
// kendi kimliğini üretir. Bu, tamponda yazılmış bir referansı (bir oturumun userId'si, bir
// `userId:deviceId` bileşik anahtarı) bozardı.
//
// Çözüm, tampon kimliklerini ARANABİLİR yapmak: `stg_` + 32 onaltılık karakter. Boşaltma
// sırasında her metin alanında bu desenin geçtiği yerler gerçek kimlikle değiştirilir. Alt
// dize eşleşmesi güvenlidir çünkü bu desenin ilgisiz bir veride tesadüfen bulunma olasılığı
// yoktur -- ki tam da bu yüzden kimlikler kısa sayılar değil.
//
// Yeniden yazımın ULAŞMADIĞI yer: şifrelenmiş ya da base64'lenmiş bir gövdenin İÇİNE gömülmüş
// bir kimlik. Açılış penceresinde böyle bir şey yazılmıyor, ama bu bir varsayım ve burada
// yazılı olması gerekiyor.

const STAGED_ID_PREFIX = 'stg_';
const STAGED_ID_RE = /stg_[0-9a-f]{32}/g;

// Tamponun alabileceği azami işlem sayısı.
//
// Bir sınır olması şart: veritabanı hiç gelmezse bu yapı süreç belleğinde sınırsız büyür ve
// sonuç, kimlik sağlayıcısının OOM ile ölmesi olur. Dolduğunda yazmalar reddediliyor --
// sessizce düşürmek, yöneticiye kaydedildiğini söyleyip kaydetmemek demek olurdu.
const DEFAULT_MAX_OPERATIONS = 5000;

function stagedId() {
  return STAGED_ID_PREFIX + crypto.randomBytes(16).toString('hex');
}

class StagingFull extends Error {
  constructor(max) {
    super(`[fitfak-idp] Açılış tamponu doldu (${max} işlem). Veritabanına bağlanılamadığı sürece `
      + 'yeni yazma kabul edilmiyor. Veritabanı sunucusunun ayakta olduğunu doğrulayın.');
    this.name = 'StagingFull';
    this.code = 'staging_full';
    this.httpStatus = 503;
  }
}

class StagingCollection {
  constructor(store, name) {
    this.store = store;
    this.name = name;
    this.rows = new Map(); // id -> record
  }

  async insert(record) {
    const id = stagedId();
    const stored = { _id: id, ...record };
    this.rows.set(id, stored);
    this.store._record({ op: 'insert', collection: this.name, id, record });
    return id;
  }

  /**
   * Tekillik kontrolü tampon İÇİNDE yapılır ve boşaltmada gerçek veritabanı onu KENDİSİ
   * yeniden uygular. İkisi de gerekli: buradaki kontrol yöneticiye anında geri bildirim verir,
   * oradaki ise tamponun görmediği (veritabanında zaten var olan) bir çakışmayı yakalar.
   */
  async insertUnique(record, { unique } = {}) {
    if (!unique || unique.length === 0) throw new Error('staging: insertUnique en az bir `unique` alanı ister');
    for (const field of unique) {
      for (const row of this.rows.values()) {
        if (row[field] === record[field]) {
          const err = new Error(`staging: '${field}' zaten var`);
          err.code = 'UNIQUE_CONSTRAINT';
          err.field = field;
          throw err;
        }
      }
    }
    const id = stagedId();
    this.rows.set(id, { _id: id, ...record });
    this.store._record({ op: 'insertUnique', collection: this.name, id, record, unique });
    return id;
  }

  async get(id) { return this.rows.get(String(id)) || null; }

  async findOne(field, value) {
    for (const row of this.rows.values()) if (row[field] === value) return row;
    return null;
  }

  async find(field, value, { limit = 0 } = {}) {
    const out = [];
    for (const row of this.rows.values()) {
      if (row[field] === value) out.push(row);
      if (limit && out.length >= limit) break;
    }
    return out;
  }

  async findRange(field, min, max, { limit = 0 } = {}) {
    const out = [];
    for (const row of this.rows.values()) {
      const v = Number(row[field]);
      if (Number.isFinite(v) && v >= Number(min) && v <= Number(max)) out.push(row);
      if (limit && out.length >= limit) break;
    }
    return out;
  }

  async *scan() { for (const row of this.rows.values()) yield row; }

  async update(id, patch) {
    const row = this.rows.get(String(id));
    if (!row) return null;
    Object.assign(row, patch);
    this.store._record({ op: 'update', collection: this.name, id: String(id), patch });
    return row;
  }

  async delete(id) {
    const existed = this.rows.delete(String(id));
    if (existed) this.store._record({ op: 'delete', collection: this.name, id: String(id) });
    return existed;
  }

  async count() { return this.rows.size; }
}

class StagingStore extends EventEmitter {
  constructor({ maxOperations = DEFAULT_MAX_OPERATIONS, logger = null } = {}) {
    super();
    this.maxOperations = maxOperations;
    this._log = logger;
    this.collections = new Map();
    // Tek bir SIRALI işlem günlüğü. Koleksiyon başına ayrı günlük tutmak, oturumun
    // kullanıcıdan önce oynatılmasına ve referansının çözülememesine yol açardı.
    this.operations = [];
    this.schemas = [];
    this.startedAt = Date.now();
  }

  collection(name) {
    if (!this.collections.has(name)) this.collections.set(name, new StagingCollection(this, name));
    return this.collections.get(name);
  }

  async defineCollectionAsync(name, definition) {
    this.schemas.push({ name, definition });
    this.collection(name);
    return { staged: true, name };
  }

  async applySchemaRegistry(registry) {
    for (const [name, definition] of Object.entries(registry)) {
      await this.defineCollectionAsync(name, definition);
    }
    return { staged: true, collections: Object.keys(registry).length };
  }

  _record(operation) {
    if (this.operations.length >= this.maxOperations) throw new StagingFull(this.maxOperations);
    this.operations.push(operation);
    if (this.operations.length === 1) {
      this._log?.warn?.({
        msg: 'veritabanı henüz bağlı değil — yazmalar açılış tamponuna alınıyor',
        note: 'tampon bellektedir; bağlantı kurulmadan süreç ölürse bu pencerede yazılanlar kaybolur',
      });
    }
    this.emit('buffered', operation);
  }

  get size() { return this.operations.length; }

  status() {
    return {
      operations: this.operations.length,
      maxOperations: this.maxOperations,
      collections: [...this.collections.keys()],
      records: [...this.collections.values()].reduce((sum, c) => sum + c.rows.size, 0),
      since: this.startedAt,
    };
  }

  /**
   * Tamponu gerçek veritabanına boşaltır.
   *
   * Şema ÖNCE uygulanır: alanları tanımlanmamış bir koleksiyona yazmak, motorun kayıtları
   * reddetmesi ya da indeksleri kurmaması demek olurdu.
   *
   * İşlemler yazıldıkları SIRAYLA oynatılır ve her ekleme, ürettiği gerçek kimliği haritaya
   * yazar; sonraki işlemlerdeki tampon kimlikleri o haritayla değiştirilir.
   */
  async flushTo(db) {
    const idMap = new Map();
    const applied = { schemas: 0, inserts: 0, updates: 0, deletes: 0, conflicts: 0 };

    if (typeof db.applySchemaRegistry === 'function' && this.schemas.length) {
      const registry = {};
      for (const { name, definition } of this.schemas) registry[name] = definition;
      await db.applySchemaRegistry(registry);
      applied.schemas = Object.keys(registry).length;
    } else {
      for (const { name, definition } of this.schemas) {
        if (typeof db.defineCollectionAsync === 'function') await db.defineCollectionAsync(name, definition);
        else if (typeof db.defineCollection === 'function') await db.defineCollection(name, definition);
        applied.schemas += 1;
      }
    }

    for (const operation of this.operations) {
      const collection = db.collection(operation.collection);

      if (operation.op === 'insert' || operation.op === 'insertUnique') {
        const record = rewrite(operation.record, idMap);
        try {
          const realId = operation.op === 'insertUnique'
            ? await collection.insertUnique(record, { unique: operation.unique })
            : await collection.insert(record);
          idMap.set(operation.id, String(realId));
          applied.inserts += 1;
        } catch (err) {
          // Tekillik çakışması: aynı kayıt veritabanında ZATEN var. Bu, tamponun göremediği
          // bir durumdur ve bir hata değil bir birleşmedir -- boşaltmayı durdurmak, geri
          // kalan her şeyi de kaybetmek olurdu.
          if (isUniqueConflict(err)) {
            applied.conflicts += 1;
            this._log?.warn?.({
              collection: operation.collection,
              msg: 'boşaltma sırasında tekillik çakışması — kayıt veritabanında zaten vardı, atlandı',
            });
            continue;
          }
          throw err;
        }
        continue;
      }

      // Güncelleme ve silme, ekleme yapılmamış bir kimliğe işaret ediyorsa atlanır: o kayıt
      // aynı pencerede eklenip silinmiş olabilir, ya da çakışma yüzünden atlanmıştır.
      const realId = idMap.get(operation.id);
      if (!realId) continue;

      if (operation.op === 'update') {
        await collection.update(realId, rewrite(operation.patch, idMap));
        applied.updates += 1;
      } else if (operation.op === 'delete') {
        await collection.delete(realId);
        applied.deletes += 1;
      }
    }

    const summary = { ...applied, operations: this.operations.length };
    this.operations = [];
    for (const collection of this.collections.values()) collection.rows.clear();
    this.emit('flushed', summary);
    return summary;
  }
}

/**
 * Bir kaydın metin alanlarındaki tampon kimliklerini gerçek kimliklerle değiştirir.
 *
 * Alt dize üzerinden, tam eşitlik üzerinden değil: `userDeviceKey` gibi bileşik anahtarlar
 * (`<userId>:<deviceId>`) tam eşleşmeyle yakalanmaz ve yeniden yazılmadan bırakılırsa o kayıt
 * hiçbir zaman bulunamaz. Desen (`stg_` + 32 onaltılık) ilgisiz bir veride tesadüfen
 * bulunamayacak kadar dar.
 */
function rewrite(value, idMap) {
  if (typeof value === 'string') {
    if (!value.includes(STAGED_ID_PREFIX)) return value;
    return value.replace(STAGED_ID_RE, (match) => idMap.get(match) || match);
  }
  if (Array.isArray(value)) return value.map((item) => rewrite(item, idMap));
  if (value && typeof value === 'object' && !Buffer.isBuffer(value) && typeof value !== 'bigint') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = rewrite(v, idMap);
    return out;
  }
  return value;
}

function isUniqueConflict(err) {
  return err.code === 'UNIQUE_CONSTRAINT' || err.code === 'ALREADY_EXISTS'
    || /already exists|unique/i.test(err.message || '');
}

module.exports = { StagingStore, StagingCollection, StagingFull, stagedId, STAGED_ID_PREFIX };
