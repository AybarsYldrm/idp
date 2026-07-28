'use strict';

// SADECE TEST içindir. @fitfak/database'in DatabaseManager/collection arayüzünü TAM
// olarak taklit ETMEZ (alan-düzeyi şifreleme yok, disk kalıcılığı yok, blindIndex/MLS
// anahtar sarma yok) -- sadece services/*.js'in beklediği METOD ŞEKLİNİ
// (insert/get/findOne/update/scan) sağlayarak iş mantığını gerçek bir veritabanı olmadan
// uçtan uca test etmeyi mümkün kılar. `scan()` (async iterator) GERÇEK API'de doğrulanan
// desendir (bkz. db/query-utils.js) -- `findAll` diye bir metod YOKTUR.

let idCounter = 1;

function createMockCollection() {
  const rows = new Map(); // id (string) -> record

  return {
    async insert(obj) {
      const id = String(idCounter++);
      rows.set(id, { _id: id, ...obj });
      return id;
    },
    // GERÇEK API'de var (bkz. @fitfak/database Collection#insertUnique): kontrolü
    // yazma kuyruğunun İÇİNDE yapıp UNIQUE_CONSTRAINT ile döner.
    //
    // Buraya eklenmesinin sebebi ders niteliğinde: mock'ta olmadığı için,
    // sertifika üretimini mock ile koşturan test "insertUnique is not a
    // function" ile 500 alıyordu -- yani test ikilisi gerçek adaptörün
    // GERİSİNDEYDİ ve ürünün gerçekten koştuğu yolu hiç sınamıyordu. Aynı
    // desen bu projede iki gerçek hatayı daha gizlemişti.
    async insertUnique(obj, { unique } = {}) {
      if (!unique || unique.length === 0) {
        throw new Error('mock-db: insertUnique en az bir `unique` alanı ister');
      }
      for (const field of unique) {
        for (const row of rows.values()) {
          if (row[field] === obj[field]) {
            const err = new Error(`mock-db: '${field}' zaten var: ${obj[field]}`);
            err.code = 'UNIQUE_CONSTRAINT';
            err.field = field;
            err.value = obj[field];
            throw err;
          }
        }
      }
      const id = String(idCounter++);
      rows.set(id, { _id: id, ...obj });
      return id;
    },
    async get(id) {
      return rows.get(String(id)) || null;
    },
    async findOne(field, value) {
      for (const row of rows.values()) if (row[field] === value) return row;
      return null;
    },
    async* scan() {
      for (const row of rows.values()) yield row;
    },
    async update(id, patch) {
      const row = rows.get(String(id));
      if (!row) return null;
      Object.assign(row, patch);
      return row;
    },
    async delete(id) {
      return rows.delete(String(id));
    },
    _debugAll: () => [...rows.values()],
  };
}

function createMockDb(collectionNames) {
  const collections = new Map();
  for (const name of collectionNames) collections.set(name, createMockCollection());
  return {
    collection(name) {
      if (!collections.has(name)) throw new Error(`mock-db: tanımsız koleksiyon '${name}'`);
      return collections.get(name);
    },
  };
}

module.exports = { createMockDb, createMockCollection };
