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
