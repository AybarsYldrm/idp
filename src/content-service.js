'use strict';

/**
 * content-service.js
 * ---------------------------------------------------------------
 * Tıp Fakültesi "Ders Çalışma ve Soru Bankası" Platformu - İçerik Katmanı
 *
 * Mevcut custom.network gRPC altyapısına (server.js içindeki GrpcApplication)
 * iki yeni servis ekler:
 *
 *   - ContentService  : Komite > Ders > Konu > Soru hiyerarşisi (CRUD)
 *   - FeedbackService : Öğrencilerin hata/geribildirim bildirimleri
 *
 * Tasarım kararları:
 *   - İçerik (ders/soru verisi) kurumsal/paylaşılan bir veridir; bu yüzden
 *     her kullanıcının kendi şifreli "kasa"sında değil, zaten sunucu
 *     tarafından yönetilen `systemDb` (system_core) içinde saklanır.
 *     Öğrencinin içeriği görebilmek için bir "kasa şifresi" girmesine
 *     gerek YOKTUR — sadece giriş yapmış olması yeterlidir.
 *   - Karmaşık/iç içe veriler (şıklar, görsel listeleri, etiketler) mevcut
 *     kod tabanındaki `payloadJson` konvansiyonuna uyularak JSON string
 *     olarak saklanır/iletilir (InsertRecord/UpdateRecord ile aynı desen).
 *   - Yazma (Create/Update/Delete) uç noktaları sadece ADMIN rolüne
 *     sahip kullanıcılara açıktır; okuma (List/Get) uç noktaları giriş
 *     yapmış her kullanıcıya açıktır.
 *   - Rol biti: ROLE_MASKS.ADMIN (63) = ROLE_MASKS.USER (31) | 32.
 *     Yani 32 numaralı bit "içerik yönetici" yetkisidir.
 */

const { GRPC_STATUS } = require('./grpc-server');

const CONTENT_ADMIN_BIT = 32;

function isAdmin(call) {
  return !!(call && call.user && (Number(call.user.permissions) & CONTENT_ADMIN_BIT));
}

function requireAdmin(call) {
  if (!isAdmin(call)) {
    const err = new Error('Bu işlem için yönetici (içerik sorumlusu) yetkisi gereklidir.');
    err.code = GRPC_STATUS.PERMISSION_DENIED;
    throw err;
  }
}

function jsonSafe(_key, val) { return typeof val === 'bigint' ? val.toString() : val; }
function toJson(data) { return JSON.stringify(data, jsonSafe); }
function bySira(a, b) { return (parseInt(a.sira, 10) || 0) - (parseInt(b.sira, 10) || 0); }
function byTarihDesc(a, b) { return String(b.olusturulmaTarihi || '').localeCompare(String(a.olusturulmaTarihi || '')); }

async function scanAll(col) {
  const out = [];
  for await (const rec of col.scan()) out.push(rec);
  return out;
}

// `col.find(field, value)` bazı implementasyonlarda dizi, bazılarında tekil
// kayıt döndürebilir; ikisini de tolere edip her zaman dizi döndürüyoruz.
async function findMany(col, field, value) {
  const res = await col.find(field, value);
  if (Array.isArray(res)) return res;
  return res ? [res] : [];
}

async function getOrDefineCollection(db, name, fields) {
  try {
    return db.collection(name);
  } catch (e) {
    return db.defineCollectionAsync(name, { fields });
  }
}

function notFound(msg) {
  const err = new Error(msg);
  err.code = GRPC_STATUS.NOT_FOUND;
  return err;
}

/**
 * @param {object} opts
 * @param {object} opts.app     GrpcApplication örneği (server.js içindeki `app`)
 * @param {object} [opts.logger] mk('content') gibi bir logger; verilmezse console kullanılır
 */
function registerContentPlatform({ app, logger }) {
  const log = logger || console;
  const state = {
    db: null,
    komiteColl: null,
    dersColl: null,
    konuColl: null,
    soruColl: null,
    feedbackColl: null,
  };

  function assertReady() {
    if (!state.db) {
      const err = new Error('İçerik sistemi henüz başlatılmadı, birazdan tekrar deneyin.');
      err.code = GRPC_STATUS.UNAVAILABLE;
      throw err;
    }
  }

  async function initCollections(systemDb) {
    state.db = systemDb;

    state.komiteColl = await getOrDefineCollection(systemDb, 'komiteler', [
      { no: 2, name: 'donem', type: 'string', blindIndex: true },
      { no: 3, name: 'ad', type: 'string' },
      { no: 4, name: 'aciklama', type: 'string' },
      { no: 5, name: 'sira', type: 'string' },
      { no: 6, name: 'olusturulmaTarihi', type: 'string' },
    ]);

    state.dersColl = await getOrDefineCollection(systemDb, 'dersler', [
      { no: 2, name: 'komiteId', type: 'string', blindIndex: true },
      { no: 3, name: 'ad', type: 'string' },
      { no: 4, name: 'sira', type: 'string' },
      { no: 5, name: 'olusturulmaTarihi', type: 'string' },
    ]);

    state.konuColl = await getOrDefineCollection(systemDb, 'konular', [
      { no: 2, name: 'dersId', type: 'string', blindIndex: true },
      { no: 3, name: 'baslik', type: 'string' },
      { no: 4, name: 'icerik', type: 'string' },
      { no: 5, name: 'gorselUrlleriJson', type: 'string' },
      { no: 6, name: 'sira', type: 'string' },
      { no: 7, name: 'olusturulmaTarihi', type: 'string' },
      { no: 8, name: 'guncellemeTarihi', type: 'string' },
    ]);

    state.soruColl = await getOrDefineCollection(systemDb, 'sorular', [
      { no: 2, name: 'konuId', type: 'string', blindIndex: true },
      { no: 3, name: 'soruTipi', type: 'string' }, // 'coktan_secmeli' | 'klasik'
      { no: 4, name: 'soruMetni', type: 'string' },
      { no: 5, name: 'soruGorselUrl', type: 'string' },
      { no: 6, name: 'siklarJson', type: 'string' }, // [{harf:'A', metin:'...'}, ...] - sadece coktan_secmeli
      { no: 7, name: 'dogruSik', type: 'string' }, // 'A'..'E' - sadece coktan_secmeli
      { no: 8, name: 'cozumMetni', type: 'string' }, // klasik icin model cevap / ÇS icin aciklama
      { no: 9, name: 'cozumGorselUrl', type: 'string' },
      { no: 10, name: 'zorluk', type: 'string' }, // 'kolay' | 'orta' | 'zor'
      { no: 11, name: 'etiketlerJson', type: 'string' },
      { no: 12, name: 'olusturanId', type: 'string' },
      { no: 13, name: 'olusturulmaTarihi', type: 'string' },
      { no: 14, name: 'guncellemeTarihi', type: 'string' },
    ]);

    state.feedbackColl = await getOrDefineCollection(systemDb, 'geribildirimler', [
      { no: 2, name: 'hedefTip', type: 'string' }, // 'soru' | 'konu' | 'ders' | 'komite'
      { no: 3, name: 'hedefId', type: 'string', blindIndex: true },
      { no: 4, name: 'kullaniciId', type: 'string', blindIndex: true },
      { no: 5, name: 'kullaniciAdi', type: 'string' },
      { no: 6, name: 'mesaj', type: 'string' },
      { no: 7, name: 'durum', type: 'string', blindIndex: true }, // 'acik' | 'inceleniyor' | 'cozuldu'
      { no: 8, name: 'adminYaniti', type: 'string' },
      { no: 9, name: 'olusturulmaTarihi', type: 'string' },
      { no: 10, name: 'guncellemeTarihi', type: 'string' },
    ]);

    state.favoriColl = await getOrDefineCollection(systemDb, 'favoriler', [
      { no: 2, name: 'kullaniciId', type: 'string', blindIndex: true },
      { no: 3, name: 'hedefTip', type: 'string' }, // 'soru' | 'konu'
      { no: 4, name: 'hedefId', type: 'string', blindIndex: true },
      { no: 5, name: 'olusturulmaTarihi', type: 'string' },
    ]);

    state.programColl = await getOrDefineCollection(systemDb, 'ders_programi', [
      { no: 2, name: 'komiteId', type: 'string', blindIndex: true },
      { no: 3, name: 'hafta', type: 'string' }, // "1", "2" ... haftanın kaçıncı haftası
      { no: 4, name: 'gun', type: 'string' }, // 'Pazartesi'..'Pazar' veya bos (tum hafta)
      { no: 5, name: 'dersId', type: 'string' },
      { no: 6, name: 'dersAdi', type: 'string' },
      { no: 7, name: 'konuId', type: 'string' }, // opsiyonel
      { no: 8, name: 'konuBaslik', type: 'string' },
      { no: 9, name: 'not', type: 'string' },
      { no: 10, name: 'sira', type: 'string' },
      { no: 11, name: 'olusturulmaTarihi', type: 'string' },
    ]);

    (log.info || log)('[CONTENT] Komite/Ders/Konu/Soru/Geribildirim/Favori/Program koleksiyonları hazır.');
    return state;
  }

  // ================= ContentService =================
  app.registerController('ContentService', {

    GetContentSpace: {
      requiresAuth: true, request: [], response: [{ no: 1, name: 'dbId', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        return { dbId: String(state.db.dbId) };
      }
    },

    // ---------- KOMİTE ----------
    ListKomiteler: {
      requiresAuth: true, request: [], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async () => {
        assertReady();
        const list = (await scanAll(state.komiteColl)).sort(bySira);
        return { payloadJson: toJson(list) };
      }
    },
    CreateKomite: {
      requiresAuth: true, request: [{ no: 1, name: 'payloadJson', type: 'string' }], response: [{ no: 1, name: 'recordId', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const data = JSON.parse(req.payloadJson || '{}');
        if (!data.ad) { const err = new Error('Komite adı zorunludur.'); err.code = GRPC_STATUS.INVALID_ARGUMENT; throw err; }
        const doc = {
          donem: String(data.donem || ''), ad: String(data.ad), aciklama: String(data.aciklama || ''),
          sira: String(data.sira ?? 0), olusturulmaTarihi: new Date().toISOString(),
        };
        const id = String(await state.komiteColl.insert(doc));
        (log.info || log)(`[KOMITE OLUSTURULDU] ${id} - ${doc.ad} (${call.user.username})`);
        return { recordId: id };
      }
    },
    UpdateKomite: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }, { no: 2, name: 'payloadJson', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const existing = await state.komiteColl.get(req.id); if (!existing) throw notFound('Komite bulunamadı.');
        const data = JSON.parse(req.payloadJson || '{}');
        await state.komiteColl.update(req.id, {
          ...existing,
          donem: data.donem !== undefined ? String(data.donem) : existing.donem,
          ad: data.ad !== undefined ? String(data.ad) : existing.ad,
          aciklama: data.aciklama !== undefined ? String(data.aciklama) : existing.aciklama,
          sira: data.sira !== undefined ? String(data.sira) : existing.sira,
        });
        return { message: 'Komite güncellendi.' };
      }
    },
    DeleteKomite: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const baglıDersler = await findMany(state.dersColl, 'komiteId', req.id);
        if (baglıDersler.length > 0) { const err = new Error('Bu komiteye bağlı dersler var; önce dersleri silin.'); err.code = GRPC_STATUS.FAILED_PRECONDITION; throw err; }
        await state.komiteColl.delete(req.id);
        return { message: 'Komite silindi.' };
      }
    },

    // ---------- DERS ----------
    ListDersler: {
      requiresAuth: true, request: [{ no: 1, name: 'komiteId', type: 'string' }], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req) => {
        assertReady();
        const list = (req.komiteId ? await findMany(state.dersColl, 'komiteId', req.komiteId) : await scanAll(state.dersColl)).sort(bySira);
        return { payloadJson: toJson(list) };
      }
    },
    CreateDers: {
      requiresAuth: true, request: [{ no: 1, name: 'payloadJson', type: 'string' }], response: [{ no: 1, name: 'recordId', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const data = JSON.parse(req.payloadJson || '{}');
        if (!data.komiteId || !data.ad) { const err = new Error('Ders için komiteId ve ad zorunludur.'); err.code = GRPC_STATUS.INVALID_ARGUMENT; throw err; }
        const doc = { komiteId: String(data.komiteId), ad: String(data.ad), sira: String(data.sira ?? 0), olusturulmaTarihi: new Date().toISOString() };
        const id = String(await state.dersColl.insert(doc));
        (log.info || log)(`[DERS OLUSTURULDU] ${id} - ${doc.ad} (${call.user.username})`);
        return { recordId: id };
      }
    },
    UpdateDers: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }, { no: 2, name: 'payloadJson', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const existing = await state.dersColl.get(req.id); if (!existing) throw notFound('Ders bulunamadı.');
        const data = JSON.parse(req.payloadJson || '{}');
        await state.dersColl.update(req.id, {
          ...existing,
          ad: data.ad !== undefined ? String(data.ad) : existing.ad,
          sira: data.sira !== undefined ? String(data.sira) : existing.sira,
        });
        return { message: 'Ders güncellendi.' };
      }
    },
    DeleteDers: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const baglıKonular = await findMany(state.konuColl, 'dersId', req.id);
        if (baglıKonular.length > 0) { const err = new Error('Bu derse bağlı konular var; önce konuları silin.'); err.code = GRPC_STATUS.FAILED_PRECONDITION; throw err; }
        await state.dersColl.delete(req.id);
        return { message: 'Ders silindi.' };
      }
    },

    // ---------- KONU ----------
    ListKonular: {
      requiresAuth: true, request: [{ no: 1, name: 'dersId', type: 'string' }], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req) => {
        assertReady();
        const list = (req.dersId ? await findMany(state.konuColl, 'dersId', req.dersId) : await scanAll(state.konuColl)).sort(bySira);
        return { payloadJson: toJson(list) };
      }
    },
    GetKonu: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req) => {
        assertReady();
        const konu = await state.konuColl.get(req.id); if (!konu) throw notFound('Konu bulunamadı.');
        return { payloadJson: toJson(konu) };
      }
    },
    CreateKonu: {
      requiresAuth: true, request: [{ no: 1, name: 'payloadJson', type: 'string' }], response: [{ no: 1, name: 'recordId', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const data = JSON.parse(req.payloadJson || '{}');
        if (!data.dersId || !data.baslik) { const err = new Error('Konu için dersId ve başlık zorunludur.'); err.code = GRPC_STATUS.INVALID_ARGUMENT; throw err; }
        const now = new Date().toISOString();
        const doc = {
          dersId: String(data.dersId), baslik: String(data.baslik), icerik: String(data.icerik || ''),
          gorselUrlleriJson: JSON.stringify(Array.isArray(data.gorselUrlleri) ? data.gorselUrlleri : []),
          sira: String(data.sira ?? 0), olusturulmaTarihi: now, guncellemeTarihi: now,
        };
        const id = String(await state.konuColl.insert(doc));
        (log.info || log)(`[KONU OLUSTURULDU] ${id} - ${doc.baslik} (${call.user.username})`);
        return { recordId: id };
      }
    },
    UpdateKonu: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }, { no: 2, name: 'payloadJson', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const existing = await state.konuColl.get(req.id); if (!existing) throw notFound('Konu bulunamadı.');
        const data = JSON.parse(req.payloadJson || '{}');
        await state.konuColl.update(req.id, {
          ...existing,
          baslik: data.baslik !== undefined ? String(data.baslik) : existing.baslik,
          icerik: data.icerik !== undefined ? String(data.icerik) : existing.icerik,
          gorselUrlleriJson: data.gorselUrlleri !== undefined ? JSON.stringify(data.gorselUrlleri) : existing.gorselUrlleriJson,
          sira: data.sira !== undefined ? String(data.sira) : existing.sira,
          guncellemeTarihi: new Date().toISOString(),
        });
        return { message: 'Konu güncellendi.' };
      }
    },
    DeleteKonu: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const baglıSorular = await findMany(state.soruColl, 'konuId', req.id);
        if (baglıSorular.length > 0) { const err = new Error('Bu konuya bağlı sorular var; önce soruları silin.'); err.code = GRPC_STATUS.FAILED_PRECONDITION; throw err; }
        await state.konuColl.delete(req.id);
        return { message: 'Konu silindi.' };
      }
    },

    // ---------- SORU ----------
    ListSorular: {
      requiresAuth: true, request: [{ no: 1, name: 'konuId', type: 'string' }], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req) => {
        assertReady();
        const list = (req.konuId ? await findMany(state.soruColl, 'konuId', req.konuId) : await scanAll(state.soruColl));
        return { payloadJson: toJson(list) };
      }
    },
    GetSoru: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req) => {
        assertReady();
        const soru = await state.soruColl.get(req.id); if (!soru) throw notFound('Soru bulunamadı.');
        return { payloadJson: toJson(soru) };
      }
    },
    CreateSoru: {
      requiresAuth: true, request: [{ no: 1, name: 'payloadJson', type: 'string' }], response: [{ no: 1, name: 'recordId', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const data = JSON.parse(req.payloadJson || '{}');
        if (!data.konuId || !data.soruMetni || !data.soruTipi) { const err = new Error('konuId, soruTipi ve soruMetni zorunludur.'); err.code = GRPC_STATUS.INVALID_ARGUMENT; throw err; }
        const now = new Date().toISOString();
        const doc = {
          konuId: String(data.konuId),
          soruTipi: String(data.soruTipi), // 'coktan_secmeli' | 'klasik'
          soruMetni: String(data.soruMetni),
          soruGorselUrl: String(data.soruGorselUrl || ''),
          siklarJson: JSON.stringify(Array.isArray(data.siklar) ? data.siklar : []),
          dogruSik: String(data.dogruSik || ''),
          cozumMetni: String(data.cozumMetni || ''),
          cozumGorselUrl: String(data.cozumGorselUrl || ''),
          zorluk: String(data.zorluk || 'orta'),
          etiketlerJson: JSON.stringify(Array.isArray(data.etiketler) ? data.etiketler : []),
          olusturanId: String(call.user.id),
          olusturulmaTarihi: now, guncellemeTarihi: now,
        };
        const id = String(await state.soruColl.insert(doc));
        (log.info || log)(`[SORU OLUSTURULDU] ${id} (${call.user.username})`);
        return { recordId: id };
      }
    },
    UpdateSoru: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }, { no: 2, name: 'payloadJson', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const existing = await state.soruColl.get(req.id); if (!existing) throw notFound('Soru bulunamadı.');
        const data = JSON.parse(req.payloadJson || '{}');
        const merged = { ...existing };
        for (const key of ['soruTipi', 'soruMetni', 'soruGorselUrl', 'dogruSik', 'cozumMetni', 'cozumGorselUrl', 'zorluk']) {
          if (data[key] !== undefined) merged[key] = String(data[key]);
        }
        if (data.siklar !== undefined) merged.siklarJson = JSON.stringify(data.siklar);
        if (data.etiketler !== undefined) merged.etiketlerJson = JSON.stringify(data.etiketler);
        merged.guncellemeTarihi = new Date().toISOString();
        await state.soruColl.update(req.id, merged);
        return { message: 'Soru güncellendi.' };
      }
    },
    DeleteSoru: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        await state.soruColl.delete(req.id);
        return { message: 'Soru silindi.' };
      }
    },

    // ---------- HIZLI TEST: bir ders/komitedeki tüm soruları toplu getirme ----------
    ListSorularByDers: {
      requiresAuth: true, request: [{ no: 1, name: 'dersId', type: 'string' }], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req) => {
        assertReady();
        const konular = await findMany(state.konuColl, 'dersId', req.dersId);
        const all = [];
        for (const k of konular) {
          const sorular = await findMany(state.soruColl, 'konuId', k._id);
          sorular.forEach(s => all.push({ ...s, konuBaslik: k.baslik }));
        }
        return { payloadJson: toJson(all) };
      }
    },
    ListSorularByKomite: {
      requiresAuth: true, request: [{ no: 1, name: 'komiteId', type: 'string' }], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req) => {
        assertReady();
        const dersler = await findMany(state.dersColl, 'komiteId', req.komiteId);
        const all = [];
        for (const d of dersler) {
          const konular = await findMany(state.konuColl, 'dersId', d._id);
          for (const k of konular) {
            const sorular = await findMany(state.soruColl, 'konuId', k._id);
            sorular.forEach(s => all.push({ ...s, konuBaslik: k.baslik, dersAdi: d.ad }));
          }
        }
        return { payloadJson: toJson(all) };
      }
    },

    // ---------- ARAMA: konu başlığı/içeriği ve soru metni üzerinde ----------
    SearchContent: {
      requiresAuth: true, request: [{ no: 1, name: 'query', type: 'string' }], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req) => {
        assertReady();
        const q = String(req.query || '').trim().toLowerCase();
        if (q.length < 2) return { payloadJson: '[]' };

        const [komiteler, dersler, konular, sorular] = await Promise.all([
          scanAll(state.komiteColl), scanAll(state.dersColl), scanAll(state.konuColl), scanAll(state.soruColl)
        ]);
        const komiteById = new Map(komiteler.map(k => [k._id, k]));
        const dersById = new Map(dersler.map(d => [d._id, d]));
        const konuById = new Map(konular.map(k => [k._id, k]));
        const stripHtml = (html) => String(html || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();

        const results = [];
        for (const k of konular) {
          const plain = stripHtml(k.icerik);
          const haystack = (k.baslik + ' ' + plain).toLowerCase();
          const idx = haystack.indexOf(q);
          if (idx === -1) continue;
          const ders = dersById.get(k.dersId); const komite = ders ? komiteById.get(ders.komiteId) : null;
          const previewSrc = plain.toLowerCase().includes(q) ? plain : k.baslik;
          const pIdx = previewSrc.toLowerCase().indexOf(q);
          const onizleme = pIdx >= 0 ? (pIdx > 40 ? '…' : '') + previewSrc.slice(Math.max(0, pIdx - 40), pIdx + 90) + (pIdx + 90 < previewSrc.length ? '…' : '') : previewSrc.slice(0, 110);
          results.push({ tip: 'konu', id: k._id, baslik: k.baslik, onizleme, dersId: k.dersId, dersAdi: ders ? ders.ad : '', komiteAdi: komite ? komite.ad : '' });
        }
        for (const s of sorular) {
          const plain = stripHtml(s.soruMetni);
          if (!plain.toLowerCase().includes(q)) continue;
          const konu = konuById.get(s.konuId); const ders = konu ? dersById.get(konu.dersId) : null; const komite = ders ? komiteById.get(ders.komiteId) : null;
          const pIdx = plain.toLowerCase().indexOf(q);
          const onizleme = (pIdx > 40 ? '…' : '') + plain.slice(Math.max(0, pIdx - 40), pIdx + 90) + (pIdx + 90 < plain.length ? '…' : '');
          results.push({ tip: 'soru', id: s._id, konuId: s.konuId, onizleme, konuBaslik: konu ? konu.baslik : '', dersAdi: ders ? ders.ad : '', komiteAdi: komite ? komite.ad : '' });
        }
        return { payloadJson: toJson(results.slice(0, 40)) };
      }
    },

    // ---------- İSTATİSTİK: bir komitedeki her ders için konu/soru sayısı ----------
    GetKomiteStats: {
      requiresAuth: true, request: [{ no: 1, name: 'komiteId', type: 'string' }], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const dersler = await findMany(state.dersColl, 'komiteId', req.komiteId);
        const stats = [];
        for (const d of dersler) {
          const konular = await findMany(state.konuColl, 'dersId', d._id);
          let soruSayisi = 0;
          for (const k of konular) { soruSayisi += (await findMany(state.soruColl, 'konuId', k._id)).length; }
          stats.push({ dersId: d._id, dersAdi: d.ad, konuSayisi: konular.length, soruSayisi });
        }
        return { payloadJson: toJson(stats) };
      }
    },
  });

  // ================= ScheduleService: Haftalık Ders Programı =================
  app.registerController('ScheduleService', {
    ListSchedule: {
      requiresAuth: true, request: [{ no: 1, name: 'komiteId', type: 'string' }], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req) => {
        assertReady();
        const list = (await findMany(state.programColl, 'komiteId', req.komiteId)).sort((a, b) => {
          const ha = parseInt(a.hafta, 10) || 0, hb = parseInt(b.hafta, 10) || 0;
          if (ha !== hb) return ha - hb;
          return (parseInt(a.sira, 10) || 0) - (parseInt(b.sira, 10) || 0);
        });
        return { payloadJson: toJson(list) };
      }
    },
    CreateScheduleEntry: {
      requiresAuth: true, request: [{ no: 1, name: 'payloadJson', type: 'string' }], response: [{ no: 1, name: 'recordId', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const data = JSON.parse(req.payloadJson || '{}');
        if (!data.komiteId || !data.hafta || !data.dersId) { const err = new Error('Komite, hafta ve ders zorunludur.'); err.code = GRPC_STATUS.INVALID_ARGUMENT; throw err; }
        const doc = {
          komiteId: String(data.komiteId), hafta: String(data.hafta), gun: String(data.gun || ''),
          dersId: String(data.dersId), dersAdi: String(data.dersAdi || ''),
          konuId: String(data.konuId || ''), konuBaslik: String(data.konuBaslik || ''),
          not: String(data.not || ''), sira: String(data.sira ?? 0),
          olusturulmaTarihi: new Date().toISOString(),
        };
        const id = String(await state.programColl.insert(doc));
        return { recordId: id };
      }
    },
    UpdateScheduleEntry: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }, { no: 2, name: 'payloadJson', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const existing = await state.programColl.get(req.id); if (!existing) throw notFound('Program kaydı bulunamadı.');
        const data = JSON.parse(req.payloadJson || '{}');
        const merged = { ...existing };
        for (const key of ['hafta', 'gun', 'dersId', 'dersAdi', 'konuId', 'konuBaslik', 'not', 'sira']) {
          if (data[key] !== undefined) merged[key] = String(data[key]);
        }
        await state.programColl.update(req.id, merged);
        return { message: 'Program kaydı güncellendi.' };
      }
    },
    DeleteScheduleEntry: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        await state.programColl.delete(req.id);
        return { message: 'Program kaydı silindi.' };
      }
    },
  });

  // ================= FavoriteService =================
  app.registerController('FavoriteService', {
    ToggleFavorite: {
      requiresAuth: true, request: [{ no: 1, name: 'hedefTip', type: 'string' }, { no: 2, name: 'hedefId', type: 'string' }], response: [{ no: 1, name: 'favorited', type: 'bool' }],
      handler: async (req, call) => {
        assertReady();
        const mine = await findMany(state.favoriColl, 'kullaniciId', String(call.user.id));
        const existing = mine.find(f => f.hedefTip === req.hedefTip && f.hedefId === req.hedefId);
        if (existing) { await state.favoriColl.delete(existing._id); return { favorited: false }; }
        await state.favoriColl.insert({ kullaniciId: String(call.user.id), hedefTip: req.hedefTip, hedefId: req.hedefId, olusturulmaTarihi: new Date().toISOString() });
        return { favorited: true };
      }
    },
    ListFavorites: {
      requiresAuth: true, request: [], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req, call) => {
        assertReady();
        const mine = (await findMany(state.favoriColl, 'kullaniciId', String(call.user.id))).sort(byTarihDesc);
        // Favorilenen konu/soru'ların güncel başlık/metnini ekleyerek zenginleştir.
        const enriched = [];
        for (const f of mine) {
          if (f.hedefTip === 'konu') {
            const k = await state.konuColl.get(f.hedefId).catch(() => null);
            if (k) enriched.push({ ...f, baslik: k.baslik, dersId: k.dersId });
          } else if (f.hedefTip === 'soru') {
            const s = await state.soruColl.get(f.hedefId).catch(() => null);
            if (s) enriched.push({ ...f, baslik: (s.soruMetni || '').slice(0, 90), konuId: s.konuId });
          }
        }
        return { payloadJson: toJson(enriched) };
      }
    },
  });

  // ================= FeedbackService =================
  app.registerController('FeedbackService', {
    CreateFeedback: {
      requiresAuth: true, request: [{ no: 1, name: 'payloadJson', type: 'string' }], response: [{ no: 1, name: 'recordId', type: 'string' }],
      handler: async (req, call) => {
        assertReady();
        const data = JSON.parse(req.payloadJson || '{}');
        if (!data.hedefTip || !data.hedefId || !data.mesaj) { const err = new Error('hedefTip, hedefId ve mesaj zorunludur.'); err.code = GRPC_STATUS.INVALID_ARGUMENT; throw err; }
        const now = new Date().toISOString();
        const doc = {
          hedefTip: String(data.hedefTip), hedefId: String(data.hedefId),
          kullaniciId: String(call.user.id), kullaniciAdi: String(call.user.username),
          mesaj: String(data.mesaj), durum: 'acik', adminYaniti: '',
          olusturulmaTarihi: now, guncellemeTarihi: now,
        };
        const id = String(await state.feedbackColl.insert(doc));
        (log.info || log)(`[GERIBILDIRIM] ${id} - ${doc.hedefTip}:${doc.hedefId} (${call.user.username})`);
        return { recordId: id };
      }
    },
    MyFeedback: {
      requiresAuth: true, request: [], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req, call) => {
        assertReady();
        const list = (await findMany(state.feedbackColl, 'kullaniciId', String(call.user.id))).sort(byTarihDesc);
        return { payloadJson: toJson(list) };
      }
    },
    ListFeedback: {
      requiresAuth: true, request: [{ no: 1, name: 'durum', type: 'string' }], response: [{ no: 1, name: 'payloadJson', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const all = (req.durum ? await findMany(state.feedbackColl, 'durum', req.durum) : await scanAll(state.feedbackColl)).sort(byTarihDesc);
        return { payloadJson: toJson(all) };
      }
    },
    ResolveFeedback: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }, { no: 2, name: 'payloadJson', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady(); requireAdmin(call);
        const existing = await state.feedbackColl.get(req.id); if (!existing) throw notFound('Geribildirim bulunamadı.');
        const data = JSON.parse(req.payloadJson || '{}');
        await state.feedbackColl.update(req.id, {
          ...existing,
          durum: data.durum !== undefined ? String(data.durum) : existing.durum,
          adminYaniti: data.adminYaniti !== undefined ? String(data.adminYaniti) : existing.adminYaniti,
          guncellemeTarihi: new Date().toISOString(),
        });
        return { message: 'Geribildirim güncellendi.' };
      }
    },
    UpdateMyFeedback: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }, { no: 2, name: 'mesaj', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady();
        const existing = await state.feedbackColl.get(req.id); if (!existing) throw notFound('Geribildirim bulunamadı.');
        if (String(existing.kullaniciId) !== String(call.user.id)) { const err = new Error('Bu geribildirim size ait değil.'); err.code = GRPC_STATUS.PERMISSION_DENIED; throw err; }
        if (existing.durum !== 'acik') { const err = new Error('İncelemeye alınmış veya çözülmüş bir geribildirim artık düzenlenemez.'); err.code = GRPC_STATUS.FAILED_PRECONDITION; throw err; }
        if (!req.mesaj || !req.mesaj.trim()) { const err = new Error('Mesaj boş olamaz.'); err.code = GRPC_STATUS.INVALID_ARGUMENT; throw err; }
        await state.feedbackColl.update(req.id, { ...existing, mesaj: String(req.mesaj), guncellemeTarihi: new Date().toISOString() });
        return { message: 'Geribildiriminiz güncellendi.' };
      }
    },
    DeleteMyFeedback: {
      requiresAuth: true, request: [{ no: 1, name: 'id', type: 'string' }], response: [{ no: 1, name: 'message', type: 'string' }],
      handler: async (req, call) => {
        assertReady();
        const existing = await state.feedbackColl.get(req.id); if (!existing) throw notFound('Geribildirim bulunamadı.');
        if (String(existing.kullaniciId) !== String(call.user.id)) { const err = new Error('Bu geribildirim size ait değil.'); err.code = GRPC_STATUS.PERMISSION_DENIED; throw err; }
        await state.feedbackColl.delete(req.id);
        return { message: 'Geribildiriminiz silindi.' };
      }
    },
  });

  return {
    initCollections,
    getContentDbId: () => (state.db ? String(state.db.dbId) : null),
  };
}

module.exports = { registerContentPlatform, isAdmin, requireAdmin, CONTENT_ADMIN_BIT };