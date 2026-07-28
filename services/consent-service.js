'use strict';

const crypto = require('node:crypto');

const { AppError } = require('../core/errors');
const { scanFindAll } = require('../db/query-utils');

// ============================================================================
// OAuth onayı (consent).
//
// Bu dosyadan ÖNCE /oauth/authorize şöyle davranıyordu: kayıtlı bir client
// geldiyse ve kullanıcının oturumu varsa, yetkilendirme kodu SESSİZCE
// üretiliyordu. Yani kayıtlı herhangi bir uygulama, kullanıcı hiçbir şey
// görmeden onun adına token alabiliyordu. SSO'nun "sihri" bu değil -- SSO,
// kullanıcının TEKRAR PAROLA GİRMEMESİ demek; kullanıcıya HİÇ SORULMAMASI
// demek değil.
//
// İkinci ve daha sessiz sorun: istenen `scope` hiçbir yerde client'ın
// `allowedScopes` listesiyle karşılaştırılmıyordu. Bir client kendi kayıtlı
// yetkisinin dışında bir kapsam isteyebiliyor, o kapsam yetkilendirme koduna
// ve oradan da erişim token'ına yazılıyordu. Kayıt sırasında verilen liste,
// uygulanmadığı sürece yalnızca bir yorum satırıdır.
// ============================================================================

// Kullanıcıya ne söylendiği, ne verildiği kadar önemli. Bir onay ekranı
// 'dns:write' yazıp geçiyorsa, kullanıcı onaylarken ne verdiğini bilmiyordur.
const SCOPE_CATALOG = {
  openid: {
    title: 'Kimliğiniz',
    detail: 'Hesabınızın kimlik numarasını görür. Ad, e-posta ya da başka bir bilgi içermez.',
    sensitive: false,
  },
  profile: {
    title: 'Profil bilgileriniz',
    detail: 'Görünen adınızı, kullanıcı adınızı ve profil fotoğrafınızı görür.',
    sensitive: false,
  },
  email: {
    title: 'E-posta adresiniz',
    detail: 'E-posta adresinizi ve doğrulanmış olup olmadığını görür.',
    sensitive: false,
  },
  'dns:read': {
    title: 'DNS kayıtlarınız (okuma)',
    detail: 'Bölgelerinizi ve kayıtlarınızı listeler. Değişiklik yapamaz.',
    sensitive: false,
  },
  'dns:write': {
    title: 'DNS kayıtlarınız (yazma)',
    detail: 'Kayıt ekleyebilir, değiştirebilir ve silebilir. Bir alan adının nereye çözüleceğini değiştirmek, o alan adı için sertifika almayı da mümkün kılar.',
    sensitive: true,
  },
  'cert:issue': {
    title: 'Adınıza sertifika alma',
    detail: 'Sizin adınıza sertifika talep eder. Verilen sertifikalar Certificate Transparency günlüğüne yazılır ve /profile sayfasından görülebilir.',
    sensitive: true,
  },
  'service:enrol': {
    title: 'Servis kimliği alma',
    detail: 'Altyapı servislerinin veritabanına kaydolmasını sağlar. Yalnızca servis hesapları içindir.',
    sensitive: true,
  },
  offline_access: {
    title: 'Siz yokken de erişim',
    detail: 'Tarayıcınızı kapattıktan sonra da erişimini sürdürür (yenileme belirteci). İzni geri aldığınızda sona erer.',
    sensitive: true,
  },
};

function describeScope(scope) {
  const known = SCOPE_CATALOG[scope];
  if (known) return { scope, ...known };
  // Bilinmeyen bir kapsam, katalogda olmadığı için "zararsız" sayılmaz --
  // tersine: ne olduğunu anlatamıyorsak kullanıcıya da öyle söyleriz.
  return {
    scope,
    title: scope,
    detail: 'Bu iznin ne yaptığı burada tanımlı değil. Ne olduğundan emin değilseniz reddedin.',
    sensitive: true,
  };
}

function parseScope(raw) {
  return String(raw || '').split(/[\s+]+/).map((s) => s.trim()).filter(Boolean);
}

function formatScope(list) {
  return Array.from(new Set(list)).sort().join(' ');
}

/**
 * İstenen kapsamları client'ın kayıtlı yetkisiyle karşılaştırır.
 *
 * Sessizce kırpmıyoruz. "İstediğinin bir kısmını verdim" davranışı, client'ın
 * çalıştığını sanıp yetkisi olmayan bir işi denemesine yol açar; hata mesajı
 * o noktada artık kullanıcıya gösterilir. Reddetmek, kayıt anındaki listeyle
 * çalışma anındaki davranışı aynı yerde tutar.
 */
function resolveRequestedScopes({ requested, client }) {
  const allowed = new Set(client.allowedScopes || []);
  const asked = parseScope(requested);
  // Kapsam istenmediyse client'ın kayıtlı listesi varsayılandır (RFC 6749 §3.3).
  if (asked.length === 0) return Array.from(allowed);

  const rejected = asked.filter((s) => !allowed.has(s));
  if (rejected.length > 0) {
    throw new AppError('invalid_scope', `Bu uygulama için izin verilmeyen kapsam: ${rejected.join(', ')}`, { httpStatus: 400 });
  }
  return asked;
}

function grantKey(userId, clientId) {
  return `${userId}:${clientId}`;
}

async function getGrant({ db, userId, clientId }) {
  const row = await db.collection('oauth_grants').findOne('userClientKey', grantKey(userId, clientId));
  if (!row) return null;
  return {
    _id: row._id,
    userId: row.userId,
    clientId: row.clientId,
    scopes: parseScope(row.scope),
    grantedAt: Number(row.grantedAt || 0),
    updatedAt: Number(row.updatedAt || 0),
    lastUsedAt: Number(row.lastUsedAt || 0),
  };
}

/**
 * Onay ekranı gerekli mi?
 *
 * Kayıtlı izin, istenen kapsamların TAMAMINI kapsamıyorsa gerekli. Bu, "bir kez
 * onayla, sonsuza kadar genişle" davranışını engelleyen tek kontrol: uygulama
 * sonradan `dns:write` eklerse, eski `dns:read` onayı onu kapsamaz.
 */
async function needsConsent({ db, userId, client, scopes }) {
  if (client.firstParty) return false;
  const grant = await getGrant({ db, userId, clientId: client.clientId });
  if (!grant) return true;
  const held = new Set(grant.scopes);
  return scopes.some((s) => !held.has(s));
}

async function saveGrant({ db, userId, clientId, scopes }) {
  const grants = db.collection('oauth_grants');
  const existing = await getGrant({ db, userId, clientId });
  const now = BigInt(Date.now());
  // Birleşim: kullanıcı daha önce verdiği bir izni bu ekranda görmediyse,
  // görmediği bir şeyi kaybetmemeli.
  const merged = formatScope([...(existing ? existing.scopes : []), ...scopes]);

  if (existing) {
    await grants.update(existing._id, { scope: merged, updatedAt: now });
  } else {
    await grants.insert({
      userClientKey: grantKey(userId, clientId),
      userId: String(userId), clientId,
      scope: merged, grantedAt: now, updatedAt: now, lastUsedAt: now,
    });
  }
  return { scopes: parseScope(merged) };
}

async function touchGrant({ db, userId, clientId }) {
  const existing = await getGrant({ db, userId, clientId });
  if (!existing) return;
  await db.collection('oauth_grants').update(existing._id, { lastUsedAt: BigInt(Date.now()) });
}

async function listGrants({ db, userId, clientStore }) {
  const rows = await scanFindAll(db.collection('oauth_grants'), 'userId', String(userId));
  const out = [];
  for (const row of rows) {
    // eslint-disable-next-line no-await-in-loop
    const client = clientStore ? await clientStore.getClient(row.clientId) : null;
    out.push({
      clientId: row.clientId,
      name: client ? client.name : row.clientId,
      clientUri: client ? client.clientUri || null : null,
      // Silinmiş bir client'ın izni listede KALIR ve öyle işaretlenir:
      // kullanıcının verdiği izni, izni alan taraf ortadan kalktı diye
      // gizlemek, kaydı eksik göstermek olur.
      exists: !!client,
      scopes: parseScope(row.scope).map(describeScope),
      grantedAt: Number(row.grantedAt || 0),
      lastUsedAt: Number(row.lastUsedAt || 0),
    });
  }
  return out.sort((a, b) => b.lastUsedAt - a.lastUsedAt);
}

/**
 * İzni geri al.
 *
 * Kaydı silmek yetmez: o client için verilmiş yenileme belirteçleri hâlâ
 * çalışıyor olurdu. İzni geri almanın kullanıcı için anlamı "artık
 * erişemesin"dir, "bir dahaki sefere tekrar sorulsun" değil.
 */
async function revokeGrant({ db, userId, clientId, sessionManager }) {
  const grant = await getGrant({ db, userId, clientId });
  if (!grant) throw new AppError('not_found', 'Böyle bir izin yok', { httpStatus: 404 });
  await db.collection('oauth_grants').delete(grant._id);

  let revokedTokens = 0;
  if (sessionManager) {
    const sessions = await sessionManager.listSessions(String(userId));
    const sessionIds = new Set(sessions.map((s) => s.sessionId));
    const tokens = await scanFindAll(db.collection('refresh_tokens'), 'audience', clientId);
    for (const token of tokens) {
      if (!sessionIds.has(token.sessionId)) continue;
      // eslint-disable-next-line no-await-in-loop
      await db.collection('refresh_tokens').update(token._id, { used: true, expiresAt: BigInt(Date.now()) });
      revokedTokens += 1;
    }
  }
  return { revoked: true, revokedTokens };
}

// ============================================================================
// Bekleyen yetkilendirme isteği.
//
// Onay ekranına parametreler URL'de TAŞINMAZ; sunucuda saklanır ve tarayıcıya
// yalnızca opak bir tanıtıcı verilir. İki sebep:
//
//  1. Onay ekranındaki "izin ver" düğmesi, adres çubuğundaki değerlere göre
//     karar verseydi, kullanıcıya A uygulamasını gösterip B uygulamasına izin
//     vermek mümkün olurdu (istek, gösterimden sonra değiştirilerek).
//  2. Tek kullanımlıktır: aynı onay iki kez tüketilemez.
// ============================================================================
const PENDING_TTL_MS = 10 * 60_000;

async function createPendingAuthorization({ store, request }) {
  const id = crypto.randomBytes(24).toString('base64url');
  await store.set(`consent:${id}`, { ...request, createdAt: Date.now() }, PENDING_TTL_MS);
  return id;
}

async function readPendingAuthorization({ store, id }) {
  if (!id || typeof id !== 'string') return null;
  return store.get(`consent:${id}`);
}

async function consumePendingAuthorization({ store, id }) {
  const pending = await readPendingAuthorization({ store, id });
  if (pending) await store.delete(`consent:${id}`);
  return pending;
}

module.exports = {
  SCOPE_CATALOG, describeScope, parseScope, formatScope,
  resolveRequestedScopes, needsConsent,
  getGrant, saveGrant, touchGrant, listGrants, revokeGrant,
  createPendingAuthorization, readPendingAuthorization, consumePendingAuthorization,
  PENDING_TTL_MS,
};
