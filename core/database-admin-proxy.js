'use strict';

const http = require('node:http');
const { URL } = require('node:url');

// Veritabanının yönetim API'sini one.fitfak.net'e taşıyan vekil.
//
// Veritabanının paneli 127.0.2.1'de duruyor ve orada durmasının iyi bir sebebi var: düz HTTP
// konuşuyor ve tek taşıma seviyesi koruması ağdan erişilemez olmak. Ama bu, veritabanına
// bakmanın tek yolunun o makinede bir kabuk açmak olması demekti -- yönetim yüzeyi başka bir
// yerdeyken.
//
// Vekil bu ikisini birleştiriyor: istek one.fitfak.net'e geliyor, IdP oturumu ile doğrulanıyor,
// ve oradan yerel adrese iletiliyor. Veritabanının paneli hâlâ ağa açık DEĞİL.
//
//
// KİMİN ADINA
//
// İki ayrı kimlik doğrulama var ve ikisi de gerekli:
//
//   1. KULLANICI -> IdP.       Vekile gelen isteği yapan kişi, IdP'nin yönetici saydığı biri
//                              olmak zorunda. Bu kontrol çağıranda (requireAdmin).
//   2. IdP -> VERİTABANI.      Vekil, eşleştirme dizininden okuduğu makine kimlik bilgisiyle
//                              gidiyor. O kimlik bilgisi bir İNSANIN elinden geçmiyor.
//
// İkincisi olmasaydı, operatörün veritabanının açılış anahtarını bilmesi gerekirdi -- yani
// tarayıcıya yapıştırılan, sohbete düşen, ekran görüntüsünde kalan bir değer. Şimdi kimse onu
// görmüyor.
//
//
// NEDEN BEYAZ LİSTE
//
// Vekil, gelen yolu OLDUĞU GİBİ iletmiyor. İletseydi, `/admin/database/` altına yazılan her şey
// veritabanının API'sine giderdi -- bugün var olmayan ama yarın eklenecek uçlar dahil. Bir vekilin
// neyi ilettiğini bilmesi gerekir; bilmediği bir şeyi iletmesi, o şeyin yetkilendirme kararının
// da bilinmediği anlamına gelir.

const DEFAULT_TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 256 * 1024;

/**
 * Vekilin ilettiği uçlar.
 *
 * Her satır bir karar: bu uç, IdP yöneticisi olan birine açıktır. Listede olmayan bir uç
 * iletilmez ve 404 döner -- veritabanında var olsa bile.
 */
const ROUTES = Object.freeze({
  'GET /overview': { method: 'GET', path: '/api/overview' },
  'GET /services': { method: 'GET', path: '/api/services' },
  'GET /connections': { method: 'GET', path: '/api/connections' },
  'GET /storage': { method: 'GET', path: '/api/storage' },
  'GET /settings': { method: 'GET', path: '/api/settings' },
  'POST /services': { method: 'POST', path: '/api/services' },
  'POST /services/update': { method: 'POST', path: '/api/services/update' },
  'POST /services/rotate': { method: 'POST', path: '/api/services/rotate' },
  'POST /services/remove': { method: 'POST', path: '/api/services/remove' },
  'POST /metrics/reset': { method: 'POST', path: '/api/metrics/reset' },
  // Mühürleme BİLEREK listede. Ele geçirilmiş bir veritabanını kapatmak, yönetim yüzeyinden
  // yapılabilmesi gereken ilk şeydir ve o an makineye kabuk açmak için zaman yoktur.
  'POST /admission/seal': { method: 'POST', path: '/api/admission/seal' },
});

class DatabaseAdminProxy {
  /**
   * @param {object}   opts
   * @param {function} opts.readPairing  async () => { adminApiUrl, adminApiToken } | null
   * @param {object}  [opts.logger]
   * @param {number}  [opts.timeoutMs]
   */
  constructor({ readPairing, logger = null, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    this.readPairing = readPairing;
    this._log = logger;
    this.timeoutMs = timeoutMs;
    this._cached = null;
  }

  /**
   * Veritabanının API adresi ve kimlik bilgisi.
   *
   * Önbelleklenmiş ama YOKLUĞU önbelleklenmemiş: veritabanı henüz açılmadıysa dosya yok, ve o
   * durumu hatırlamak, veritabanı sonradan açıldığında vekilin çalışmamaya devam etmesi demek
   * olurdu.
   */
  async _endpoint() {
    if (this._cached) return this._cached;
    const pairing = await this.readPairing();
    if (!pairing || !pairing.adminApiUrl || !pairing.adminApiToken) return null;
    this._cached = { url: pairing.adminApiUrl, token: pairing.adminApiToken };
    return this._cached;
  }

  /** Yapılandırma değiştiğinde ya da kimlik bilgisi reddedildiğinde. */
  invalidate() { this._cached = null; }

  /**
   * Bir isteği veritabanına iletir.
   *
   * @param {string} method
   * @param {string} route    `/overview` gibi, `/admin/database` önekinden SONRAsı
   * @param {object} [body]
   * @returns {{ status, payload }}
   */
  async forward(method, route, body = null) {
    const mapped = ROUTES[`${method} ${route}`];
    if (!mapped) {
      return {
        status: 404,
        payload: {
          error: 'not_proxied',
          error_description: `'${method} ${route}' bu vekil tarafından iletilmiyor. `
            + 'İletilen uçlar core/database-admin-proxy.js içinde açıkça listelidir.',
        },
      };
    }

    const endpoint = await this._endpoint();
    if (!endpoint) {
      // Bir hata değil bir DURUM: veritabanı henüz açılmamış olabilir ve bu, bu mimaride
      // beklenen bir açılış sırası. Mesajın bunu söylemesi, operatörün yanlış yerde hata
      // aramasını engelliyor.
      return {
        status: 503,
        payload: {
          error: 'database_unavailable',
          error_description: 'Veritabanının yönetim API\'si henüz yayınlanmadı. Veritabanı '
            + 'sunucusu çalışıyor mu, ve iki süreç aynı eşleştirme dizinini mi kullanıyor '
            + '(FITFAK_PAIRING_DIR)?',
        },
      };
    }

    try {
      return await this._request(endpoint, mapped, body);
    } catch (err) {
      // Bağlantı hatasında önbellek boşaltılıyor: veritabanı yeniden başlamış ve adresi ya da
      // kimlik bilgisi değişmiş olabilir, ve eski değeri tutmak vekili kalıcı olarak bozardı.
      this.invalidate();
      this._log?.warn?.({ error: err.message, route, msg: 'veritabanı yönetim API\'sine ulaşılamadı' });
      return {
        status: 502,
        payload: { error: 'database_unreachable', error_description: err.message },
      };
    }
  }

  _request(endpoint, mapped, body) {
    const url = new URL(endpoint.url + mapped.path);
    const payload = body ? JSON.stringify(body) : null;

    return new Promise((resolve, reject) => {
      const req = http.request({
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname + url.search,
        method: mapped.method,
        headers: {
          accept: 'application/json',
          'x-admin-token': endpoint.token,
          // Aynı kaynak kontrolü karşı tarafta duruyor ve POST'larda `Origin` bakıyor. Vekilin
          // kendi kaynağını bildirmesi, o kontrolün bir tarayıcı isteğini ayırt etmesini sağlar.
          origin: url.origin,
          ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
        },
        timeout: this.timeoutMs,
      }, (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > MAX_BODY_BYTES) { req.destroy(new Error('veritabanı yanıtı çok büyük')); return; }
          chunks.push(chunk);
        });
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let parsed;
          try { parsed = raw ? JSON.parse(raw) : {}; } catch (_) {
            return reject(new Error(
              `veritabanı ${res.statusCode} ile JSON olmayan bir gövde döndü (${raw.slice(0, 120)})`,
            ));
          }
          // 401: kimlik bilgisi artık geçerli değil. Veritabanı yeniden başlamış ve yeni bir
          // anahtar yayınlamış olabilir, o yüzden önbellek boşaltılıyor -- bir sonraki istek
          // eşleştirme dizinini yeniden okur ve kendini toparlar.
          if (res.statusCode === 401) this.invalidate();
          resolve({ status: res.statusCode, payload: parsed });
        });
      });
      req.on('timeout', () => req.destroy(new Error(`veritabanı ${this.timeoutMs}ms içinde yanıt vermedi`)));
      req.on('error', reject);
      req.end(payload);
    });
  }

  /** Panel için: vekil bağlanabiliyor mu, ve nereye. */
  async status() {
    const endpoint = await this._endpoint();
    return {
      configured: !!endpoint,
      // Kimlik bilgisi DÖNMÜYOR, yalnızca adres. Bir durum ucunun sır döndürmesi, o sırrın
      // panelin ağ sekmesine ve oradan bir ekran görüntüsüne düşmesi demektir.
      target: endpoint ? endpoint.url : null,
      routes: Object.keys(ROUTES),
    };
  }
}

function createDatabaseAdminProxy(options) { return new DatabaseAdminProxy(options); }

module.exports = { DatabaseAdminProxy, createDatabaseAdminProxy, PROXY_ROUTES: ROUTES };
