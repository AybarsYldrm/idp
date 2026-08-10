'use strict';

/**
 * Bağımlılıksız, yapılandırılmış günlükleyici -- renkli, bileşen etiketli, hex dökümü destekli.
 *
 * ── NEDEN AYRI BİR DOSYA ─────────────────────────────────────────────────────────────────
 * Bu, @fitfak/database'in src/logger.js'iyle aynı uygulamadır ve kopyalanmış olması bilinçli
 * bir istisnadır. core/spiffe.js'te tam tersini yaptım -- SPIFFE ayrıştırıcısı paketten
 * geliyor, çünkü o iki tarafın KARŞILAŞTIRDIĞI bir değer ve iki uygulama er ya da geç aynı
 * sertifikayı iki farklı kimlik olarak okur.
 *
 * Günlükleyici öyle değil. O bir TEŞHİS ARACIDIR ve teşhis aracının, teşhis edilecek şey
 * çalışmadığında da çalışması gerekir. Paketten yüklemek, "@fitfak/database yüklenemedi"
 * hatasının kendisini kaydedecek şeyin de yüklenememesi demek olurdu -- yani sistemin
 * söyleyecek en önemli şeyi olduğu anda susması.
 *
 * Çalışma zamanında yine de TEK bir akış var: oauth-server.js açılışta
 * `require('@fitfak/database').configureLogging({ sink })` çağırıyor ve motorun her satırı bu
 * günlükleyiciye akıyor. Diskte iki dosya, ekranda tek akış.
 *
 * ── İKİ ÇAĞRI BİÇİMİ, BİLEREK ────────────────────────────────────────────────────────────
 * İkisi de çalışır ve aynı şeyi ifade eder:
 *
 *     log.info('oturum açıldı', { userId: 12 })
 *     log.info({ msg: 'oturum açıldı', userId: 12 })
 *
 * İkincisi @fitfak/database ve @fitfak/smtp'nin kullandığı biçim. Kabul edilmesi, o paketlerin
 * kendi günlükleyicilerini doğrudan geçirebilmesini sağlayan şey.
 */

const LEVELS = { TRACE: 10, DEBUG: 20, INFO: 30, WARN: 40, ERROR: 50, SILENT: 99 };

const LEVEL_COLORS = {
  TRACE: '\x1b[90m', DEBUG: '\x1b[36m', INFO: '\x1b[32m',
  WARN: '\x1b[33m', ERROR: '\x1b[31m',
};
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

// FITFAK_IDP_LOG_LEVEL bu pakete ait ad; FITDB_LOG_LEVEL de dinleniyor, böylece yığının geri
// kalanını ayrıntıya açan bir dağıtım aynı derinliği görmek için iki değişken ayarlamak
// zorunda kalmıyor.
//
// Varsayılan DEBUG. INFO daha önce varsayılandı ve yanlış karardı: her zamanlamayı ve her
// strateji kararını gizliyordu, yani sistem sessiz görünüyordu. İstek başına satırlar DEBUG'da,
// bayt düzeyi ayrıntı TRACE'te; sessizlik isteyen bir dağıtım FITFAK_IDP_LOG_LEVEL=INFO yazar.
const envLevel = String(
  process.env.FITFAK_IDP_LOG_LEVEL || process.env.FITDB_LOG_LEVEL || 'DEBUG',
).toUpperCase();
let minLevel = LEVELS[envLevel] ?? LEVELS.DEBUG;

let colorEnabled = !!process.stdout.isTTY && process.env.NO_COLOR !== '1';
let jsonMode = String(process.env.FITFAK_IDP_LOG_JSON || '') === '1';

let sink = null;

function c(code) { return colorEnabled && !jsonMode ? code : ''; }

function ts() { return new Date().toISOString().slice(11, 23); } // HH:MM:SS.mmm

/**
 * Değeri hiçbir seviyede günlüğe düşmeyen anahtarlar.
 *
 * "Yalnızca trace'te yazdırıyoruz" koruma değildir: trace'i açan kişi bir sorunun peşindedir ve
 * çıktıyla yaptığı ilk şey onu bir yere yapıştırmaktır. O yapıştırmadaki bir istemci sırrı ya da
 * bir oturum jetonu bir hesap ele geçirmedir, o yüzden bunlar koşulsuz maskelenir.
 *
 * `verifier` ve `salt` bu listede: SRP doğrulayıcısı bir parola hash'i değildir ama parolaya
 * karşı çevrimdışı sözlük saldırısı yapmak için yeterlidir.
 */
const SECRET_KEY_RE = /(secret|password|passwd|token|authorization|cookie|privatekey|apikey|api_key|ddk|kek|verifier|salt|proof|challenge|code_verifier|clientsecret)/i;

function maskSecret(value) {
  const s = String(value == null ? '' : value);
  if (!s) return '';
  if (s.length <= 8) return '***';
  return `${s.slice(0, 4)}…${s.slice(-4)} (${s.length}b)`;
}

function bufReplacer(_k, v) {
  if (Buffer.isBuffer(v)) {
    const head = v.toString('hex').slice(0, 48);
    return `<Buffer ${v.length}B 0x${head}${v.length > 24 ? '…' : ''}>`;
  }
  if (typeof v === 'bigint') return v.toString();
  return v;
}

function safeJson(o) {
  try { return JSON.stringify(o, bufReplacer); } catch { return String(o); }
}

/** Her iki çağrı biçimini tek bir `{ msg, ...alanlar }` nesnesine indirger. */
function coerce(a, b) {
  if (a instanceof Error) return { error: a.message, stack: a.stack, ...(b && typeof b === 'object' ? b : {}) };
  if (typeof a === 'string') return { msg: a, ...(b && typeof b === 'object' ? b : {}) };
  if (a && typeof a === 'object') return { ...a, ...(b && typeof b === 'object' ? b : {}) };
  return { msg: String(a == null ? '' : a) };
}

function redact(fields) {
  const out = {};
  for (const [k, v] of Object.entries(fields || {})) {
    if (v === undefined) continue;
    if (SECRET_KEY_RE.test(k)) {
      out[k] = (v && typeof v === 'object' && !Buffer.isBuffer(v)) ? '[gizlendi]' : maskSecret(v);
      continue;
    }
    out[k] = v instanceof Error ? v.message : v;
  }
  return out;
}

/**
 * `msg` dışındaki her şey, girintili bir JSON bloğu olarak.
 *
 * Bu, yığının geri kalanının kullandığı sunum ve eşleşmesi kozmetik değil: bir kimlik satırı
 * genelde iç içe ayrıntı taşır (bir sertifikanın profili ve SAN'ları, bir enrolment'ın reddedilme
 * sebebi, bir sorgunun stratejisi) ve bunu tek bir `k=v` satırına düzleştirmek, tam da en çok
 * gerektiği anda okunmaz hâle geldiği yerdir.
 */
function metaBlock(fields) {
  const rest = {};
  for (const [k, v] of Object.entries(fields)) {
    if (k === 'msg' || v === undefined) continue;
    rest[k] = v;
  }
  if (Object.keys(rest).length === 0) return '';
  try { return JSON.stringify(rest, bufReplacer, 2); }
  catch { return String(rest); }
}

function hexDump(buf, { width = 16, indent = '  ', maxBytes = 512 } = {}) {
  if (!Buffer.isBuffer(buf) || buf.length === 0) return `${indent}<boş>`;
  const view = buf.length > maxBytes ? buf.subarray(0, maxBytes) : buf;
  const out = [];
  for (let i = 0; i < view.length; i += width) {
    const slice = view.subarray(i, i + width);
    const hex = [...slice].map((b) => b.toString(16).padStart(2, '0'))
      .join(' ').padEnd(width * 3 - 1, ' ');
    const ascii = [...slice].map((b) => ((b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.')).join('');
    const off = i.toString(16).padStart(6, '0');
    out.push(`${indent}${c(DIM)}${off}${c(RESET)}  ${hex}  ${c(DIM)}|${ascii}|${c(RESET)}`);
  }
  if (buf.length > maxBytes) out.push(`${indent}${c(DIM)}… ${buf.length - maxBytes} bayt daha${c(RESET)}`);
  return out.join('\n');
}

function emit(levelName, component, fields, localSink = null) {
  if (LEVELS[levelName] < minLevel) return;
  const norm = redact(fields);

  const target = localSink || sink;
  if (target) {
    const method = levelName.toLowerCase();
    // Bir ana uygulama günlükleyicisi her seviyeyi uygulamak zorunda değil. `info`'ya düşmek,
    // eksik bir metot yüzünden fırlatmak yerine debug satırını görünür tutar; aşağıdaki koruma
    // ise onu bile içermeyen bir günlükleyicinin ölümcül değil sessiz olması demek.
    const fn = typeof target[method] === 'function' ? target[method] : target.info;
    if (typeof fn === 'function') fn.call(target, { component, ...norm });
    return;
  }

  const stream = LEVELS[levelName] >= LEVELS.WARN ? process.stderr : process.stdout;

  if (jsonMode) {
    stream.write(`${safeJson({ ts: new Date().toISOString(), level: levelName, component, ...norm })}\n`);
    return;
  }

  const color = c(LEVEL_COLORS[levelName] || '');
  const head = `${c(DIM)}${ts()}${c(RESET)} ${color}${c(BOLD)}${levelName.padEnd(5)}${c(RESET)} ${color}[${component}]${c(RESET)}`;
  const message = norm.msg != null ? ` ${norm.msg}` : '';
  const meta = metaBlock(norm);
  stream.write(`${head}${message}${meta ? `\n${c(DIM)}${meta}${c(RESET)}` : ''}\n`);
}

/** `component`'e bağlı bir günlükleyici üretir. */
function mk(component, { sink: localSink = null } = {}) {
  const self = {
    trace: (a, b) => emit('TRACE', component, coerce(a, b), localSink),
    debug: (a, b) => emit('DEBUG', component, coerce(a, b), localSink),
    info: (a, b) => emit('INFO', component, coerce(a, b), localSink),
    warn: (a, b) => emit('WARN', component, coerce(a, b), localSink),
    error: (a, b) => emit('ERROR', component, coerce(a, b), localSink),
    child: (sub) => mk(`${component}:${sub}`, { sink: localSink }),
    enabled: (lvl) => (LEVELS[String(lvl).toUpperCase()] ?? 0) >= minLevel,

    hex: (label, buf) => {
      if (LEVELS.DEBUG < minLevel) return;
      emit('DEBUG', component, { msg: label, bytes: Buffer.isBuffer(buf) ? buf.length : 0 }, localSink);
      if (!localSink && !sink && !jsonMode) process.stdout.write(`${hexDump(buf)}\n`);
    },

    /**
     * Süre ölçer: `const done = log.timer('enrolment'); … done({ principal })`.
     *
     * Normalde DEBUG'da, `warnAboveMs`'i aşınca WARN'a yükselir. Yükselme asıl mesele --
     * sessizce 100 kat yavaşlamış bir işlem, tam olarak süreci düşürene kadar kimsenin
     * aramadığı türden bir şeydir.
     */
    timer: (label, { warnAboveMs = 1000 } = {}) => {
      const startedAt = process.hrtime.bigint();
      return (fields = {}) => {
        const ms = Number(process.hrtime.bigint() - startedAt) / 1e6;
        const rounded = Math.round(ms * 100) / 100;
        emit(ms >= warnAboveMs ? 'WARN' : 'DEBUG', component, { msg: label, ms: rounded, ...fields }, localSink);
        return rounded;
      };
    },
  };
  return self;
}

const REQUIRED_METHODS = ['trace', 'debug', 'info', 'warn', 'error', 'child', 'timer', 'hex', 'enabled'];

/**
 * Çağıranın `logger` olarak verdiği her şeyi, güvenilebilecek bir günlükleyiciye çevirir.
 *
 * Tam yüzeye zaten sahip bir günlükleyici olduğu gibi kullanılır (böylece bizim bir çocuğumuz
 * kendi bileşen yolunu korur). Kısmi olan her şey sarmalanır: kod tam bir günlükleyici alır ve
 * yazdığı her satır verilene iletilir.
 */
function adapt(candidate, component) {
  if (!candidate) return mk(component);
  if (REQUIRED_METHODS.every((m) => typeof candidate[m] === 'function')) {
    return candidate.child(component);
  }
  return mk(component, { sink: candidate });
}

function setLevel(name) {
  const n = LEVELS[String(name).toUpperCase()];
  if (n == null) throw new Error(`[fitfak-idp] bilinmeyen günlük seviyesi: ${name}`);
  minLevel = n;
  return name;
}

function getLevel() {
  return Object.keys(LEVELS).find((k) => LEVELS[k] === minLevel) || 'INFO';
}

function setSink(hostLogger) { sink = hostLogger || null; return sink; }

function configure({ level, json, color, sink: hostLogger } = {}) {
  if (level) setLevel(level);
  if (json != null) jsonMode = !!json;
  if (color != null) colorEnabled = !!color;
  if (hostLogger !== undefined) setSink(hostLogger);
  if (jsonMode) colorEnabled = false;
  return { level: getLevel(), json: jsonMode, color: colorEnabled, sink: !!sink };
}

const NULL_LOGGER = {
  trace() {}, debug() {}, info() {}, warn() {}, error() {}, hex() {},
  enabled() { return false; },
  child() { return NULL_LOGGER; },
  timer() { return () => 0; },
};

module.exports = { mk, adapt, hexDump, setLevel, getLevel, setSink, configure, LEVELS, NULL_LOGGER };
