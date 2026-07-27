'use strict';

const http = require('node:http');
const http2 = require('node:http2');
const { EventEmitter } = require('node:events');

// ============================================================================
// Standart gRPC durum kodları (bkz. grpc.io/docs/guides/status-codes)
// ============================================================================
const GRPC_STATUS = {
  OK: 0, CANCELLED: 1, UNKNOWN: 2, INVALID_ARGUMENT: 3, DEADLINE_EXCEEDED: 4,
  NOT_FOUND: 5, ALREADY_EXISTS: 6, PERMISSION_DENIED: 7, RESOURCE_EXHAUSTED: 8,
  FAILED_PRECONDITION: 9, ABORTED: 10, OUT_OF_RANGE: 11, UNIMPLEMENTED: 12,
  INTERNAL: 13, UNAVAILABLE: 14, DATA_LOSS: 15, UNAUTHENTICATED: 16,
};

class GrpcError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// ============================================================================
// ÇERÇEVELEME (framing)
// ============================================================================
function encodeFrame(obj, { trailer = false } = {}) {
  const payload = Buffer.from(JSON.stringify(obj ?? null), 'utf8');
  const header = Buffer.alloc(5);
  header.writeUInt8(trailer ? 0x80 : 0x00, 0);
  header.writeUInt32BE(payload.length, 1);
  return Buffer.concat([header, payload]);
}

function decodeFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (buffer.length - offset >= 5) {
    const flags = buffer.readUInt8(offset);
    const len = buffer.readUInt32BE(offset + 1);
    if (buffer.length - offset - 5 < len) break;
    const payloadBuf = buffer.subarray(offset + 5, offset + 5 + len);
    let value;
    try { value = JSON.parse(payloadBuf.toString('utf8')); } catch { value = null; }
    frames.push({ trailer: !!(flags & 0x80), value });
    offset += 5 + len;
  }
  return { frames, rest: buffer.subarray(offset) };
}

class FrameDecoder {
  constructor() { this.buffer = Buffer.alloc(0); }
  push(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const { frames, rest } = decodeFrames(this.buffer);
    this.buffer = rest;
    return frames;
  }
}

function requireBearerAuth(verifyFn) {
  return async (call) => {
    const authHeader = call.metadata.authorization || '';
    const match = /^Bearer\s+(.+)$/.exec(authHeader);
    if (!match) throw new GrpcError(GRPC_STATUS.UNAUTHENTICATED, 'Bearer token eksik');
    let payload;
    try {
      ({ payload } = verifyFn(match[1]));
    } catch {
      throw new GrpcError(GRPC_STATUS.UNAUTHENTICATED, 'Token geçersiz veya süresi dolmuş');
    }
    call.context = { ...call.context, ...payload };
  };
}

function requireScope(requiredScope) {
  return async (call) => {
    const scopes = String(call.context.scope || '').split(' ').filter(Boolean);
    if (!scopes.includes(requiredScope)) {
      throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, `Bu işlem için '${requiredScope}' scope'u gerekli`);
    }
  };
}

class Service {
  constructor(name) {
    this.name = name;
    this.methods = new Map();
    this.middlewares = [];
  }
  use(mw) { this.middlewares.push(mw); return this; }
  addUnary(name, handler) { this.methods.set(name, { type: 'unary', handler }); return this; }
  addServerStream(name, handler) { this.methods.set(name, { type: 'server_stream', handler }); return this; }
  addClientStream(name, handler) { this.methods.set(name, { type: 'client_stream', handler }); return this; }
  addBidi(name, handler) { this.methods.set(name, { type: 'bidi', handler }); return this; }
}

// ============================================================================
// YENİLENMİŞ SERVER: Çoklu IP (Multi-Bind) ve Soket Seviyesinde L4 Yönlendirme
// ============================================================================
class Server {
  constructor() {
    this.services = new Map(); // serviceName -> { service, bindIp }
    this.httpHandlers = [];    // [{ matcher, handler, bindIp }]
    this._httpServers = [];    // Oluşturulan tüm HTTP sunucularını tutar
    this._http2Servers = [];   // Oluşturulan tüm HTTP/2 sunucularını tutar
    this._addReflectionHandler();
    this.corsOrigins = new Set([
      'https://session.fitfak.net',
      'https://trust.fitfak.net'
    ]);
  }

  _applyCors(req, res) {
    const origin = req.headers.origin;

    if (!origin) return;

    if (this.corsOrigins.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader(
        'Access-Control-Allow-Headers',
        req.headers['access-control-request-headers'] || 'Content-Type, Authorization'
      );
      res.setHeader('Vary', 'Origin');
    }
  }

  // YENİ: Artık servisleri belirli bir IP adresine kilitleyebilirsin (Örn: '127.0.0.1')
  addService(service, bindIp = null) { 
    this.services.set(service.name, { service, bindIp }); 
    return this; 
  }

  // YENİ: HTTP rotaları da spesifik IP adreslerine kilitlenebilir.
  addHttpHandler(matcher, handler, bindIp = null) {
    this.httpHandlers.push({ matcher, handler, bindIp });
    return this;
  }

  listen(httpPort, hostOrOpts, opts, cb) {
    let options = {};
    let callback = cb;

    if (typeof hostOrOpts === 'string') {
        options.host = hostOrOpts;
    } else if (typeof hostOrOpts === 'function') {
        callback = hostOrOpts;
    } else if (typeof hostOrOpts === 'object' && hostOrOpts !== null) {
        options = hostOrOpts;
    }

    if (typeof opts === 'function') {
        callback = opts;
    } else if (opts && typeof opts === 'object') {
        options = { ...options, ...opts };
    }

    // YENİ: `host` parametresini Array olarak kabul ediyoruz.
    // Örn: { host: ['127.0.0.1', '127.0.0.2'] }
    let hosts = ['127.0.0.1'];
    if (options.host) {
        hosts = Array.isArray(options.host) ? options.host : [options.host];
    }

    let pending = hosts.length * (options.http2Port ? 2 : 1);
    const done = () => { pending -= 1; if (pending === 0 && callback) callback(); };

    // Her bir IP adresi için bağımsız sunucu örnekleri oluşturuyoruz
    for (const h of hosts) {
        const h1 = http.createServer((req, res) => {
          this._dispatch(req, res, { allowBidi: false }).catch((e) => this._onDispatchError(res, e));
        });
        h1.listen(httpPort, h, done);
        this._httpServers.push(h1);

        if (options.http2Port) {
          const fs = require('node:fs');
          const path = require('node:path');
          const tlsOptions = {
            key: fs.readFileSync(path.join(__dirname, '..', 'certs', 'server.key')),
            cert: fs.readFileSync(path.join(__dirname, '..', 'certs', 'server.crt')) 
          };

          const h2 = http2.createSecureServer(tlsOptions, (req, res) => {
            this._dispatch(req, res, { allowBidi: true }).catch((e) => this._onDispatchError(res, e));
          });
          h2.listen(options.http2Port, h, done);
          this._http2Servers.push(h2);
        }
    }

    return this;
  }

  _onDispatchError(res, e) {
    console.error('http-transport: yakalanmamış dispatch hatası', e);
    if (!res.headersSent) { res.statusCode = 500; }
    res.end();
  }

  close(cb) {
    let pending = this._httpServers.length + this._http2Servers.length;
    if (pending === 0) { if (cb) cb(); return; }
    
    const done = () => { pending -= 1; if (pending === 0 && cb) cb(); };
    for (const s of this._httpServers) s.close(done);
    for (const s of this._http2Servers) s.close(done);
  }

  _addReflectionHandler() {
    this.addHttpHandler({ method: 'GET', path: '/reflect' }, (req, res) => {
      const services = [...this.services.values()].map((svcRecord) => ({
        name: svcRecord.service.name,
        methods: [...svcRecord.service.methods.entries()].map(([name, def]) => ({ name, type: def.type })),
      }));
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ services }));
    });
  }

  async _dispatch(req, res, { allowBidi }) {
    // YENİ: İsteğin hangi yerel IP adresine geldiğini Soket seviyesinden (L4) okuyoruz.
    // IPv6/IPv4 karmaşasını önlemek için (örn: ::ffff:127.0.0.1) 'endsWith' kullanıyoruz.
    const localIp = req.socket.localAddress || '';

    this._applyCors(req, res);

    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }

    for (const { matcher, handler, bindIp } of this.httpHandlers) {
      // SOKET KONTROLÜ: Eğer rota belli bir IP'ye kilitlenmişse ve gelen IP uyuşmuyorsa pas geç.
      if (bindIp && !localIp.endsWith(bindIp)) continue;

      if (this._matches(matcher, req)) {
        try {
          await handler(req, res);
        } catch (e) {
          this._sendHttpError(req, res, e);
        }
        return;
      }
    }

    const parts = req.url.split('?')[0].split('/').filter(Boolean);
    if (parts.length === 2) {
      const svcRecord = this.services.get(parts[0]);
      if (svcRecord) {
        // SOKET KONTROLÜ: gRPC servisi belli bir IP'ye kilitlendiyse doğrula
        if (svcRecord.bindIp && !localIp.endsWith(svcRecord.bindIp)) {
          // İstemci yanlış porttan doğru servise erişmeye çalıştı, pas geç.
        } else {
          const methodDef = svcRecord.service.methods.get(parts[1]);
          if (methodDef) {
            return this._dispatchGrpc(req, res, svcRecord.service, parts[1], methodDef, { allowBidi });
          }
        }
      }
    }
    
    res.statusCode = 404;
    res.end('bulunamadı');
  }

  _matches(matcher, req) {
    const path = req.url.split('?')[0];
    if (typeof matcher === 'string') return path === matcher;
    if (typeof matcher === 'function') return matcher(req);
    if (matcher && typeof matcher === 'object') {
      return (!matcher.method || matcher.method === req.method) && (!matcher.path || matcher.path === path);
    }
    return false;
  }

  async _dispatchGrpc(req, res, service, methodName, methodDef, { allowBidi }) {
    const call = { metadata: { ...req.headers }, context: {} };

    try {
      for (const mw of service.middlewares) await mw(call);
    } catch (e) {
      return this._sendGrpcError(res, e);
    }

    res.statusCode = 200;
    res.setHeader('content-type', 'application/grpc-web-json');

    if (methodDef.type === 'unary' || methodDef.type === 'server_stream') {
      const body = await this._readFullBody(req);
      const { frames } = decodeFrames(body);
      call.request = frames.length ? frames[0].value : null;

      if (methodDef.type === 'unary') {
        try {
          const response = await methodDef.handler(call);
          res.write(encodeFrame(response));
          res.write(encodeFrame({ 'grpc-status': GRPC_STATUS.OK }, { trailer: true }));
        } catch (e) {
          this._writeGrpcErrorFrame(res, e);
        }
        res.end();
      } else {
        call.send = (msg) => res.write(encodeFrame(msg));
        try {
          await methodDef.handler(call);
          res.write(encodeFrame({ 'grpc-status': GRPC_STATUS.OK }, { trailer: true }));
        } catch (e) {
          this._writeGrpcErrorFrame(res, e);
        }
        res.end();
      }
      return;
    }

    if (methodDef.type === 'client_stream') {
      const body = await this._readFullBody(req);
      const { frames } = decodeFrames(body);
      call.requestMessages = frames.filter((f) => !f.trailer).map((f) => f.value);
      try {
        const response = await methodDef.handler(call);
        res.write(encodeFrame(response));
        res.write(encodeFrame({ 'grpc-status': GRPC_STATUS.OK }, { trailer: true }));
      } catch (e) {
        this._writeGrpcErrorFrame(res, e);
      }
      res.end();
      return;
    }

    if (!allowBidi) {
      res.write(encodeFrame({
        'grpc-status': GRPC_STATUS.UNIMPLEMENTED,
        'grpc-message': "bidi sadece gerçek HTTP/2 bağlantısı üzerinden desteklenir",
      }, { trailer: true }));
      res.end();
      return;
    }
    
    const decoder = new FrameDecoder();
    const emitter = new EventEmitter();
    call.on = (event, fn) => { emitter.on(event, fn); return call; };
    call.send = (msg) => res.write(encodeFrame(msg));
    call.end = () => { res.write(encodeFrame({ 'grpc-status': GRPC_STATUS.OK }, { trailer: true })); res.end(); };

    req.on('data', (chunk) => {
      for (const f of decoder.push(chunk)) if (!f.trailer) emitter.emit('message', f.value);
    });
    req.on('end', () => emitter.emit('end'));

    try {
      await methodDef.handler(call);
    } catch (e) {
      this._writeGrpcErrorFrame(res, e);
      res.end();
    }
  }

  _readFullBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }

  _writeGrpcErrorFrame(res, e) {
    const status = e instanceof GrpcError ? e.status : GRPC_STATUS.INTERNAL;
    const message = e instanceof GrpcError ? e.message : 'iç sunucu hatası';
    res.write(encodeFrame({ 'grpc-status': status, 'grpc-message': message }, { trailer: true }));
  }

  _sendGrpcError(res, e) {
    res.statusCode = 200;
    res.setHeader('content-type', 'application/grpc-web-json');
    this._writeGrpcErrorFrame(res, e);
    res.end();
  }

  _sendHttpError(req, res, e) {
      this._applyCors(req, res);

      const status = e.httpStatus || 500;
      res.statusCode = status;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({
          error: e.code || 'internal_error',
          error_description: e.message || 'İç sunucu hatası'
      }));
  }
}

module.exports = {
  GRPC_STATUS, GrpcError, Service, Server,
  encodeFrame, decodeFrames, FrameDecoder,
  requireBearerAuth, requireScope,
};