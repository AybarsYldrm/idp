'use strict';

const http2 = require('node:http2');
const zlib = require('node:zlib');
const { EventEmitter } = require('node:events');
const { encodeMessage, decodeMessage } = require('./protobuf');

const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

const GRPC_STATUS = {
  OK: 0, CANCELLED: 1, UNKNOWN: 2, INVALID_ARGUMENT: 3, DEADLINE_EXCEEDED: 4,
  NOT_FOUND: 5, ALREADY_EXISTS: 6, PERMISSION_DENIED: 7, RESOURCE_EXHAUSTED: 8,
  FAILED_PRECONDITION: 9, ABORTED: 10, OUT_OF_RANGE: 11, UNIMPLEMENTED: 12,
  INTERNAL: 13, UNAVAILABLE: 14, DATA_LOSS: 15, UNAUTHENTICATED: 16,
};

function parseGrpcTimeout(timeoutStr) {
  if (!timeoutStr) return null;
  const match = /^(\d+)([HMSmu])$/.exec(timeoutStr);
  if (!match) return null;
  const val = parseInt(match[1], 10);
  switch (match[2]) {
    case 'H': return val * 3600000;
    case 'M': return val * 60000;
    case 'S': return val * 1000;
    case 'm': return val;
    case 'u': return Math.ceil(val / 1000);
    default: return null;
  }
}

function frameMessage(payload, compress = false) {
  let finalPayload = payload;
  let compressFlag = 0;
  if (compress) { finalPayload = zlib.gzipSync(payload); compressFlag = 1; }
  const frame = Buffer.alloc(5 + finalPayload.length);
  frame.writeUInt8(compressFlag, 0); 
  frame.writeUInt32BE(finalPayload.length, 1);
  finalPayload.copy(frame, 5);
  return frame;
}

class GrpcServer {
  constructor() {
    this.services = new Map();
    this.middlewares = [];
    this.httpHandlers = [];
    this.server = null;
  }

  use(middlewareFn) { this.middlewares.push(middlewareFn); return this; }
  addService(serviceName, methods) { this.services.set(serviceName, methods); return this; }
  addHttpHandler(handlerFn) { this.httpHandlers.push(handlerFn); return this; }

  listen(port, { host = '0.0.0.0', tls = null } = {}) {
    this.server = tls
      ? http2.createSecureServer({ ...tls, allowHTTP1: false })
      : http2.createServer();

    this.server.on('secureConnection', (socket) => socket.setNoDelay(true));
    this.server.on('connection', (socket) => socket.setNoDelay(true));

    this.server.on('stream', async (stream, headers) => {
      try { 
        for (const handler of this.httpHandlers) {
            const handled = await handler(stream, headers);
            if (handled) return; 
        }
        this._handleStream(stream, headers); 
      } 
      catch (e) { this._trailersOnlyError(stream, GRPC_STATUS.INTERNAL, e.message); }
    });

    this.server.on('error', (e) => console.error('[grpc] sunucu hatası:', e));
    this.server.listen(port, host);
    return this.server;
  }

  _trailersOnlyError(stream, code, message) {
    if (stream.headersSent) { stream.end(); return; }
    stream.respond({
      ':status': 200,
      'content-type': 'application/grpc+proto',
      'grpc-status': String(code),
      'grpc-message': encodeURIComponent(message || ''),
      'access-control-allow-origin': CORS_ORIGIN
    }, { endStream: true });
  }

  async _handleStream(stream, headers) {
    const httpMethod = headers[':method'];
    const path = headers[':path'] || '';

    // Frontend HTML Servisi
    if (httpMethod === 'GET' && (path === '/' || path === '/index.html')) {
      const fs = require('node:fs');
      try {
        const html = fs.readFileSync('./index.html');
        stream.respond({ ':status': 200, 'content-type': 'text/html; charset=utf-8' });
        stream.end(html);
      } catch (err) {
        stream.respond({ ':status': 404, 'content-type': 'text/plain; charset=utf-8' });
        stream.end('Hata: index.html bulunamadı.');
      }
      return; 
    }

    if (httpMethod === 'GET' && path === '/favicon.ico') {
      stream.respond({ ':status': 404 }); stream.end(); return;
    }

    if (httpMethod === 'OPTIONS') {
      stream.respond({
        ':status': 200,
        'access-control-allow-origin': CORS_ORIGIN,
        'access-control-allow-methods': 'POST, GET, OPTIONS',
        'access-control-allow-headers': 'content-type, x-grpc-web, authorization, grpc-timeout',
        'access-control-expose-headers': 'grpc-status, grpc-message, x-refresh-token'
      });
      stream.end(); return;
    }

    if (httpMethod !== 'POST') {
      stream.respond({ ':status': 405, 'content-type': 'text/plain; charset=utf-8' });
      stream.end('405 Method Not Allowed'); return;
    }

    const match = /^\/([^/]+)\/([^/]+)$/.exec(path);
    if (!match) return this._trailersOnlyError(stream, GRPC_STATUS.UNIMPLEMENTED, `geçersiz path`);
    const [, serviceName, methodName] = match;
    const svc = this.services.get(serviceName);
    if (!svc) return this._trailersOnlyError(stream, GRPC_STATUS.UNIMPLEMENTED, `servis bulunamadı`);
    
    const method = svc[methodName];
    if (!method) return this._trailersOnlyError(stream, GRPC_STATUS.UNIMPLEMENTED, `metod bulunamadı`);

    const contentType = headers['content-type'] || '';
    const isGrpcWeb = contentType.startsWith('application/grpc-web');
    const clientAcceptsGzip = (headers['grpc-accept-encoding'] || '').includes('gzip');
    
    let timeoutTimer = null;
    const timeoutMs = parseGrpcTimeout(headers['grpc-timeout']);
    if (timeoutMs) {
      timeoutTimer = setTimeout(() => {
        this._trailersOnlyError(stream, GRPC_STATUS.DEADLINE_EXCEEDED, 'Zaman aşımı');
        stream.destroy();
      }, timeoutMs);
    }

    const trailerState = { value: { 'grpc-status': '0' } };
    const call = this._makeCall(stream, method, trailerState, clientAcceptsGzip, timeoutTimer, isGrpcWeb);
    call.headers = headers;

    try {
      for (const mw of this.middlewares) await mw(call);
    } catch (err) {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      return this._trailersOnlyError(stream, err.code || GRPC_STATUS.UNAUTHENTICATED, err.message);
    }

    const responseHeaders = {
      ':status': 200,
      'content-type': isGrpcWeb ? 'application/grpc-web+proto' : 'application/grpc+proto',
      'access-control-allow-origin': CORS_ORIGIN,
      'access-control-expose-headers': 'grpc-status, grpc-message, x-refresh-token'
    };
    if (clientAcceptsGzip) responseHeaders['grpc-encoding'] = 'gzip';

    stream.respond(responseHeaders, { waitForTrailers: !isGrpcWeb });

    if (!isGrpcWeb) {
      stream.on('wantTrailers', () => { try { stream.sendTrailers(trailerState.value); } catch (_) {} });
    }

    // YENİ EKLENDİ: Gerçek Zamanlı (Bidi) akışlarda İstemcinin kopmasını (Disconnect) yakala
    stream.on('close', () => {
        if (!stream.writableEnded) { call.emit('cancelled'); }
    });
    stream.on('error', (err) => { call.emit('error', err); });

    const MAX_PAYLOAD_SIZE = 100 * 1024 * 1024; // 100 MB Limit
    let totalBytesReceived = 0;
    let buf = Buffer.alloc(0);
    
    stream.on('data', (chunk) => {
      totalBytesReceived += chunk.length;
      if (totalBytesReceived > MAX_PAYLOAD_SIZE) {
        stream.destroy(); return;
      }
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      for (;;) {
        if (buf.length < 5) break;
        const isCompressed = buf.readUInt8(0) === 1;
        const len = buf.readUInt32BE(1);
        if (buf.length < 5 + len) break;
        let msgBuf = buf.slice(5, 5 + len);
        buf = buf.slice(5 + len);

        try {
          if (isCompressed) msgBuf = zlib.unzipSync(msgBuf);
          const reqObj = decodeMessage(method.schemas, method.requestType, msgBuf);
          call.emit('message', reqObj);
        } catch (e) {
          return call.end({ code: GRPC_STATUS.INVALID_ARGUMENT, message: `Decode hatası` });
        }
      }
    });
    
    stream.on('end', () => call.emit('end'));
    this._dispatch(method, call);
  }

  // YENİ EKLENDİ: Dispatch artık bidi ve client_stream'i profesyonelce ayırıyor
  _dispatch(method, call) {
    const handleErr = (e) => call.end({ code: e.code || GRPC_STATUS.INTERNAL, message: e.message });
    
    if (method.kind === 'unary' || !method.kind) {
      call.once('message', async (r) => { 
          try { call.write(await method.handler(r, call)); call.end(); } catch(e) { handleErr(e); }
      });
    } else if (method.kind === 'server_stream') {
      call.once('message', async (r) => { 
          try { await method.handler(r, call); call.end(); } catch(e) { handleErr(e); }
      });
    } else if (method.kind === 'client_stream' || method.kind === 'bidi') {
      // Client ve Bidi Stream'lerde tetikleyici handler'ın kendisine bırakılır. 
      // Olayları (call.on('message')) geliştirici kendisi yakalar.
      try {
        const result = method.handler(call);
        if (result instanceof Promise) result.catch(handleErr);
      } catch (e) { handleErr(e); }
    }
  }

  _makeCall(stream, method, trailerState, clientAcceptsGzip, timeoutTimer, isGrpcWeb) {
    const call = new EventEmitter();
    let ended = false;
    
    // YENİ EKLENDİ: Dinamik Trailer (Refresh Token vb. için) desteği
    const dynamicTrailers = {};
    call.setTrailer = (key, value) => { dynamicTrailers[key.toLowerCase()] = value; };

    call.write = (msg) => {
      if (ended || stream.destroyed || stream.writableEnded) return false;
      const payload = encodeMessage(method.schemas, method.responseType, msg);
      const compress = clientAcceptsGzip && payload.length > 100;
      return stream.write(frameMessage(payload, compress));
    };

    call.end = (status) => {
      if (ended) return;
      ended = true;
      if (timeoutTimer) clearTimeout(timeoutTimer);
      
      const code = status && status.code !== undefined ? status.code : GRPC_STATUS.OK;
      
      // Standart treylerler ile geliştiricinin (setTrailer) eklediklerini birleştir
      const trailers = { 'grpc-status': String(code), ...dynamicTrailers };
      if (status && status.message) trailers['grpc-message'] = encodeURIComponent(status.message);
      
      if (isGrpcWeb) {
        let trailerStr = '';
        for (const [k, v] of Object.entries(trailers)) trailerStr += `${k}: ${v}\r\n`;
        const trailerBuf = Buffer.from(trailerStr, 'utf8');
        const frame = Buffer.alloc(5 + trailerBuf.length);
        frame.writeUInt8(0x80, 0); 
        frame.writeUInt32BE(trailerBuf.length, 1);
        trailerBuf.copy(frame, 5);
        
        if (!stream.destroyed && !stream.writableEnded) {
            stream.write(frame);
            stream.end();
        }
      } else {
        trailerState.value = trailers;
        if (!stream.destroyed && !stream.writableEnded) stream.end();
      }
    };
    return call;
  }
}

module.exports = { GrpcServer, GRPC_STATUS, frameMessage };