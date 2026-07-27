'use strict';

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { encodeFrame, decodeFrames, GRPC_STATUS } = require('./http-transport');

// ============================================================================
// DÜRÜSTLÜK NOTU (bkz. README "Kapsam ve sınırlamalar"): tarayıcılar JavaScript'ten
// GERÇEK çift-yönlü bir HTTP/2 akışı açamaz -- fetch()'in "duplex: half" desteği son
// derece kısıtlı ve tüm tarayıcılarda güvenilir değil, XHR'de hiç yok. Bu köprü, TEK bir
// gerçek bidi ceremony'sini (core/http-transport.js'teki Server'ın bidi dalı, ki bu SADECE
// Node<->Node HTTP/2 istemcileri arasında -- örn. client/identity-client.js -- gerçekten
// çift-yönlüdür) tarayıcı için İKİ AYRI, sıradan HTTP isteğine böler:
//
//   - subscribe (server_stream, AÇIK KALAN bir GET): sunucudan istemciye giden mesajlar
//   - send (unary POST, her mesaj için ayrı kısa istek): istemciden sunucuya giden mesajlar
//
// İkisi paylaşılan bir `bridgeSessionId` ile eşleştirilir. Handler fonksiyonu
// (`(call) => {...}`) core/http-transport.js'teki `service.addBidi(name, handler)` ile
// TAM AYNI imzayı kullanır -- handler'ın kendisi altta gerçek bir tek-akış mı yoksa bu
// iki-istekli taklit mi olduğunu bilmez/bilmemesi gerekir. Somut kullanım senaryosu
// (README'de detaylandırıldı): canlı güvenlik/oturum olayı bildirimleri -- "yeni bir
// cihazdan giriş yapıldı, bu oturumu iptal etmek ister misiniz?" gibi anlık push'lar.
// ============================================================================

class BidiBridge {
  constructor() {
    this.sessions = new Map(); // bridgeSessionId -> session kaydı
  }

  /** @param {(call) => void|Promise<void>} handler */
  createSession(handler) {
    const bridgeSessionId = crypto.randomUUID();
    const emitter = new EventEmitter();
    const outbox = []; // subscribe henüz bağlanmadan ÖNCE gönderilen mesajlar burada kuyruklanır
    let pushToSubscriber = null;
    let ended = false;

    const call = {
      on: (event, fn) => { emitter.on(event, fn); return call; },
      send: (msg) => {
        if (pushToSubscriber) pushToSubscriber(msg);
        else outbox.push(msg);
      },
      end: () => {
        ended = true;
        if (pushToSubscriber) pushToSubscriber(null, { end: true });
      },
    };

    this.sessions.set(bridgeSessionId, {
      emitter,
      attachSubscriber: (fn) => {
        pushToSubscriber = fn;
        while (outbox.length) pushToSubscriber(outbox.shift());
        if (ended) pushToSubscriber(null, { end: true });
      },
      detachSubscriber: () => { pushToSubscriber = null; },
    });

    Promise.resolve(handler(call)).catch((e) => {
      // eslint-disable-next-line no-console
      console.error('bidi-bridge: handler hatası', e);
      emitter.emit('_handlerError', e);
    });

    return bridgeSessionId;
  }

  getSession(id) { return this.sessions.get(id); }
  removeSession(id) { this.sessions.delete(id); }
}

function readFullBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * Bir `handler(call)` fonksiyonunu, verilen `pathPrefix` altında dört HTTP uç noktası
 * olarak monte eder: POST {prefix}/open, GET {prefix}/subscribe?session=, POST
 * {prefix}/send?session=, POST {prefix}/close?session=. `server`, core/http-transport.js
 * Server örneğidir (addHttpHandler kullanılır -- gRPC dispatch'e karışmaz).
 */
function mountBidiBridge(server, pathPrefix, handler) {
  const bridge = new BidiBridge();

  server.addHttpHandler({ method: 'POST', path: `${pathPrefix}/open` }, (req, res) => {
    const bridgeSessionId = bridge.createSession(handler);
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ bridgeSessionId }));
  });

  server.addHttpHandler({ method: 'GET', path: `${pathPrefix}/subscribe` }, (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const sessionId = url.searchParams.get('session');
    const session = bridge.getSession(sessionId);
    if (!session) { res.statusCode = 404; res.end(); return; }

    res.statusCode = 200;
    res.setHeader('content-type', 'application/grpc-web-json');
    session.attachSubscriber((msg, opts) => {
      if (opts?.end) {
        res.write(encodeFrame({ 'grpc-status': GRPC_STATUS.OK }, { trailer: true }));
        res.end();
        bridge.removeSession(sessionId);
      } else {
        res.write(encodeFrame(msg));
      }
    });

    req.on('close', () => session.detachSubscriber());
  });

  server.addHttpHandler({ method: 'POST', path: `${pathPrefix}/send` }, async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const sessionId = url.searchParams.get('session');
    const session = bridge.getSession(sessionId);
    if (!session) { res.statusCode = 404; res.end(); return; }

    const body = await readFullBody(req);
    const { frames } = decodeFrames(body);
    for (const f of frames) if (!f.trailer) session.emitter.emit('message', f.value);

    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ok: true }));
  });

  server.addHttpHandler({ method: 'POST', path: `${pathPrefix}/close` }, (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const sessionId = url.searchParams.get('session');
    const session = bridge.getSession(sessionId);
    if (session) session.emitter.emit('end');
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ok: true }));
  });

  return bridge;
}

module.exports = { BidiBridge, mountBidiBridge };
