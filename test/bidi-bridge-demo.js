'use strict';

const assert = require('node:assert');
const http = require('node:http');
const { Server, encodeFrame, FrameDecoder, GRPC_STATUS } = require('../core/http-transport');
const { mountBidiBridge } = require('../core/bidi-bridge');

const PORT = 51824;

// Bilerek düz `node:http` istemcisi kullanılıyor (http2.connect() DEĞİL): bu köprünün
// TÜM amacı, gerçek bir tarayıcının (h2c konuşamayan) deneyimlediği TAM senaryoyu
// simüle etmek -- bkz. core/bidi-bridge.js başlığı.
function httpPost(path, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(`http://localhost:${PORT}${path}`, { method: 'POST' }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function main() {
  // Aynı handler imzası core/http-transport.js'teki service.addBidi(name, handler) ile
  // birebir aynı -- gerçek bidi'de de, bu köprüde de DEĞİŞMEDEN kullanılabilir olduğunu
  // göstermek için kasıtlı olarak aynı şekilde yazıldı.
  async function welcomeEchoHandler(call) {
    call.send({ welcome: true }); // subscribe henüz bağlanmamışken gönderiliyor -- kuyruklanmalı
    call.on('message', (msg) => call.send({ echo: msg }));
    call.on('end', () => call.end());
  }

  const server = new Server();
  mountBidiBridge(server, '/bridge/echo', welcomeEchoHandler);
  await new Promise((resolve) => server.listen(PORT, resolve));

  try {
    // ---- 1) open ----
    const openBody = await httpPost('/bridge/echo/open');
    const { bridgeSessionId } = JSON.parse(openBody.toString('utf8'));
    assert.ok(bridgeSessionId);
    console.log('bidi-bridge: /open oturum başlattı, handler senkron olarak çalıştı (welcome mesajı kuyruklandı)');

    // ---- 2) subscribe (welcome mesajının, subscribe bağlandığı anda hemen teslim edildiğini doğrula) ----
    const received = [];
    let resolveEnd;
    const endPromise = new Promise((resolve) => { resolveEnd = resolve; });

    const decoder = new FrameDecoder();
    const subReq = http.request(`http://localhost:${PORT}/bridge/echo/subscribe?session=${bridgeSessionId}`, { method: 'GET' }, (res) => {
      res.on('data', (chunk) => {
        for (const f of decoder.push(chunk)) {
          if (f.trailer) {
            assert.strictEqual(f.value['grpc-status'], GRPC_STATUS.OK);
            resolveEnd();
          } else {
            received.push(f.value);
          }
        }
      });
    });
    subReq.end();

    // subscribe'ın bağlanıp welcome mesajını almasını bekle
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.deepStrictEqual(received, [{ welcome: true }]);
    console.log('bidi-bridge: subscribe bağlanır bağlanmaz kuyruklanmış (open sırasında gönderilmiş) mesajı hemen aldı');

    // ---- 3) send x2 ----
    await httpPost(`/bridge/echo/send?session=${bridgeSessionId}`, encodeFrame({ n: 1 }));
    await httpPost(`/bridge/echo/send?session=${bridgeSessionId}`, encodeFrame({ n: 2 }));
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.deepStrictEqual(received, [{ welcome: true }, { echo: { n: 1 } }, { echo: { n: 2 } }]);
    console.log('bidi-bridge: iki ayrı /send isteği (düz HTTP/1.1 POST), TEK açık subscribe akışına (düz HTTP/1.1 GET) doğru sırada yansıdı -- gerçek bir tarayıcının kullanacağı BİREBİR mekanizma');

    // ---- 4) close ----
    await httpPost(`/bridge/echo/close?session=${bridgeSessionId}`);
    await endPromise;
    console.log('bidi-bridge: /close -> handler\'ın call.end() çağrısı subscribe akışını doğru OK trailer\'ıyla kapattı');

    console.log('\nALL BIDI-BRIDGE CHECKS PASSED (open -> subscribe -> send x2 -> close, düz HTTP/1.1 üzerinden -- gerçek tarayıcı senaryosu)');
  } finally {
    server.close();
  }
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
