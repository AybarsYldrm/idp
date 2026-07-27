'use strict';

const assert = require('node:assert');
const http2 = require('node:http2');
const {
  Server, Service, GRPC_STATUS, GrpcError,
  encodeFrame, decodeFrames, FrameDecoder,
  requireBearerAuth, requireScope,
} = require('../core/http-transport');

const PORT = 51823;
const HTTP2_PORT = 51825;

function fakeVerifyFn(token) {
  if (token === 'good-token') return { payload: { sub: 'u1', scope: 'openid dns:read' } };
  if (token === 'no-scope-token') return { payload: { sub: 'u2', scope: 'openid' } };
  throw new Error('geçersiz token');
}

function grpcUnaryCall(client, path, message, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = client.request({ ':method': 'POST', ':path': path, ...headers });
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const { frames } = decodeFrames(Buffer.concat(chunks));
      resolve(frames);
    });
    req.on('error', reject);
    req.write(encodeFrame(message));
    req.end();
  });
}

function grpcClientStreamCall(client, path, messages, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = client.request({ ':method': 'POST', ':path': path, ...headers });
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const { frames } = decodeFrames(Buffer.concat(chunks));
      resolve(frames);
    });
    req.on('error', reject);
    for (const m of messages) req.write(encodeFrame(m));
    req.end();
  });
}

function httpGet(client, path) {
  return new Promise((resolve, reject) => {
    const req = client.request({ ':method': 'GET', ':path': path });
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
    req.end();
  });
}

async function main() {
  const idSvc = new Service('IdentityTest');
  idSvc.use(requireBearerAuth(fakeVerifyFn));

  idSvc.addUnary('Ping', async (call) => ({ pong: true, sub: call.context.sub, echo: call.request }));

  idSvc.addServerStream('CountTo', async (call) => {
    const n = call.request?.n || 0;
    for (let i = 1; i <= n; i++) call.send({ i });
  });

  idSvc.addClientStream('Sum', async (call) => {
    const sum = call.requestMessages.reduce((acc, m) => acc + (m.value || 0), 0);
    return { sum };
  });

  idSvc.addBidi('Echo', async (call) => {
    call.on('message', (msg) => call.send({ echo: msg }));
    call.on('end', () => call.end());
  });

  // scope-korumalı bir metod: sadece 'dns:read' scope'una sahip token'lar geçebilir
  const dnsSvc = new Service('DnsTest');
  dnsSvc.use(requireBearerAuth(fakeVerifyFn));
  dnsSvc.use(requireScope('dns:read'));
  dnsSvc.addUnary('Resolve', async () => ({ ip: '203.0.113.42' }));

  // hata fırlatan bir metod -- doğru grpc-status trailer'ına dönüşmeli
  idSvc.addUnary('AlwaysFail', async () => { throw new GrpcError(GRPC_STATUS.NOT_FOUND, 'kayıt bulunamadı'); });

  const server = new Server();
  server.addService(idSvc);
  server.addService(dnsSvc);
  server.addHttpHandler({ method: 'GET', path: '/healthz' }, (req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ status: 'ok' }));
  });

  await new Promise((resolve) => server.listen(PORT, { http2Port: HTTP2_PORT }, resolve));
  const client = http2.connect(`http://localhost:${HTTP2_PORT}`);

  try {
    // ---- düz HTTP handler ----
    const health = JSON.parse(await httpGet(client, '/healthz'));
    assert.strictEqual(health.status, 'ok');
    console.log('http-transport: addHttpHandler ile kayıtlı düz HTTP rotası OK');

    // ---- reflection ----
    const reflect = JSON.parse(await httpGet(client, '/reflect'));
    const idReflect = reflect.services.find((s) => s.name === 'IdentityTest');
    assert.ok(idReflect.methods.some((m) => m.name === 'Ping' && m.type === 'unary'));
    assert.ok(idReflect.methods.some((m) => m.name === 'CountTo' && m.type === 'server_stream'));
    assert.ok(idReflect.methods.some((m) => m.name === 'Echo' && m.type === 'bidi'));
    console.log('http-transport: /reflect servis+metod envanterini doğru şekilde döndürdü');

    // ---- kimlik doğrulama olmadan çağrı: UNAUTHENTICATED beklenir ----
    const noAuthFrames = await grpcUnaryCall(client, '/IdentityTest/Ping', { hello: 'world' });
    const noAuthTrailer = noAuthFrames.find((f) => f.trailer);
    assert.strictEqual(noAuthTrailer.value['grpc-status'], GRPC_STATUS.UNAUTHENTICATED);
    console.log('http-transport: Authorization header\'sız çağrı doğru şekilde UNAUTHENTICATED döndürdü');

    // ---- unary (mutlu yol) ----
    const pingFrames = await grpcUnaryCall(client, '/IdentityTest/Ping', { hello: 'world' }, { authorization: 'Bearer good-token' });
    const pingData = pingFrames.find((f) => !f.trailer).value;
    const pingTrailer = pingFrames.find((f) => f.trailer).value;
    assert.strictEqual(pingData.pong, true);
    assert.strictEqual(pingData.sub, 'u1');
    assert.deepStrictEqual(pingData.echo, { hello: 'world' });
    assert.strictEqual(pingTrailer['grpc-status'], GRPC_STATUS.OK);
    console.log('http-transport: unary çağrı (Ping) OK -- middleware context.sub doğru şekilde handler\'a ulaştı');

    // ---- unary hata durumu ----
    const failFrames = await grpcUnaryCall(client, '/IdentityTest/AlwaysFail', {}, { authorization: 'Bearer good-token' });
    const failTrailer = failFrames.find((f) => f.trailer).value;
    assert.strictEqual(failTrailer['grpc-status'], GRPC_STATUS.NOT_FOUND);
    assert.strictEqual(failTrailer['grpc-message'], 'kayıt bulunamadı');
    console.log('http-transport: handler\'ın fırlattığı GrpcError doğru durum kodu+mesajıyla trailer\'a yansıdı');

    // ---- scope kontrolü: yetersiz scope -> PERMISSION_DENIED ----
    const noScopeFrames = await grpcUnaryCall(client, '/DnsTest/Resolve', {}, { authorization: 'Bearer no-scope-token' });
    const noScopeTrailer = noScopeFrames.find((f) => f.trailer).value;
    assert.strictEqual(noScopeTrailer['grpc-status'], GRPC_STATUS.PERMISSION_DENIED);
    console.log('http-transport: requireScope -- yetersiz scope\'lu token doğru şekilde PERMISSION_DENIED ile reddedildi');

    // ---- scope kontrolü: doğru scope -> başarılı ----
    const dnsFrames = await grpcUnaryCall(client, '/DnsTest/Resolve', {}, { authorization: 'Bearer good-token' });
    const dnsData = dnsFrames.find((f) => !f.trailer).value;
    assert.strictEqual(dnsData.ip, '203.0.113.42');
    console.log('http-transport: requireScope -- doğru scope\'lu (dns:read) token başarıyla geçti');

    // ---- server_stream ----
    const countFrames = await grpcUnaryCall(client, '/IdentityTest/CountTo', { n: 4 }, { authorization: 'Bearer good-token' });
    const countData = countFrames.filter((f) => !f.trailer).map((f) => f.value);
    assert.deepStrictEqual(countData, [{ i: 1 }, { i: 2 }, { i: 3 }, { i: 4 }]);
    console.log('http-transport: server_stream (CountTo) -- 4 ayrı veri çerçevesi + son trailer doğru sırada geldi');

    // ---- client_stream ----
    const sumFrames = await grpcClientStreamCall(client, '/IdentityTest/Sum', [{ value: 3 }, { value: 4 }, { value: 5 }], { authorization: 'Bearer good-token' });
    const sumData = sumFrames.find((f) => !f.trailer).value;
    assert.strictEqual(sumData.sum, 12);
    console.log('http-transport: client_stream (Sum) -- istemcinin art arda çerçevelediği 3 mesaj doğru toplandı');

    // ---- bidi (gerçek çift-yönlü, Node<->Node) ----
    await new Promise((resolve, reject) => {
      const req = client.request({ ':method': 'POST', ':path': '/IdentityTest/Echo', authorization: 'Bearer good-token' });
      const decoder = new FrameDecoder();
      const received = [];
      req.on('data', (chunk) => {
        for (const f of decoder.push(chunk)) {
          if (f.trailer) {
            try {
              assert.strictEqual(f.value['grpc-status'], GRPC_STATUS.OK);
              assert.deepStrictEqual(received, [{ echo: { n: 1 } }, { echo: { n: 2 } }]);
              console.log('http-transport: bidi (Echo) -- iki yönlü, gerçek zamanlı mesaj alışverişi OK');
              resolve();
            } catch (e) { reject(e); }
          } else {
            received.push(f.value);
          }
        }
      });
      req.on('error', reject);
      req.write(encodeFrame({ n: 1 }));
      req.write(encodeFrame({ n: 2 }));
      req.end();
    });

    console.log('\nALL HTTP-TRANSPORT CHECKS PASSED (HTTP route + reflection + unary + hata + scope + server_stream + client_stream + bidi)');

    // ---- KRİTİK DOĞRULAMA: düz HTTP/1.1 portu (tarayıcıların/fetch()'in kullanacağı) ----
    // node:http2'nin allowHTTP1 ile otomatik h1-downgrade'i bu ortamda GÜVENİLİR
    // ÇALIŞMADIĞI için (bkz. core/http-transport.js başlığı), ayrı bir düz `http` modülü
    // istemcisiyle asıl `PORT`'u (http2Port DEĞİL) test ediyoruz -- gerçek bir tarayıcının
    // deneyimlediği yolun AYNISI.
    const http = require('node:http');
    const plainHttpGet = (path) => new Promise((resolve, reject) => {
      http.get(`http://localhost:${PORT}${path}`, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      }).on('error', reject);
    });
    const plainHealth = JSON.parse(await plainHttpGet('/healthz'));
    assert.strictEqual(plainHealth.status, 'ok');
    console.log('http-transport: [PORT, düz HTTP/1.1 istemcisiyle] addHttpHandler rotası OK -- tarayıcıların göreceği TAM senaryo');

    const plainPingResult = await new Promise((resolve, reject) => {
      const req = http.request(`http://localhost:${PORT}/IdentityTest/Ping`, { method: 'POST', headers: { authorization: 'Bearer good-token' } }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(decodeFrames(Buffer.concat(chunks)).frames));
      });
      req.on('error', reject);
      req.write(encodeFrame({ hello: 'plain-http1' }));
      req.end();
    });
    const plainPingData = plainPingResult.find((f) => !f.trailer).value;
    assert.deepStrictEqual(plainPingData.echo, { hello: 'plain-http1' });
    console.log('http-transport: [PORT, düz HTTP/1.1] unary (Ping) çağrısı da mükemmel çalışıyor -- tarayıcılar bunu SORUNSUZ kullanabilir');

    const plainBidiResult = await new Promise((resolve, reject) => {
      const req = http.request(`http://localhost:${PORT}/IdentityTest/Echo`, { method: 'POST', headers: { authorization: 'Bearer good-token' } }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(decodeFrames(Buffer.concat(chunks)).frames));
      });
      req.on('error', reject);
      req.write(encodeFrame({ n: 1 }));
      req.end();
    });
    const plainBidiTrailer = plainBidiResult.find((f) => f.trailer).value;
    assert.strictEqual(plainBidiTrailer['grpc-status'], GRPC_STATUS.UNIMPLEMENTED);
    console.log('http-transport: [PORT, düz HTTP/1.1] bidi çağrısı beklendiği gibi UNIMPLEMENTED döndü (gerçek bidi için http2Port ya da bidi-bridge gerekir) -- YANLIŞ DAVRANMADI, açıkça reddetti');
  } finally {
    client.close();
    server.close();
  }
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
