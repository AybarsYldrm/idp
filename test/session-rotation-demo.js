'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fsp = require('node:fs/promises');
const { SessionManager, SessionError } = require('../core/session-manager');
const { loadOrCreateSigningKeyPair } = require('../core/keys');
const { createMockStore } = require('./mock-store');

async function main() {
  const keyDir = path.join(__dirname, '..', '.tmp-session-demo-keys');
  await fsp.rm(keyDir, { recursive: true, force: true });
  const signingKeyPair = loadOrCreateSigningKeyPair(keyDir);

  const store = createMockStore();
  const sm = new SessionManager({ store, signingKeyPair, issuer: 'https://session.fitfak.net', cookieDomain: '.fitfak.net' });

  // ---- ilk oturum oluşturma ----
  const { sessionId, accessToken, refreshToken } = await sm.createSession({
    userId: 'u1', ip: '203.0.113.5', userAgent: 'test-agent', fingerprintId: 'fp1',
  });
  assert.ok(sessionId && accessToken && refreshToken);
  const { payload } = sm.verifyAccessToken(accessToken);
  assert.strictEqual(payload.sub, 'u1');
  assert.strictEqual(payload.aud, 'self');
  console.log('session-manager: createSession OK, access token doğru claim\'lerle imzalandı');

  // ---- SSO çerezleri doğru bayraklarla üretiliyor mu ----
  const cookieStrings = sm.buildSsoCookies({ accessToken, refreshToken });
  assert.ok(cookieStrings.some((c) => c.includes('Domain=.fitfak.net') && c.includes('HttpOnly') && c.includes('Secure') && c.includes('SameSite=Lax')));
  assert.ok(cookieStrings.some((c) => c.includes('Path=/oauth/token'))); // refresh cookie'si dar path'e hapsedilmiş
  console.log('session-manager: SSO cookie\'leri Domain=.fitfak.net; HttpOnly; Secure; SameSite=Lax ile doğru üretiliyor');

  // ---- normal refresh (rotasyon) ----
  const refreshed = await sm.refresh({ refreshToken, ip: '203.0.113.5', userAgent: 'test-agent' });
  assert.notStrictEqual(refreshed.refreshToken, refreshToken, 'rotasyon sonrası YENİ bir refresh token dönmeli');
  console.log('session-manager: refresh rotasyonu OK -- yeni access+refresh çifti üretildi');

  // ---- ESKİ (rotasyondan önceki) refresh token'ın TEKRAR kullanılması: HIRSIZLIK sinyali ----
  // Bu, gerçek dünyada "saldırgan eski bir token'ı yakaladı ve kullanmayı denedi" senaryosu.
  await assert.rejects(
    () => sm.refresh({ refreshToken, ip: '198.51.100.66', userAgent: 'saldirgan-agent' }),
    (e) => e instanceof SessionError && e.code === 'refresh_token_reuse',
  );
  console.log('session-manager: rotasyona uğramış (eski) refresh token\'ın tekrar kullanımı doğru şekilde reddedildi');

  // ---- ...VE bu, meşru kullanıcının YENİ (rotasyondan sonraki geçerli) token'ını da geçersiz kılmalı,
  // çünkü tüm oturum iptal edildi -- bu kasıtlı bir tasarım: hırsızlık şüphesinde tüm zincir yanar.
  await assert.rejects(
    () => sm.refresh({ refreshToken: refreshed.refreshToken, ip: '203.0.113.5', userAgent: 'test-agent' }),
    (e) => e instanceof SessionError && e.code === 'refresh_token_reuse',
  );
  console.log('session-manager: reuse tespiti sonrası TÜM oturum (yeni token dahil) doğru şekilde iptal edilmiş durumda');

  const revokedSession = await store.getSessionById(sessionId);
  assert.strictEqual(revokedSession.revoked, true);
  assert.strictEqual(revokedSession.revokedReason, 'refresh_token_reuse_detected');
  console.log('session-manager: oturum kaydı revoked=true + doğru sebep ile işaretlenmiş');

  // ---- yeni, temiz bir oturumda: kullanıcı tarafından MANUEL iptal (revoke) ----
  const session2 = await sm.createSession({ userId: 'u1', ip: '203.0.113.5', userAgent: 'ikinci-cihaz' });
  await sm.revokeSession(session2.sessionId, 'user_requested');
  await assert.rejects(
    () => sm.refresh({ refreshToken: session2.refreshToken }),
    (e) => e instanceof SessionError,
  );
  console.log('session-manager: manuel revokeSession() sonrası refresh doğru şekilde reddediliyor');

  // ---- oturum listeleme (kullanıcının "aktif oturumlarım" ekranı) ----
  const session3 = await sm.createSession({ userId: 'u1', ip: '203.0.113.5', userAgent: 'ucuncu-cihaz' });
  const list = await sm.listSessions('u1');
  assert.ok(list.length >= 3); // ilk (iptal), ikinci (iptal), üçüncü (aktif)
  assert.ok(list.some((s) => s.sessionId === session3.sessionId && !s.revoked));
  console.log(`session-manager: listSessions('u1') ${list.length} oturum döndürdü, aralarında aktif üçüncü oturum var`);

  // ---- farklı bir relying party (OAuth client) için token üretme ----
  const rpTokens = await sm.issueTokensForClient({ sessionId: session3.sessionId, clientId: 'dns-fitfak-net', scope: 'openid profile dns:read' });
  const { payload: rpPayload } = sm.verifyAccessToken(rpTokens.accessToken);
  assert.strictEqual(rpPayload.aud, 'dns-fitfak-net');
  assert.strictEqual(rpPayload.scope, 'openid profile dns:read');
  console.log('session-manager: issueTokensForClient farklı bir relying party için doğru aud/scope ile token üretti');

  // ---- iptal edilmiş oturum için token üretilemez ----
  await sm.revokeSession(session3.sessionId, 'test');
  await assert.rejects(() => sm.issueTokensForClient({ sessionId: session3.sessionId, clientId: 'dns-fitfak-net', scope: 'openid' }));
  console.log('session-manager: iptal edilmiş oturum için yeni relying-party token\'ı üretimi doğru şekilde reddedildi');

  console.log('\nALL SESSION-MANAGER CHECKS PASSED');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
