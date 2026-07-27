'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const { ProofOfWorkService, countLeadingZeroBits } = require('../core/proof-of-work');
const { LoginProtection } = require('../core/rate-limiter');
const fingerprint = require('../core/fingerprint');

function solvePow(challenge, difficultyBits) {
  // Tarayıcının yapacağı brute-force çözümü Node tarafında simüle ediyoruz. Testin hızlı
  // kalması için düşük zorluk (bit sayısı) kullanıyoruz -- üretim varsayılanı ~18-22 bit.
  let nonce = 0;
  for (;;) {
    const digest = crypto.createHash('sha256').update(`${challenge}:${nonce}`).digest();
    if (countLeadingZeroBits(digest) >= difficultyBits) return String(nonce);
    nonce++;
  }
}

async function main() {
  // ---- Proof of Work ----
  const pow = new ProofOfWorkService({ ttlMs: 5000 });
  const issued = await pow.issueChallenge({ difficultyBits: 12 }); // test için düşük zorluk
  const nonce = solvePow(issued.challenge, issued.difficultyBits);
  const result = await pow.verifySolution({ challengeId: issued.challengeId, nonce });
  assert.strictEqual(result.ok, true);
  console.log(`pow: geçerli çözüm kabul edildi (difficulty=${issued.difficultyBits} bit, nonce=${nonce})`);

  // aynı challenge tekrar sunulamaz (tek kullanımlık)
  const replay = await pow.verifySolution({ challengeId: issued.challengeId, nonce });
  assert.strictEqual(replay.ok, false);
  assert.strictEqual(replay.reason, 'unknown_or_already_used_challenge');
  console.log('pow: aynı challenge tekrar (replay) doğru şekilde reddedildi');

  // yetersiz iş (rastgele/çözülmemiş nonce neredeyse kesin başarısız olur)
  const issued2 = await pow.issueChallenge({ difficultyBits: 20 });
  const badGuess = await pow.verifySolution({ challengeId: issued2.challengeId, nonce: '0' });
  assert.strictEqual(badGuess.ok, false);
  assert.strictEqual(badGuess.reason, 'insufficient_work');
  console.log('pow: yetersiz/çözülmemiş iş doğru şekilde reddedildi');

  // bilinmeyen challengeId reddedilmeli
  const unknown = await pow.verifySolution({ challengeId: 'olmayan-id', nonce: '0' });
  assert.strictEqual(unknown.ok, false);
  console.log('pow: bilinmeyen challengeId doğru şekilde reddedildi');
  pow.stop();

  // ---- Rate Limiter: server.js'teki boşluğun kapandığını kanıtla ----
  // Senaryo: TEK bir IP'den, HER SEFERİNDE FARKLI bir kullanıcı adıyla deneme (credential
  // stuffing). Referans koddaki `${username}:${ip}` bileşik anahtarı bunu YAKALAYAMAZDI
  // çünkü her (kullanıcıadı, ip) çifti kendi başına eşiğin altında kalır.
  const protection = new LoginProtection({ perIp: { windowMs: 60_000, max: 10 } });
  let caughtByPureIpAxis = false;
  for (let i = 0; i < 25; i++) {
    const { limited, results } = protection.recordAttempt({ ip: '203.0.113.9', username: `kurban_${i}` });
    if (limited && results.ip.limited && !results.ipUsername.limited) {
      caughtByPureIpAxis = true;
      break;
    }
  }
  assert.ok(caughtByPureIpAxis, 'tek IP + farklı kullanıcı adları saldırısı salt-IP ekseninde yakalanmalıydı');
  console.log('rate-limiter: tek-IP/çoklu-kullanıcı-adı (credential stuffing) saldırısı salt-IP ekseninde doğru şekilde yakalandı');

  // ---- Kademeli kilitleme ----
  const protection2 = new LoginProtection({});
  assert.strictEqual(protection2.isLockedOut('abuzer'), false);
  protection2.recordFailure('abuzer'); // 1. hata: henüz kilitlenmez (typo toleransı)
  assert.strictEqual(protection2.isLockedOut('abuzer'), false);
  protection2.recordFailure('abuzer'); // 2. hata
  protection2.recordFailure('abuzer'); // 3. hata: artık kilitlenmeli
  assert.strictEqual(protection2.isLockedOut('abuzer'), true);
  console.log('rate-limiter: kademeli kilitleme (ilk hatalarda tolerans, ısrarda kilit) doğru çalışıyor');
  protection2.recordSuccess('abuzer'); // başarılı giriş kilidi ve sayaçları temizlemeli
  assert.strictEqual(protection2.isLockedOut('abuzer'), false);
  console.log('rate-limiter: başarılı giriş sonrası kilit/sayaç sıfırlanıyor');

  // adaptif PoW zorluğu: şüpheli hacimde artmalı
  const proto3 = new LoginProtection({});
  const baseline = proto3.recommendedPowDifficultyBits({ ip: '198.51.100.1', fingerprintTrust: 0.5 });
  for (let i = 0; i < 15; i++) proto3.recordAttempt({ ip: '198.51.100.1', username: `x${i}` });
  const afterBurst = proto3.recommendedPowDifficultyBits({ ip: '198.51.100.1', fingerprintTrust: 0.5 });
  assert.ok(afterBurst > baseline, `beklenen: yoğun trafik sonrası PoW zorluğu artmalı (${baseline} -> ${afterBurst})`);
  console.log(`rate-limiter: yoğun trafik sonrası adaptif PoW zorluğu arttı (${baseline} -> ${afterBurst} bit)`);

  // ---- Fingerprint: istemci imzası eksikse güven skoru düşmeli ----
  const serverSignals = fingerprint.extractServerSignals({ 'user-agent': 'Mozilla/5.0 test' }, {});
  const withClient = fingerprint.combine({ clientFingerprint: { webdriver: false, hasConsistentTimezone: true }, serverSignals });
  const withoutClient = fingerprint.combine({ clientFingerprint: null, serverSignals });
  assert.ok(withoutClient.trustScore < withClient.trustScore, 'istemci fingerprint\'i olmayan istek daha düşük güven almalı');
  const webdriverFlagged = fingerprint.combine({ clientFingerprint: { webdriver: true }, serverSignals });
  assert.ok(webdriverFlagged.trustScore < withClient.trustScore, 'navigator.webdriver=true güveni düşürmeli');
  console.log('fingerprint: istemci sinyali eksikliği ve webdriver bayrağı güven skorunu doğru şekilde düşürüyor');

  console.log('\nALL ANTI-BOT (PoW + rate-limiter + fingerprint) CHECKS PASSED');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
