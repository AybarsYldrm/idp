'use strict';

// ============================================================================
// FitfakAntiBot -- tarayıcı tarafı fingerprint toplama + proof-of-work çözme.
//
// core/fingerprint.js sunucu tarafında bu imzaları TLS/header sinyalleriyle
// birleştirir; core/proof-of-work.js'in verifySolution() ile BİT-BİT uyumlu bir
// SHA-256 tabanlı hashcash çözücüsü burada Web Crypto (crypto.subtle) ile uygulanır.
//
// DÜRÜSTLÜK NOTU: Bu sinyaller (canvas/WebGL/vb.) kararlı bir kimlik KANITI değil --
// gizli modda, farklı tarayıcı ayarlarında, ya da bilinçli bir taklit ile değişebilir.
// Amaç, otomasyonu İMKANSIZ kılmak değil, HACİMLİ botlaşmanın maliyetini yükseltmek
// (bkz. core/rate-limiter.js ve core/proof-of-work.js'teki aynı notlar).
// ============================================================================

(function initFitfakAntiBot(global) {
  async function sha256Bytes(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return new Uint8Array(digest);
  }

  function countLeadingZeroBits(bytes) {
    let count = 0;
    for (let i = 0; i < bytes.length; i++) {
      const byte = bytes[i];
      if (byte === 0) { count += 8; continue; }
      let mask = 0x80;
      while (mask && (byte & mask) === 0) { count++; mask >>= 1; }
      break;
    }
    return count;
  }

  /**
   * Basit, tarayıcıda çalıştırılabilir bir kompozit parmak izi toplar. Sunucuya
   * OLDUĞU GİBİ gönderilir -- sunucu (core/fingerprint.js) bunu kendi gözlemlediği
   * sinyallerle (TLS/header) birleştirip TEK bir güven skoru üretir.
   */
  function collectFingerprint() {
    const nav = typeof navigator !== 'undefined' ? navigator : {};
    const scr = typeof screen !== 'undefined' ? screen : {};
    const signal = {
      userAgent: nav.userAgent || '',
      language: nav.language || '',
      languages: Array.isArray(nav.languages) ? nav.languages.join(',') : '',
      hardwareConcurrency: nav.hardwareConcurrency || 0,
      deviceMemory: nav.deviceMemory || 0,
      screenWidth: scr.width || 0,
      screenHeight: scr.height || 0,
      colorDepth: scr.colorDepth || 0,
      timezone: (Intl.DateTimeFormat().resolvedOptions() || {}).timeZone || '',
      timezoneOffset: new Date().getTimezoneOffset(),
    };

    try {
      signal.canvasHash = collectCanvasSignal();
    } catch {
      signal.canvasHash = null; // canvas engellenmiş/desteklenmiyor -- sorun değil, sadece bu sinyal eksik kalır
    }
    try {
      signal.webglRenderer = collectWebglSignal();
    } catch {
      signal.webglRenderer = null;
    }

    return signal;
  }

  function collectCanvasSignal() {
    const canvas = document.createElement('canvas');
    canvas.width = 220;
    canvas.height = 30;
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(0, 0, 100, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('fitfak-idp fingerprint', 2, 2);
    return canvas.toDataURL();
  }

  function collectWebglSignal() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return null;
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    if (!ext) return null;
    return gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
  }

  /**
   * `challenge`+`nonce` için SHA-256'nın en az `difficultyBits` kadar baştan-sıfır bit'e
   * sahip olduğu bir `nonce` bulana kadar dener -- core/proof-of-work.js'in
   * verifySolution() ile BİT-BİT AYNI algoritma. Ana thread'i kilitlememek için
   * periyodik olarak event loop'a nefes alma fırsatı verir.
   *
   * @param {{challengeId: string, challenge: string, difficultyBits: number}} challenge
   * @param {{onProgress?: (attempts: number) => void, yieldEveryNAttempts?: number}} [opts]
   * @returns {Promise<{challengeId: string, nonce: string, attempts: number, elapsedMs: number}>}
   */
  async function solveProofOfWork(challenge, opts = {}) {
    const { challengeId, challenge: challengeStr, difficultyBits } = challenge;
    const yieldEvery = opts.yieldEveryNAttempts || 400;
    const start = performance.now();
    let nonce = 0;

    for (;;) {
      const digestBytes = await sha256Bytes(`${challengeStr}:${nonce}`);
      if (countLeadingZeroBits(digestBytes) >= difficultyBits) {
        return { challengeId, nonce: String(nonce), attempts: nonce + 1, elapsedMs: performance.now() - start };
      }
      nonce++;
      if (nonce % yieldEvery === 0) {
        if (opts.onProgress) opts.onProgress(nonce);
        // eslint-disable-next-line no-await-in-loop
        await new Promise((resolve) => setTimeout(resolve, 0)); // event loop'a nefes aldır (UI donmasın)
      }
    }
  }

  /**
   * Kolaylık fonksiyonu: sunucudan bir PoW meydan okuması ister, çözer, ve
   * register/login isteğine doğrudan eklenebilecek { powChallengeId, powNonce }
   * alanlarını döner.
   */
  async function fetchAndSolveChallenge(challengeEndpoint = '/auth/pow-challenge', opts = {}) {
    const res = await fetch(challengeEndpoint, { method: 'POST' });
    if (!res.ok) throw new Error(`PoW meydan okuması alınamadı: HTTP ${res.status}`);
    const challenge = await res.json();
    const solved = await solveProofOfWork(challenge, opts);
    return { powChallengeId: solved.challengeId, powNonce: solved.nonce };
  }

  global.FitfakAntiBot = {
    collectFingerprint, solveProofOfWork, fetchAndSolveChallenge,
  };
}(typeof window !== 'undefined' ? window : globalThis));
