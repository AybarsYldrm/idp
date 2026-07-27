'use strict';

// ============================================================================
// IdentityClient -- diğer backend servislerinizin (örn. dns.fitfak.net'in KENDİ
// sunucu tarafı kodu, bir tarayıcı DEĞİL) fitfak-idp'nin gRPC IdentityService'ini
// kolayca çağırabilmesi için Node.js SDK'sı.
//
// KULLANIM:
//   const { IdentityClient } = require('@fitfak/idp-client'); // ya da dosyayı kopyalayın
//   const identity = new IdentityClient({
//     baseUrl: 'https://session.fitfak.net',
//     clientId: 'dns-fitfak-net',
//     clientSecret: process.env.FITFAK_IDP_CLIENT_SECRET,
//   });
//
//   const info = await identity.introspectToken(accessToken);
//   if (!info.active) { /* reddet */ }
//
// GÜVENLİK NOTU: `clientSecret` bir SIR'dır -- ASLA tarayıcıya göndermeyin, ASLA
// önyüz (frontend) koduna gömmeyin. Bu SDK sadece güvendiğiniz backend sunucunuzda
// çalıştırılmalıdır. Kimlik doğrulama, kullanıcının kendi access token'ı ile DEĞİL,
// bu servisin (dns-fitfak-net'in) KENDİ client kimlik bilgileriyle yapılır -- bu
// yüzden IntrospectToken/VerifySession/vb. çağrıları, SİZİN RP'nize (audience'ı
// clientId'nizle eşleşen) ait oturumlarla sınırlıdır; başka bir RP'nin oturumlarını
// göremez/iptal edemezsiniz (bkz. oauth-server.js IdentityService implementasyonu).
// ============================================================================

const http = require('node:http');
const https = require('node:https');
const http2 = require('node:http2');
const { encodeFrame, decodeFrames, FrameDecoder, GRPC_STATUS } = require('../core/http-transport');

class IdentityClientError extends Error {
  constructor(message, { grpcStatus, method } = {}) {
    super(message);
    this.name = 'IdentityClientError';
    this.grpcStatus = grpcStatus;
    this.method = method;
  }
}

class IdentityClient {
  /**
   * @param {object} opts
   * @param {string} opts.baseUrl - fitfak-idp'nin HTTP(S) adresi, örn. 'https://session.fitfak.net'
   *   (unary çağrılar İÇİN -- bunlar düz HTTP/1.1 üzerinden çalışır, gerçek HTTP/2 GEREKMEZ,
   *   bkz. core/http-transport.js'in dual-listener notu).
   * @param {string} [opts.http2Url] - SADECE gerçek Node<->Node bidi metodları (varsa)
   *   çağırmak isterseniz gerekli, örn. 'http://localhost:8444'. Şu an bu SDK'daki 4 temel
   *   metodun (IntrospectToken/VerifySession/GetUserSessions/RevokeSession) hiçbiri bidi
   *   DEĞİL, hepsi unary -- bu alan yalnızca ileride kendi bidi metodlarınızı eklerseniz
   *   kullanılabilecek bir genişleme noktası.
   * @param {string} opts.clientId - fitfak-idp'ye kayıtlı client ID'niz (örn. 'dns-fitfak-net')
   * @param {string} opts.clientSecret - o client'a ait SIR (asla tarayıcıya göndermeyin)
   * @param {number} [opts.timeoutMs=10000]
   */
  constructor({
    baseUrl, http2Url, clientId, clientSecret, timeoutMs = 10_000,
  }) {
    if (!baseUrl) throw new Error('IdentityClient: baseUrl gerekli (örn. https://session.fitfak.net)');
    if (!clientId || !clientSecret) throw new Error('IdentityClient: clientId ve clientSecret gerekli');
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.http2Url = http2Url;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.timeoutMs = timeoutMs;
  }

  // --------------------------------------------------------------------------
  // Temel unary gRPC çağrısı -- düz HTTP/1.1 (ya da HTTPS) üzerinden, core/http-
  // transport.js ile AYNI 5-byte çerçeveleme kullanılarak. Gerçek HTTP/2 gerekmez
  // (bkz. core/http-transport.js: unary/server_stream/client_stream'in hiçbiri
  // çift-yönlü akış gerektirmediği için düz HTTP/1.1'de mükemmel çalışır).
  // --------------------------------------------------------------------------
  _unaryCall(methodName, requestObj) {
    return new Promise((resolve, reject) => {
      let url;
      try {
        url = new URL(`${this.baseUrl}/IdentityService/${methodName}`);
      } catch (e) {
        return reject(new IdentityClientError(`geçersiz baseUrl: ${e.message}`, { method: methodName }));
      }
      const lib = url.protocol === 'https:' ? https : http;
      const body = encodeFrame(requestObj);

      const req = lib.request(url, {
        method: 'POST',
        headers: {
          'x-client-id': this.clientId,
          'x-client-secret': this.clientSecret,
          'content-type': 'application/grpc-web-json',
          'content-length': body.length,
        },
        timeout: this.timeoutMs,
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          let frames;
          try {
            ({ frames } = decodeFrames(Buffer.concat(chunks)));
          } catch (e) {
            return reject(new IdentityClientError(`yanıt çözümlenemedi: ${e.message}`, { method: methodName }));
          }
          const dataFrame = frames.find((f) => !f.trailer);
          const trailerFrame = frames.find((f) => f.trailer);
          const status = trailerFrame?.value?.['grpc-status'];
          if (status !== undefined && status !== GRPC_STATUS.OK) {
            return reject(new IdentityClientError(
              trailerFrame.value['grpc-message'] || `IdentityService.${methodName} başarısız oldu`,
              { grpcStatus: status, method: methodName },
            ));
          }
          resolve(dataFrame ? dataFrame.value : null);
        });
      });
      req.on('timeout', () => req.destroy(new IdentityClientError(`IdentityService.${methodName} zaman aşımına uğradı (${this.timeoutMs}ms)`, { method: methodName })));
      req.on('error', (e) => reject(new IdentityClientError(`ağ hatası: ${e.message}`, { method: methodName })));
      req.write(body);
      req.end();
    });
  }

  /**
   * Bir access token'ın hâlâ geçerli olup olmadığını kontrol eder (imza + süre + CANLI
   * iptal durumu -- JWT'nin kendisi henüz süresi dolmamış olsa BİLE oturum iptal
   * edilmişse `active: false` döner).
   * @param {string} token
   * @returns {Promise<{active: boolean, sub?: string, scope?: string, exp?: number}>}
   */
  introspectToken(token) {
    return this._unaryCall('IntrospectToken', { token });
  }

  /**
   * Bir oturumun (sessionId ile) hâlâ geçerli ve SİZİN RP'nize ait olup olmadığını
   * kontrol eder. Başka bir RP'ye ait bir sessionId sorgularsanız PERMISSION_DENIED alırsınız.
   * @param {string} sessionId
   * @returns {Promise<{valid: boolean, userId?: string, scope?: string}>}
   */
  verifySession(sessionId) {
    return this._unaryCall('VerifySession', { sessionId });
  }

  /**
   * Bir kullanıcının, SİZİN RP'nize ait TÜM aktif oturumlarını listeler (diğer RP'lere
   * ait oturumlar -- örn. kullanıcının session.fitfak.net'te doğrudan açtığı oturumlar --
   * bu listede GÖRÜNMEZ, bu kasıtlıdır).
   * @param {string} userId
   */
  getUserSessions(userId) {
    return this._unaryCall('GetUserSessions', { userId });
  }

  /**
   * Bir oturumu iptal eder (örn. kullanıcı sizin sisteminizden "tüm cihazlardan çıkış
   * yap" dediğinde). Sadece SİZİN RP'nize ait oturumlar iptal edilebilir.
   * @param {string} sessionId
   */
  revokeSession(sessionId) {
    return this._unaryCall('RevokeSession', { sessionId });
  }

  // --------------------------------------------------------------------------
  // GENİŞLEME NOKTASI: gerçek Node<->Node bidi. Şu anki 4 metodun hiçbiri buna
  // ihtiyaç duymuyor (hepsi unary), ama fitfak-idp'ye kendi bidi metodunuzu
  // eklerseniz (core/http-transport.js'teki service.addBidi ile), burada
  // http2.connect(this.http2Url) kullanarak GERÇEK çift-yönlü bir bağlantı
  // açabilirsiniz -- core/bidi-bridge.js'e gerek YOK, çünkü bu bir tarayıcı değil,
  // gerçek bir Node süreci. Örnek iskelet:
  //
  //   openBidiStream(methodName) {
  //     const session = http2.connect(this.http2Url);
  //     const req = session.request({
  //       ':method': 'POST', ':path': `/IdentityService/${methodName}`,
  //       'x-client-id': this.clientId, 'x-client-secret': this.clientSecret,
  //     });
  //     const decoder = new FrameDecoder();
  //     req.on('data', (chunk) => { for (const f of decoder.push(chunk)) { ... } });
  //     return { send: (msg) => req.write(encodeFrame(msg)), end: () => req.end(), session };
  //   }
  // --------------------------------------------------------------------------
}

module.exports = { IdentityClient, IdentityClientError };
