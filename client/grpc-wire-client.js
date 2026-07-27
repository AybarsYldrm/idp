'use strict';

// ESKİMİŞ (superseded) -- yeni kod bunu KULLANMAMALI.
//
// Bu, veritabanına bağlanmak için elle yazılmış bir gRPC istemcisiydi.
// Yerini @fitfak/database'in kendi istemcisi aldı; bağlantı artık
// core/db-bootstrap.js üzerinden kuruluyor ve bootstrap TLS -> enrolment ->
// mTLS akışının tamamını, sertifika yenilemeyi ve yeniden başlatmada
// sertifikadan devam etmeyi kapsıyor.
//
// Burada yalnızca test/mtls-demo.js'in mTLS el sıkışma davranışını
// göstermek için duruyor. Veritabanı erişimi için kullanılmıyor.


const http2 = require('node:http2');
const { encodeMessage, decodeMessage } = require('./wire/protobuf'); 

function frameMessage(payload) {
  const frame = Buffer.alloc(5 + payload.length);
  frame.writeUInt8(0, 0); 
  frame.writeUInt32BE(payload.length, 1);
  payload.copy(frame, 5);
  return frame;
}

class GrpcWireError extends Error {
  constructor(message, grpcStatus) {
    super(message);
    this.name = 'GrpcWireError';
    this.grpcStatus = grpcStatus;
  }
}

class GrpcClient {
  constructor(host, options = {}) {
    const connectOpts = { 
      rejectUnauthorized: options.rejectUnauthorized ?? true 
    };
    
    if (options.cert) connectOpts.cert = options.cert;
    if (options.key) connectOpts.key = options.key;
    if (options.ca) connectOpts.ca = options.ca;

    // HTTP/2 bağlantısını güvenli şekilde başlatıyoruz
    this.client = http2.connect(host, connectOpts);
    
    this.client.on('error', (err) => {
      console.error('[GrpcWireClient] HTTP/2 Oturum Hatası:', err.message);
    });
  }

  invoke(path, schemas, reqType, resType, reqObj, token = null) {
    return new Promise((resolve, reject) => {
      // Bağlantı nesnesinin varlığını ve kapalı olup olmadığını kontrol et
      if (!this.client || this.client.destroyed || this.client.closed) {
        return reject(new Error('gRPC istemci oturumu kapalı veya kurulamadı. mTLS sertifika yollarını kontrol edin.'));
      }

      const headers = {
        ':path': path,
        ':method': 'POST',
        'content-type': 'application/grpc+proto',
        'user-agent': 'fitfak-idp-client/1.0',
      };
      
      if (token) headers['authorization'] = `Bearer ${token}`;

      let req;
      try {
        req = this.client.request(headers);
      } catch (err) {
        return reject(new Error(`HTTP/2 istek başlatılamadı: ${err.message}`));
      }

      let responseData = Buffer.alloc(0);
      let grpcStatus = '0';
      let grpcMessage = '';

      const payloadBytes = encodeMessage(schemas, reqType, reqObj);
      req.write(frameMessage(payloadBytes));
      req.end();

      req.on('response', (headers) => {
        if (headers['grpc-status']) grpcStatus = headers['grpc-status'];
        if (headers['grpc-message']) grpcMessage = decodeURIComponent(headers['grpc-message']);
      });

      req.on('data', (chunk) => { responseData = Buffer.concat([responseData, chunk]); });

      req.on('trailers', (trailers) => {
        if (trailers['grpc-status']) grpcStatus = trailers['grpc-status'];
        if (trailers['grpc-message']) grpcMessage = decodeURIComponent(trailers['grpc-message']);
      });

      req.on('end', () => {
        if (grpcStatus !== '0') return reject(new GrpcWireError(`gRPC Hatası [${grpcStatus}]: ${grpcMessage}`, grpcStatus));
        
        if (responseData.length >= 5) {
          const len = responseData.readUInt32BE(1);
          const msgBuf = responseData.slice(5, 5 + len);
          try { 
            resolve(decodeMessage(schemas, resType, msgBuf)); 
          } catch (e) { 
            reject(new Error(`Decode Hatası: ${e.message}`)); 
          }
        } else {
          resolve({});
        }
      });

      req.on('error', (err) => {
        reject(new Error(`Stream İstek Hatası: ${err.message}`));
      });
    });
  }

  close() {
    if (this.client) this.client.close();
  }
}

module.exports = { GrpcClient, GrpcWireError };