'use strict'; 

const http2 = require('node:http2'); 
const readline = require('node:readline'); 
const { encodeMessage, decodeMessage } = require('./protobuf'); 
const { mk, hexDump, setLevel } = require('./logger');

// ============================================================================ 
// LOG SEVIYESI
// ============================================================================ 
process.env.DTLS_LOG_LEVEL = 'DEBUG'; 
setLevel(process.env.DTLS_LOG_LEVEL);

const sysLog = mk('system');
const grpcLog = mk('grpc');
const authLog = mk('auth');
const liveLog = mk('stream');

// ============================================================================ 
// HEDEF KASA VE KULLANICI BILGILERI
// ============================================================================ 
const ADMIN_EMAIL = 'aybarsyildirim.game@gmail.com'; 
const KASA_ID = '355024942087016448'; 
const SECRET = 'vXfLbDApVcznu90cZIy3+1vlgCfBlnIbGDQkNhgLXmE='; 
const KOLEKSIYON = 'hastam'; 

// ============================================================================ 
// BASIT LOGGER
// ============================================================================ 
const Logger = {     
    step: (msg) => console.log(`\n[ASAMA] ${msg}`),     
    info: (msg) => console.log(`[BILGI] ${msg}`),     
    success: (msg) => console.log(`[BASARILI] ${msg}`),     
    error: (msg) => console.error(`[HATA] ${msg}`),     
    live: (msg) => console.log(`[CANLI AKIS] ${msg}`),
    event: (msg) => console.log(`[SISTEM BILDIRIMI] ${msg}`)
};

// ============================================================================ 
// 1. SEMALAR
// ============================================================================ 
const mySchemas = {   
    AuthService_RequestOTPReq: [ { no: 1, name: 'email', type: 'string' } ],   
    AuthService_RequestOTPRes: [ { no: 1, name: 'message', type: 'string' } ],   
    AuthService_VerifyOTPReq: [ { no: 1, name: 'email', type: 'string' }, { no: 2, name: 'code', type: 'string' } ],   
    AuthService_VerifyOTPRes: [ { no: 1, name: 'token', type: 'string' } ],   
    
    DatabaseService_OpenDatabaseReq: [ { no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'clientSecret', type: 'string' } ],
    DatabaseService_OpenDatabaseRes: [ { no: 1, name: 'message', type: 'string' } ],

    RealTimeService_WatchSystemEventsReq: [],
    RealTimeService_WatchSystemEventsRes: [ { no: 1, name: 'payloadJson', type: 'string' } ],

    DatabaseService_WatchCollectionReq: [ { no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' } ],
    DatabaseService_WatchCollectionRes: [ { no: 1, name: 'payloadJson', type: 'string' } ]
};

function frameMessage(payload) {   
    const frame = Buffer.alloc(5 + payload.length);   
    frame.writeUInt8(0, 0);    
    frame.writeUInt32BE(payload.length, 1);   
    payload.copy(frame, 5);   
    return frame;
}

function askQuestion(query) {     
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });     
    return new Promise(resolve => rl.question(query, ans => {         
        rl.close();         
        resolve(ans);     
    }));
}

// ============================================================================ 
// 2. SAF (PURE) gRPC ISTEMCISI
// ============================================================================ 
class PureGrpcClient {
    constructor(host) {
        this.session = http2.connect(host, { rejectUnauthorized: false });
        grpcLog.debug(`HTTP/2 Oturumu Baslatildi -> ${host}`);

        this.session.on('error', (err) => grpcLog.error(`HTTP/2 Oturum Hatasi: ${err.message}`));
        this.session.on('close', () => grpcLog.warn('HTTP/2 Oturumu Kapandi.'));
    }

    invoke(serviceMethod, reqType, resType, reqObj, jwtToken = null) {
        return new Promise((resolve, reject) => {
            grpcLog.trace(`[INVOKE] Istek Hazirlaniyor: ${serviceMethod}`);

            const headers = {       
                ':path': serviceMethod,       
                ':method': 'POST',       
                'content-type': 'application/grpc', 
                'te': 'trailers',                   
                'user-agent': 'fitdb-cli/2.0',     
            };          
            if (jwtToken) {
                headers['authorization'] = `Bearer ${jwtToken}`;     
                grpcLog.trace(`[INVOKE] JWT Token Eklendi.`);
            }
            
            const payloadBytes = encodeMessage(mySchemas, reqType, reqObj);  
            grpcLog.debug(`[INVOKE] -> ${serviceMethod} | Payload: ${payloadBytes.length} bytes`);
               
            const req = this.session.request(headers);     
            
            let responseData = Buffer.alloc(0);     
            let grpcStatus = '0';
            let grpcMessage = '';

            req.write(frameMessage(payloadBytes));     
            req.end();     
            
            req.on('data', (chunk) => { 
                responseData = Buffer.concat([responseData, chunk]); 
                grpcLog.trace(`[INVOKE] Chunk Alindi: ${chunk.length} bytes. Toplam Buffer: ${responseData.length} bytes`);
            });     
            
            req.on('trailers', (trailers) => {
                grpcLog.trace(`[INVOKE] Trailers Alindi: ${JSON.stringify(trailers)}`);
                if (trailers['grpc-status']) grpcStatus = trailers['grpc-status'];
                if (trailers['grpc-message']) grpcMessage = decodeURIComponent(trailers['grpc-message']);
            });

            req.on('end', () => {       
                if (grpcStatus !== '0') {
                    grpcLog.error(`[INVOKE] Sunucu gRPC Hatasi firlatti! Kod: ${grpcStatus} | Mesaj: ${grpcMessage}`);
                    return reject(new Error(`[Sunucu Hatasi: ${grpcStatus}] ${grpcMessage}`));
                }
                
                let parsedResult = null;       
                let pos = 0;       
                try {           
                    while (pos < responseData.length) {               
                        const flag = responseData.readUInt8(pos);               
                        const len = responseData.readUInt32BE(pos + 1);               
                        const framePayload = responseData.slice(pos + 5, pos + 5 + len);                              
                        
                        if (flag === 0x00) { 
                            parsedResult = decodeMessage(mySchemas, resType, framePayload); 
                            grpcLog.debug(`[INVOKE] Frame Cozuldu. Islenen Bayt: ${len}`);
                        }                
                        pos += 5 + len;           
                    }           
                    if (!parsedResult) return reject(new Error("Sunucudan bos yanit dondu!"));                      
                    
                    grpcLog.info(`[INVOKE] Basarili: ${serviceMethod}`);
                    resolve(parsedResult);       
                } catch (e) { 
                    grpcLog.error(`[INVOKE] Decode Hatasi: ${e.message}`);
                    grpcLog.hex('Bozuk Frame Dump', responseData); 
                    reject(new Error(`Decode Hatasi: ${e.message}`)); 
                }     
            });

            req.on('error', (err) => {
                grpcLog.error(`[INVOKE] Istek Hatasi: ${err.message}`);
                reject(err);
            });
        });
    }

    bidiStream(streamName, serviceMethod, reqType, resType, reqObj, jwtToken, onPayload) {
        grpcLog.info(`[STREAM] Bidi-Stream Baslatiliyor: ${streamName} -> ${serviceMethod}`);

        const headers = {       
            ':path': serviceMethod,       
            ':method': 'POST',       
            'content-type': 'application/grpc',     
            'te': 'trailers',                   
            'authorization': `Bearer ${jwtToken}`,
            'user-agent': 'fitdb-cli/2.0'
        };

        const payloadBytes = encodeMessage(mySchemas, reqType, reqObj);     
        const req = this.session.request(headers);
        
        req.write(frameMessage(payloadBytes));
        req.end(); 
        grpcLog.debug(`[STREAM] Ilk veri gonderildi. Kanal dinlenmeye alindi. (${streamName})`);

        let buffer = Buffer.alloc(0);
        let grpcStatus = '0';
        let grpcMessage = '';

        req.on('data', (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);
            grpcLog.trace(`[STREAM] [${streamName}] Chunk: ${chunk.length} bytes | Buffer: ${buffer.length} bytes`);
            
            while (buffer.length >= 5) {
                const flag = buffer.readUInt8(0);
                const len = buffer.readUInt32BE(1);
                
                if (buffer.length < 5 + len) {
                    grpcLog.trace(`[STREAM] [${streamName}] Eksik frame bekleniyor...`);
                    break;
                }

                const framePayload = buffer.slice(5, 5 + len);
                buffer = buffer.slice(5 + len); 

                if (flag === 0x00) {
                    try {
                        const msg = decodeMessage(mySchemas, resType, framePayload);
                        const payload = JSON.parse(msg.payloadJson);
                        
                        if (payload.type === 'PING') {
                            grpcLog.trace(`[STREAM] [${streamName}] PING alindi.`);
                            continue;
                        }
                        
                        liveLog.debug(`[STREAM] [${streamName}] Yeni Olay Cozuldu: ${payload.type}`);
                        onPayload(payload);
                    } catch (e) {
                        grpcLog.error(`[STREAM] [${streamName}] Decode Hatasi: ${e.message}`);
                        grpcLog.hex('Sorunlu Frame', framePayload);
                    }
                }
            }
        });

        req.on('trailers', (trailers) => {
            grpcLog.trace(`[STREAM] [${streamName}] Trailers: ${JSON.stringify(trailers)}`);
            if (trailers['grpc-status']) grpcStatus = trailers['grpc-status'];
            if (trailers['grpc-message']) grpcMessage = decodeURIComponent(trailers['grpc-message']);
        });

        req.on('error', (err) => grpcLog.error(`[STREAM] [${streamName}] Iletisim Hatasi: ${err.message}`));
        
        req.on('end', () => {
            if (grpcStatus !== '0') {
                grpcLog.error(`[STREAM] [${streamName}] Sunucu Hatasi firlatti! Kod: ${grpcStatus} | Mesaj: ${grpcMessage}`);
            } else {
                grpcLog.warn(`[STREAM] [${streamName}] Akis Sonlandi. (Internet/Ag baglantisi kesilmis olabilir)`);
            }
            sysLog.info(`[STREAM] [${streamName}] 5 Saniye Sonra Yeniden Baglaniliyor...`);
            setTimeout(() => this.bidiStream(streamName, serviceMethod, reqType, resType, reqObj, jwtToken, onPayload), 5000);
        });
    }

    close() {
        grpcLog.warn('HTTP/2 Oturumu Kapatiliyor...');
        this.session.close();
    }
}

// ============================================================================ 
// 3. ANA SENARYO (CLI)
// ============================================================================ 
async function runClient() {   
    const grpcClient = new PureGrpcClient('https://127.0.0.1:443');

    try {       
        console.clear();
        console.log("=========================================================");
        console.log("             FITDB KLINIK IZLEME KONSOLU                 ");
        console.log("=========================================================");

        sysLog.info(`[ASAMA] [${ADMIN_EMAIL}] Adresine OTP Kodu Isteniyor...`);              
        const reqRes = await grpcClient.invoke(
            '/custom.network.AuthService/RequestOTP', 
            'AuthService_RequestOTPReq', 
            'AuthService_RequestOTPRes', 
            { email: ADMIN_EMAIL }
        );       
        authLog.info(`[BILGI] ${reqRes.message}`);       
        
        const otpCode = await askQuestion('\nLutfen 6 Haneli Dogrulama Kodunu Girin: ');       
        
        sysLog.info('[ASAMA] OTP Dogrulaniyor ve JWT Aliniyor...');              
        const verifyRes = await grpcClient.invoke(
            '/custom.network.AuthService/VerifyOTP', 
            'AuthService_VerifyOTPReq', 
            'AuthService_VerifyOTPRes', 
            { email: ADMIN_EMAIL, code: otpCode.trim() }
        );       
        const jwtToken = verifyRes.token;       
        authLog.info(`[BASARILI] Giris Basarili! JWT Alindi.`);       
        
        sysLog.info(`[ASAMA] [${KASA_ID}] Numarali Kasanin Kilidi Aciliyor...`);              
        const openRes = await grpcClient.invoke(
            '/custom.network.DatabaseService/OpenDatabase', 
            'DatabaseService_OpenDatabaseReq', 
            'DatabaseService_OpenDatabaseRes', 
            { dbId: KASA_ID, clientSecret: SECRET }, 
            jwtToken
        );       
        sysLog.info(`[BASARILI] ${openRes.message}`);       
        
        sysLog.info(`[ASAMA] Global Sistem Olaylari (Davetler/Iptaller) Dinleniyor...`);
        grpcClient.bidiStream(
            'SystemEvents',
            '/custom.network.RealTimeService/WatchSystemEvents',
            'RealTimeService_WatchSystemEventsReq',
            'RealTimeService_WatchSystemEventsRes',
            {},
            jwtToken,
            (payload) => {
                if (payload.type === 'VAULT_INVITE') {
                    console.log('\n---------------------------------------------------------');
                    liveLog.info(`YENI KASA DAVETI!`);
                    console.log(`  - Gonderen : Dr. ${payload.ownerName}`);
                    console.log(`  - Kasa Adi : ${payload.dbName || 'Isimsiz'}`);
                    console.log(`  - Kasa ID  : ${payload.dbId}`);
                    console.log('---------------------------------------------------------\n');
                } else if (payload.type === 'VAULT_REVOKE') {
                    liveLog.warn(`ERISIM IPTALI! [${payload.dbId}] numarali kasaya erisiminiz sonlandirildi.`);
                }
            }
        );

        sysLog.info(`[ASAMA] [${KOLEKSIYON}] Koleksiyonu Icin Canli Akis Baslatiliyor...`);
        grpcClient.bidiStream(
            'AnamnezAkisi',
            '/custom.network.DatabaseService/WatchCollection',
            'DatabaseService_WatchCollectionReq',
            'DatabaseService_WatchCollectionRes',
            { dbId: KASA_ID, collection: KOLEKSIYON },
            jwtToken,
            (payload) => {
                if (payload.type === 'INIT') {
                    liveLog.info(`Arsivden Mevcut Kayitlar Getirildi (${payload.data.length} adet)`);
                } else if (payload.type === 'CHANGE') {
                    console.log(`\n=========================================================`);
                    liveLog.info(`YENI OLAY YAKALANDI: [${payload.action}]`);
                    
                    const r = payload.data;
                    if (payload.action === 'DELETE') {
                        console.log(`  - Silinen Kayit ID: ${r._id}`);
                    } else {
                        console.log(`  - Hasta   : ${r.isim || '-'} (TC: ${r.tc || '-'})`);
                        console.log(`  - Servis  : ${r.seviye || '-'} | Sorumlu: ${r.doktor || '-'}`);
                        console.log(`  - Anamnez : ${r.anamnez || '-'}`);
                        if (r.istem) console.log(`  - Istem   : ${r.istem}`);
                    }
                    console.log(`=========================================================\n`);
                }
            }
        );

        console.log(`\n---------------------------------------------------------`);
        sysLog.info(`Sistem aktif. Herhangi bir olay yasandiginda buraya dusecek...`);
        console.log(`---------------------------------------------------------\n`);

    } catch (error) {       
        sysLog.error(`Kritik Hata: ${error.message}`); 
        grpcClient.close();
        process.exit(1);
    }
}

runClient();