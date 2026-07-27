'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { GrpcServer, GRPC_STATUS } = require('./src/grpc-server');
const { buildReflectionService } = require('./src/reflection');
const { mk } = require('./src/utils/logger'); 

const sysLog = mk('system');
const dbLog = mk('db');
const grpcLog = mk('grpc');

const { 
  DatabaseManager, ClientSecretKeyProvider, SnowflakeGenerator, DB_PERMISSIONS 
} = require('@fitfak/database'); 
const schema = require('./db/schema');

const snowflake = new SnowflakeGenerator({ workerId: 1 });
const dbManager = new DatabaseManager({ baseDir: './fitdb-data', snowflake });

class GrpcDatabaseServer {
  constructor(packageName) {
    this.packageName = packageName; 
    this.server = new GrpcServer();
    this.schemaRegistry = {}; 
    this.reflectionData = []; 
    this._initializeMiddleware();
  }

  registerSharedSchema(schemaName, fields) { 
    this.schemaRegistry[schemaName] = fields; 
  }

  _initializeMiddleware() {
    this.server.use(async (call) => {
      const reqPath = call.headers[':path'];
      grpcLog.info(`[GELEN gRPC İSTEĞİ] ${call.headers[':method']} ${reqPath}`);
      return; // mTLS tüneli üzerinden gelen istekler kabul ediliyor
    });
  }

  registerController(serviceName, endpoints) {
    const compiledMethods = {}, reflectMethods = [];
    for (const [methodName, config] of Object.entries(endpoints)) {
      const fullPath = `/${this.packageName}.${serviceName}/${methodName}`;
      const reqSchemaName = Array.isArray(config.request) ? `${serviceName}_${methodName}Req` : config.request;
      const resSchemaName = Array.isArray(config.response) ? `${serviceName}_${methodName}Res` : config.response;
      
      if (Array.isArray(config.request)) this.schemaRegistry[reqSchemaName] = config.request;
      if (Array.isArray(config.response)) this.schemaRegistry[resSchemaName] = config.response;
      
      compiledMethods[methodName] = { 
        kind: config.kind || 'unary', 
        schemas: this.schemaRegistry, 
        requestType: reqSchemaName, 
        responseType: resSchemaName, 
        handler: async (req, call) => {
          try {
            return await config.handler(req, call);
          } catch (handlerErr) {
            dbLog.error(`[HANDLER HATASI] ${methodName}: ${handlerErr.message}`);
            throw handlerErr;
          }
        }
      };
      
      reflectMethods.push({ 
        name: methodName, 
        requestType: reqSchemaName, 
        responseType: resSchemaName, 
        serverStreaming: false, 
        clientStreaming: false 
      });
    }
    this.server.addService(`${this.packageName}.${serviceName}`, compiledMethods); 
    this.reflectionData.push({ name: serviceName, methods: reflectMethods });
  }

  startServer(port, tlsOptions = null) {
    const reflection = buildReflectionService({ 
      fileName: 'api.proto', 
      packageName: this.packageName, 
      userSchemas: this.schemaRegistry, 
      services: this.reflectionData 
    });
    this.server.addService('grpc.reflection.v1alpha.ServerReflection', reflection);
    this.server.listen(port, { host: '0.0.0.0', tls: tlsOptions });
    sysLog.info(`[VERİTABANI SUNUCUSU] mTLS gRPC Motoru Ayakta (Port: ${port})`);
  }
}

const app = new GrpcDatabaseServer('custom.network');

// ============================================================================
// YARDIMCI: Deterministik Anahtar Türetici
// ============================================================================
function deriveDbKeyBuffer(secretRaw) {
  try {
    const decoded = Buffer.from(secretRaw, 'base64');
    if (decoded.length === 32) return decoded;
  } catch { /* base64 değil */ }
  return Buffer.from(String(secretRaw).padEnd(32, '0').slice(0, 32));
}

// ============================================================================
// OTOMATİK VERİTABANI VE KASA (VAULT) OLUŞTURUCU
// ============================================================================
const IDP_DB_ID_FILE = path.join('./fitdb-data', 'idp_db_id.txt');
const IDP_SECRET_FILE = path.join('./fitdb-data', 'idp_secret.txt');

async function bootstrapServerDatabases() {
  if (!fs.existsSync('./fitdb-data')) fs.mkdirSync('./fitdb-data', { recursive: true });

  let dbId, clientSecret;

  if (fs.existsSync(IDP_DB_ID_FILE) && fs.existsSync(IDP_SECRET_FILE)) {
    dbId = fs.readFileSync(IDP_DB_ID_FILE, 'utf8').trim();
    clientSecret = fs.readFileSync(IDP_SECRET_FILE, 'utf8').trim();
    sysLog.info(`[AUTO-DB] Mevcut IdP Veritabanı yüklendi. DB ID: ${dbId}`);
  } else {
    sysLog.info(`[AUTO-DB] İlk kez çalıştırılıyor, IdP için yeni veritabanı (kasa) oluşturuluyor...`);
    clientSecret = crypto.randomBytes(32).toString('base64');
    const keyProvider = new ClientSecretKeyProvider(deriveDbKeyBuffer(clientSecret));

    const created = await dbManager.createDatabase({ ownerId: 'fitfak-idp-service', name: 'idp_main', keyProvider });
    dbId = created.dbId;

    // db/schema.js içindeki TÜM şemaları (users, sessions, certificates vb.) koleksiyon olarak tanımla
    for (const [name, def] of Object.entries(schema)) {
      await created.db.defineCollectionAsync(name, def);
    }

    fs.writeFileSync(IDP_DB_ID_FILE, dbId);
    fs.writeFileSync(IDP_SECRET_FILE, clientSecret);
    sysLog.info(`[AUTO-DB] Yeni kasa başarıyla oluşturuldu ve şemalar tanımlandı!`);
  }

  // Sunucu başlarken kasayı bellekte açık duruma getir
  const keyProvider = new ClientSecretKeyProvider(deriveDbKeyBuffer(clientSecret));
  await dbManager.openDatabase({ 
    ownerId: 'fitfak-idp-service', 
    dbId, 
    requesterId: 'fitfak-idp-service', 
    keyProvider, 
    requiredPermission: DB_PERMISSIONS.READ 
  });

  // 🚀 MIGRATION: Şemaları mevcut veritabanına zorla senkronize et
  const openedDb = dbManager.getOpenDatabase(dbId);
  
  if (openedDb) {
    sysLog.info('[MIGRATION] Mevcut veritabanı şemaları kod ile senkronize ediliyor...');
    for (const [name, def] of Object.entries(schema)) {
      try {
        const col = openedDb.collection(name);
        
        // RAM'deki şemayı doğrudan kodumuzdaki güncel şema ile eziyoruz
        if (col && col.fields) {
          col.fields = def.fields;
        }
      } catch (e) {
        // Eğer koleksiyon diskte hiç yoksa (yeni bir tablo eklendiyse) oluşturur
        await openedDb.defineCollectionAsync(name, def);
      }
    }
    sysLog.info('[MIGRATION] Şema senkronizasyonu tamamlandı!');
  } else {
    sysLog.error('[MIGRATION] Veritabanı objesi bulunamadığı için şema senkronizasyonu atlandı!');
  }

  console.log('\n======================================================================');
  console.log('✨ FITFAK gRPC VERİTABANI BİLGİLERİ (oauth-server.js içine yazılacak):');
  console.log('----------------------------------------------------------------------');
  console.log(`process.env.FITFAK_IDP_DB_ID = "${dbId}";`);
  console.log(`process.env.FITFAK_IDP_DB_SECRET = "${clientSecret}";`);
  console.log('======================================================================\n');
}

// ============================================================================
// DATABASE SERVICE (gRPC Uç Noktaları)
// ============================================================================
app.registerController('DatabaseService', {
  OpenDatabase: {
    request: [ { no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'clientSecret', type: 'string' } ], 
    response: [{ no: 1, name: 'message', type: 'string' }],
    handler: async (req) => {
      dbLog.info(`[OpenDatabase] Kasa Açılıyor. DB ID: ${req.dbId}`);
      try {
        const keyProvider = new ClientSecretKeyProvider(deriveDbKeyBuffer(req.clientSecret));
        await dbManager.openDatabase({ ownerId: 'fitfak-idp-service', dbId: req.dbId, requesterId: 'fitfak-idp-service', keyProvider });
        dbLog.info(`[OpenDatabase BAŞARILI] Kasa erişime açıldı: ${req.dbId}`);
        return { message: 'Veritabanı kilidi başarıyla açıldı.' };
      } catch (e) {
        dbLog.error(`[OpenDatabase HATA] Kasa açılamadı: ${e.message}`);
        const err = new Error(`Kasa açılamadı: ${e.message}`); 
        err.code = GRPC_STATUS.UNAUTHENTICATED; 
        throw err;
      }
    }
  },
  InsertRecord: {
    request: [ { no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' }, { no: 3, name: 'payloadJson', type: 'string' } ], 
    response: [{ no: 1, name: 'recordId', type: 'string' }],
    handler: async (req) => {
      const db = dbManager.getOpenDatabase(req.dbId); 
      if (!db) throw new Error(`Veritabanı kapalı: ${req.dbId}`);
      
      let col;
      try {
        col = db.collection(req.collection);
      } catch {
        const colDef = schema[req.collection] || { fields: [] };
        col = await db.defineCollectionAsync(req.collection, colDef);
      }

      const recordData = JSON.parse(req.payloadJson);
      const recId = String(await col.insert(recordData));
      return { recordId: recId };
    }
  },
  UpdateRecord: {
    request: [ { no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' }, { no: 3, name: 'recordId', type: 'string' }, { no: 4, name: 'payloadJson', type: 'string' } ], 
    response: [{ no: 1, name: 'message', type: 'string' }],
    handler: async (req) => {
      const db = dbManager.getOpenDatabase(req.dbId); 
      if (!db) throw new Error('Veritabanı kapalı.');
      const col = db.collection(req.collection);
      await col.update(req.recordId, JSON.parse(req.payloadJson));
      return { message: 'Kayıt güncellendi.' };
    }
  },
  DeleteRecord: {
    request: [ { no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' }, { no: 3, name: 'recordId', type: 'string' } ], 
    response: [{ no: 1, name: 'message', type: 'string' }],
    handler: async (req) => {
      const db = dbManager.getOpenDatabase(req.dbId); 
      if (!db) throw new Error('Veritabanı kapalı.');
      await db.collection(req.collection).delete(req.recordId);
      return { message: 'Kayıt silindi.' };
    }
  },
  FindRecord: {
    request: [ { no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' }, { no: 3, name: 'field', type: 'string' }, { no: 4, name: 'value', type: 'string' } ], 
    response: [{ no: 1, name: 'payloadJson', type: 'string' }],
    handler: async (req) => {
      const db = dbManager.getOpenDatabase(req.dbId); 
      if (!db) throw new Error(`Veritabanı kapalı: ${req.dbId}`);
      
      let col;
      try {
        col = db.collection(req.collection);
      } catch {
        const colDef = schema[req.collection] || { fields: [] };
        col = await db.defineCollectionAsync(req.collection, colDef);
      }

      // 1. Taramalı (Scan) Arama
      if (req.field === '*') {
        const results = [];
        const searchTerm = String(req.value).toLocaleLowerCase('tr-TR');
        for await (const rec of col.scan()) {
          let match = false;
          for (const key in rec) {
            if (String(rec[key]).toLocaleLowerCase('tr-TR').includes(searchTerm)) { match = true; break; }
          }
          if (match) results.push(rec);
        }
        return { payloadJson: JSON.stringify(results, (k, v) => typeof v === 'bigint' ? v.toString() : v) };
      }
      
      // 2. Primary Key (_id) Araması
      if (req.field === '_id' || req.field === 'id') {
        const found = await col.get(req.value);
        return { payloadJson: JSON.stringify(found || null, (k, v) => typeof v === 'bigint' ? v.toString() : v) };
      }
      
      // 3. Normal (Index) / Blind Index Araması
      const found = await col.findOne(req.field, req.value);
      return { payloadJson: JSON.stringify(found || null, (k, v) => typeof v === 'bigint' ? v.toString() : v) };
    }
  }
});

const SERVER_PORT = 443;
let tlsConfiguration = null;

try {
  if (fs.existsSync('./certs/server.key') && fs.existsSync('./certs/server.crt') && fs.existsSync('./certs/ca.crt')) {
    tlsConfiguration = {
      key: fs.readFileSync('./certs/server.key'),
      cert: fs.readFileSync('./certs/server.crt'),
      ca: fs.readFileSync('./certs/ca.crt'),
      requestCert: true,
      rejectUnauthorized: true
    };
    sysLog.info('[mTLS HAZIR] Sunucu sertifikaları yüklendi.');
  }
} catch (e) {
  sysLog.error(`[TLS HATA] ${e.message}`);
}

// Sunucuyu başlat ve konsola veritabanı bilgilerini ver
bootstrapServerDatabases().then(() => {
  app.startServer(SERVER_PORT, tlsConfiguration);
}).catch(e => {
  sysLog.error('Başlatma hatası:', e.message);
  console.error(e.stack);
});