'use strict';

const { GrpcClient } = require('../client/grpc-wire-client');

const PKG = process.env.FITFAK_IDP_REMOTE_DB_PACKAGE || 'custom.network';

const SCHEMAS = {
  DatabaseService_OpenDatabaseReq: [{ no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'clientSecret', type: 'string' }],
  DatabaseService_OpenDatabaseRes: [{ no: 1, name: 'message', type: 'string' }],
  DatabaseService_InsertRecordReq: [{ no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' }, { no: 3, name: 'payloadJson', type: 'string' }],
  DatabaseService_InsertRecordRes: [{ no: 1, name: 'recordId', type: 'string' }],
  DatabaseService_UpdateRecordReq: [{ no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' }, { no: 3, name: 'recordId', type: 'string' }, { no: 4, name: 'payloadJson', type: 'string' }],
  DatabaseService_UpdateRecordRes: [{ no: 1, name: 'message', type: 'string' }],
  DatabaseService_DeleteRecordReq: [{ no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' }, { no: 3, name: 'recordId', type: 'string' }],
  DatabaseService_DeleteRecordRes: [{ no: 1, name: 'message', type: 'string' }],
  DatabaseService_FindRecordReq: [{ no: 1, name: 'dbId', type: 'string' }, { no: 2, name: 'collection', type: 'string' }, { no: 3, name: 'field', type: 'string' }, { no: 4, name: 'value', type: 'string' }],
  DatabaseService_FindRecordRes: [{ no: 1, name: 'payloadJson', type: 'string' }],
};

function jsonStringifyWithBigInt(obj) {
  return JSON.stringify(obj, (key, val) => (typeof val === 'bigint' ? val.toString() : val));
}

class RemoteCollection {
  constructor(client, getToken, dbId, name) {
    this.client = client; this.getToken = getToken; this.dbId = dbId; this.name = name;
  }

  async insert(obj) {
    const res = await this._call('InsertRecord', 'InsertRecordReq', 'InsertRecordRes', {
      dbId: this.dbId, collection: this.name, payloadJson: jsonStringifyWithBigInt(obj),
    });
    return res.recordId;
  }

  async get(id) {
    const rows = await this._find('_id', id);
    return rows[0] || null;
  }

  async findOne(field, value) {
    const rows = await this._find(field, value);
    return rows[0] || null;
  }

  async update(id, patch) {
    await this._call('UpdateRecord', 'UpdateRecordReq', 'UpdateRecordRes', {
      dbId: this.dbId, collection: this.name, recordId: String(id), payloadJson: jsonStringifyWithBigInt(patch),
    });
  }

  async delete(id) {
    await this._call('DeleteRecord', 'DeleteRecordReq', 'DeleteRecordRes', {
      dbId: this.dbId, collection: this.name, recordId: String(id),
    });
  }

  async* scan() {
    const rows = await this._find('*', '');
    for (const rec of rows) yield rec;
  }

  async _find(field, value) {
    const res = await this._call('FindRecord', 'FindRecordReq', 'FindRecordRes', {
      dbId: this.dbId, collection: this.name, field, value: String(value),
    });
    const parsed = JSON.parse(res.payloadJson || 'null');
    if (parsed === null) return [];
    return Array.isArray(parsed) ? parsed : [parsed];
  }

  _call(method, reqType, resType, reqObj) {
    return this.client.invoke(
      `/${PKG}.DatabaseService/${method}`, SCHEMAS, `DatabaseService_${reqType}`, `DatabaseService_${resType}`,
      reqObj, this.getToken(),
    );
  }
}

class RemoteDatabase {
  constructor(client, getToken, dbId) {
    this.client = client; this.getToken = getToken; this.dbId = dbId;
    this._collections = new Map();
  }

  collection(name) {
    if (!this._collections.has(name)) {
      this._collections.set(name, new RemoteCollection(this.client, this.getToken, this.dbId, name));
    }
    return this._collections.get(name);
  }
}

async function connectRemoteDatabase({ host, dbId, clientSecret, mtls, jwtToken }) {
  // mTLS İstemci Sertifikaları ve Güvenlik Ayarları
  const clientOpts = mtls 
    ? { cert: mtls.cert, key: mtls.key, ca: mtls.ca, rejectUnauthorized: !!mtls.ca } 
    : { rejectUnauthorized: false };
    
  const client = new GrpcClient(host, clientOpts);
  let currentToken = jwtToken || null;

  try {
    // Veritabanına ilk bağlantı ve açılış isteği (Ping niteliğinde)
    await client.invoke(
      `/${PKG}.DatabaseService/OpenDatabase`, SCHEMAS, 'DatabaseService_OpenDatabaseReq', 'DatabaseService_OpenDatabaseRes',
      { dbId, clientSecret }, currentToken,
    );
  } catch (error) {
    // Çirkin yığın (stack trace) hatası yerine temiz ve profesyonel uyarı
    console.error('\n===============================================================');
    console.error(' KRİTİK HATA: UZAK VERİTABANINA BAĞLANILAMADI');
    console.error('===============================================================');
    console.error(` Hedef Sunucu : ${host}`);
    console.error(` Veritabanı ID: ${dbId}`);
    console.error(` Hata Detayı  : ${error.message.split('(caused by:')[0].trim()}`);
    console.error('---------------------------------------------------------------');
    console.error(' Lütfen veritabanı sunucusunun (fitdb) çalıştığından, 443 portunun');
    console.error(' açık olduğundan ve ağ erişiminde bir engel olmadığından emin olun.\n');
    
    // Uygulamayı başlatmadan (diğer servisleri tetiklemeden) tamamen durdur.
    process.exit(1); 
  }

  const db = new RemoteDatabase(client, () => currentToken, dbId);
  db.getLastRefreshedToken = () => currentToken;
  db.setToken = (t) => { currentToken = t; };
  db.close = () => client.close();
  return db;
}

module.exports = { connectRemoteDatabase, RemoteDatabase, RemoteCollection, SCHEMAS };