'use strict';

const { encodeMessage } = require('./protobuf');

// ---------------------------------------------------------------------------
// google/protobuf/descriptor.proto şemasının reflection için gereken alt
// kümesi. Bu, .proto dosyası DEĞİL — descriptor.proto'nun kendisi de bir
// protobuf mesajı olduğu için, onu da kendi generic encoder'ımızla
// (protobuf.js) encode edebiliyoruz. Postman "server reflection" isteği
// attığında bu bytes'ları FileDescriptorProto olarak parse eder.
// ---------------------------------------------------------------------------

const DESCRIPTOR_SCHEMAS = {
  FieldDescriptorProto: [
    { no: 1, name: 'name', type: 'string' },
    { no: 3, name: 'number', type: 'int32' },
    { no: 4, name: 'label', type: 'enum' },
    { no: 5, name: 'type', type: 'enum' },
    { no: 6, name: 'type_name', type: 'string' }, // .package.MessageType
  ],
  DescriptorProto: [
    { no: 1, name: 'name', type: 'string' },
    { no: 2, name: 'field', type: 'message', msgType: 'FieldDescriptorProto', repeated: true },
  ],
  MethodDescriptorProto: [
    { no: 1, name: 'name', type: 'string' },
    { no: 2, name: 'input_type', type: 'string' },
    { no: 3, name: 'output_type', type: 'string' },
    { no: 5, name: 'client_streaming', type: 'bool' },
    { no: 6, name: 'server_streaming', type: 'bool' },
  ],
  ServiceDescriptorProto: [
    { no: 1, name: 'name', type: 'string' },
    { no: 2, name: 'method', type: 'message', msgType: 'MethodDescriptorProto', repeated: true },
  ],
  FileDescriptorProto: [
    { no: 1, name: 'name', type: 'string' },
    { no: 2, name: 'package', type: 'string' },
    { no: 4, name: 'message_type', type: 'message', msgType: 'DescriptorProto', repeated: true },
    { no: 6, name: 'service', type: 'message', msgType: 'ServiceDescriptorProto', repeated: true },
    { no: 12, name: 'syntax', type: 'string' },
  ],
};

// FieldDescriptorProto.Type enum değerleri (descriptor.proto ile birebir)
const FIELD_TYPE_ENUM = {
  double: 1, float: 2, int64: 3, uint64: 4, int32: 5, fixed64: 6, fixed32: 7,
  bool: 8, string: 9, message: 11, bytes: 12, uint32: 13, sfixed32: 15,
  sfixed64: 16, sint32: 17, sint64: 18,
};
const LABEL_OPTIONAL = 1;
const LABEL_REPEATED = 3;

/**
 * Kullanıcı şemasındaki (protobuf.js formatı) bir mesaj tipini
 * DescriptorProto objesine çevirir.
 */
function buildDescriptorProto(userSchemas, packageName, typeName) {
  const fields = userSchemas[typeName];
  return {
    name: typeName,
    field: fields.map((f) => ({
      name: f.name,
      number: f.no,
      label: f.repeated ? LABEL_REPEATED : LABEL_OPTIONAL,
      type: FIELD_TYPE_ENUM[f.type],
      type_name: f.type === 'message' ? `.${packageName}.${f.msgType}` : '',
    })),
  };
}

/**
 * GrpcServer üzerinde tanımlı servis(ler) ve mesaj şemalarından, encode
 * edilmiş bir FileDescriptorProto (Buffer) üretir. Bu buffer, reflection
 * cevabında file_descriptor_proto alanına doğrudan yazılır.
 */
function buildFileDescriptorProto({ fileName, packageName, userSchemas, services }) {
  const messageTypeNames = Object.keys(userSchemas);

  const fileObj = {
    name: fileName,
    package: packageName,
    syntax: 'proto3',
    message_type: messageTypeNames.map((t) => buildDescriptorProto(userSchemas, packageName, t)),
    service: services.map((svc) => ({
      name: svc.name,
      method: svc.methods.map((m) => ({
        name: m.name,
        input_type: `.${packageName}.${m.requestType}`,
        output_type: `.${packageName}.${m.responseType}`,
        client_streaming: !!m.clientStreaming,
        server_streaming: !!m.serverStreaming,
      })),
    })),
  };

  return encodeMessage(DESCRIPTOR_SCHEMAS, 'FileDescriptorProto', fileObj);
}

module.exports = {
  DESCRIPTOR_SCHEMAS,
  buildFileDescriptorProto,
};
