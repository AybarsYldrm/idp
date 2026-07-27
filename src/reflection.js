'use strict';

const { buildFileDescriptorProto } = require('./descriptor');

// grpc.reflection.v1alpha.ServerReflection için gereken mesaj şemaları.
// Postman / grpcurl gibi istemciler bu servisi sorgulayarak, elle .proto
// import etmeden servisleri ve mesaj tiplerini keşfeder.
const REFLECTION_SCHEMAS = {
  ServerReflectionRequest: [
    { no: 1, name: 'host', type: 'string' },
    { no: 3, name: 'file_by_filename', type: 'string' },
    { no: 4, name: 'file_containing_symbol', type: 'string' },
    { no: 6, name: 'all_extension_numbers_of_type', type: 'string' },
    { no: 7, name: 'list_services', type: 'string' },
  ],
  ServiceResponse: [
    { no: 1, name: 'name', type: 'string' },
  ],
  ListServiceResponse: [
    { no: 1, name: 'service', type: 'message', msgType: 'ServiceResponse', repeated: true },
  ],
  FileDescriptorResponse: [
    { no: 1, name: 'file_descriptor_proto', type: 'bytes', repeated: true },
  ],
  ErrorResponse: [
    { no: 1, name: 'error_code', type: 'int32' },
    { no: 2, name: 'error_message', type: 'string' },
  ],
  ServerReflectionResponse: [
    { no: 1, name: 'valid_host', type: 'string' },
    { no: 4, name: 'file_descriptor_response', type: 'message', msgType: 'FileDescriptorResponse' },
    { no: 6, name: 'list_services_response', type: 'message', msgType: 'ListServiceResponse' },
    { no: 7, name: 'error_response', type: 'message', msgType: 'ErrorResponse' },
  ],
};

/**
 * grpcServer.addService('grpc.reflection.v1alpha.ServerReflection', ...) için
 * kullanılacak method tanımını üretir.
 *
 * @param opts.fileName    sanal dosya adı, örn 'fitfak.proto'
 * @param opts.packageName kullanıcı servislerinin proto package adı
 * @param opts.userSchemas kullanıcı mesaj şemaları (protobuf.js formatı)
 * @param opts.services    [{ name, methods: [{ name, requestType, responseType, clientStreaming, serverStreaming }] }]
 */
function buildReflectionService(opts) {
  const fileDescriptorBytes = buildFileDescriptorProto(opts);
  const fullServiceNames = opts.services.map((s) => `${opts.packageName}.${s.name}`);

  async function handleBidi(call) {
    call.on('message', (req) => {
      if (req.list_services !== undefined && req.list_services !== '') {
        call.write({
          list_services_response: {
            service: fullServiceNames.map((name) => ({ name })),
          },
        });
        return;
      }

      if (req.file_by_filename) {
        if (req.file_by_filename === opts.fileName) {
          call.write({ file_descriptor_response: { file_descriptor_proto: [fileDescriptorBytes] } });
        } else {
          call.write({ error_response: { error_code: 5, error_message: 'dosya bulunamadı' } });
        }
        return;
      }

      if (req.file_containing_symbol) {
        // Tek dosyamız var; herhangi bir sembol için aynı FileDescriptorProto'yu döndür.
        call.write({ file_descriptor_response: { file_descriptor_proto: [fileDescriptorBytes] } });
        return;
      }

      call.write({ error_response: { error_code: 12, error_message: 'desteklenmeyen reflection isteği' } });
    });

    call.on('end', () => call.end());
  }

  return {
    ServerReflectionInfo: {
      kind: 'bidi',
      schemas: REFLECTION_SCHEMAS,
      requestType: 'ServerReflectionRequest',
      responseType: 'ServerReflectionResponse',
      clientStreaming: true,
      serverStreaming: true,
      handler: handleBidi,
    },
  };
}

module.exports = { buildReflectionService, REFLECTION_SCHEMAS };
