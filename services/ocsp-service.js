'use strict';

async function handleOcspRequest({ db, pkiIssuer, ocspRequestDer }) {

  const certs = db.collection('certificates');
  const statusMap = new Map();

  let certCount = 0;
  let revokedCount = 0;

  // Veritabanındaki sertifikaları tarayıp Map'i dolduruyoruz
  for await (const row of certs.scan()) {
    certCount++;
    const isRevoked = row.status === 'revoked';
    
    // Veritabanındaki iptal tarihini al (yoksa şu anı kullan)
    const revokedAtTime = row.revokedAt ? Number(row.revokedAt) : Date.now();
    const statusObj = isRevoked 
      ? { status: 'revoked', revokedAt: new Date(revokedAtTime) } 
      : { status: 'good' };

    // Seri numarasının olası tüm string varyasyonlarını üretiyoruz
    const rawSerial = String(row.serialNumberHex || '').trim();
    const upperSerial = rawSerial.toUpperCase();
    const lowerSerial = rawSerial.toLowerCase();
    
    let noZeroUpper = upperSerial.replace(/^0+/, '');
    if (noZeroUpper === '') noZeroUpper = '0';
    let noZeroLower = lowerSerial.replace(/^0+/, '');
    if (noZeroLower === '') noZeroLower = '0';

    // Kütüphane hangi formatta ararsa arasın bulabilmesi için hepsini haritaya gömüyoruz
    statusMap.set(rawSerial, statusObj);
    statusMap.set(upperSerial, statusObj);
    statusMap.set(lowerSerial, statusObj);
    statusMap.set(noZeroUpper, statusObj);
    statusMap.set(noZeroLower, statusObj);

    if (isRevoked) {
      revokedCount++;
    }
  }

  // Üretim aşaması
  const responseDer = await pkiIssuer.generateOcspResponse({ 
    ocspRequestDer, 
    statusLookup: statusMap 
  });

  return responseDer;
}

module.exports = { handleOcspRequest };