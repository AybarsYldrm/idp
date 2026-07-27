const tls = require('tls');
const crypto = require('crypto');
const { mk } = require('./utils/logger'); // Logger entegrasyonu
const log = mk('SMTP'); // Bileşen adı: SMTP

class SMTPService {
  constructor(options) {
    this.host = options.host || 'smtp.gmail.com';
    this.port = options.port || 465;
    this.username = options.username;
    this.password = options.password;
  }

  send(options) {
    return new Promise((resolve, reject) => {
      const from = options.from;
      const to = options.to;
      const subject = options.subject || '';
      const message = options.message || '';

      const client = tls.connect(this.port, this.host, {
        rejectUnauthorized: false
      }, () => {
        log.info(`Sunucuya Baglanildi: ${this.host}:${this.port}`);
      });

      let step = 0;
      let buffer = '';

      client.on('data', (data) => {
        buffer += data.toString();

        if (buffer.match(/^\d{3}-/m) && !buffer.match(/^\d{3} /m)) {
           return; 
        }

        const response = buffer;
        buffer = ''; 

        // Gelen yanıtları debug seviyesinde logla
        log.debug('Sunucu Yaniti:', response.trim());
        const code = response.substring(0, 3);

        if (code === '535') {
           client.end();
           return reject(new Error('Kullanici adi veya sifre yanlis! (535)'));
        }
        if (code.startsWith('5') || code.startsWith('4')) {
           client.end();
           return reject(new Error(`SMTP Hatasi: ${response.trim()}`));
        }

        try {
            if (step === 0 && code === '220') {
              // YAMA 1: Kimlik Hırsızlığı Engellendi. Sunucuya kendi adıyla EHLO çekmiyoruz!
              client.write(`EHLO localhost\r\n`);
              step++;
            } else if (step === 1 && code === '250') {
              client.write(`AUTH LOGIN\r\n`);
              step++;
            } else if (step === 2 && code === '334') {
              client.write(`${Buffer.from(this.username, 'utf-8').toString('base64')}\r\n`);
              step++;
            } else if (step === 3 && code === '334') {
              client.write(`${Buffer.from(this.password, 'utf-8').toString('base64')}\r\n`);
              step++;
            } else if (step === 4 && code === '235') {
              log.info('SMTP Girisi Basarili!');
              client.write(`MAIL FROM: <${from}>\r\n`);
              step++;
            } else if (step === 5 && code === '250') {
              client.write(`RCPT TO: <${to}>\r\n`);
              step++;
            } else if (step === 6 && code === '250') {
              client.write(`DATA\r\n`);
              step++;
            } else if (step === 7 && code === '354') {
              // YAMA 2: Spam/Milter filtrelerinden geçmesi için zorunlu başlıklar (Headers) eklendi
              const dateStr = new Date().toUTCString();
              const messageId = `<${crypto.randomUUID()}@fitfak.net>`;
              
              const emailContent = [
                  `Date: ${dateStr}`,
                  `Message-ID: ${messageId}`,
                  `MIME-Version: 1.0`,
                  `Subject: ${subject}`,
                  `From: <${from}>`,
                  `To: <${to}>`,
                  `Content-Type: text/html; charset=utf-8`,
                  ``,
                  `${message}`,
                  `.`
              ].join('\r\n') + '\r\n';
              
              client.write(emailContent);
              step++;
            } else if (step === 8 && code === '250') {
              client.write(`QUIT\r\n`);
              step++;
            } else if (step === 9 && code === '221') {
              client.end();
              resolve(true);
            }
        } catch (err) {
            client.end();
            reject(err);
        }
      });

      client.on('error', (error) => {
        log.error('SMTP Baglanti Hatasi:', error.message);
        reject(error);
      });
    });
  }
}

module.exports = SMTPService;