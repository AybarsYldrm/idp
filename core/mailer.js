'use strict';

const tls = require('node:tls');
const crypto = require('node:crypto');

// ============================================================================
// Kullanıcının sağladığı smtp-service.js'ten UYARLANDI -- aynı TLS/SMTP durum
// makinesi (EHLO -> AUTH LOGIN -> MAIL FROM -> RCPT TO -> DATA -> QUIT), aynı
// güvenlik yamaları (EHLO'da kendi adını değil 'localhost' kullanmak -- kimlik
// hırsızlığı/spoofing izlenimini önler; Message-ID + Date + MIME-Version
// başlıkları -- spam/milter filtrelerinden geçmek için). Tek fark: projenin
// geri kalanıyla tutarlı olması için `./utils/logger` yerine basit bir
// console tabanlı logger kullanılıyor.
// ============================================================================
function mk(component) {
  const prefix = `[${component}]`;
  return {
    info: (...a) => console.log(prefix, ...a),
    debug: (...a) => { if (process.env.FITFAK_IDP_SMTP_DEBUG === '1') console.log(prefix, ...a); },
    error: (...a) => console.error(prefix, ...a),
  };
}
const log = mk('SMTP');

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
        rejectUnauthorized: false,
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
            // Kendi adımızla EHLO çekmiyoruz -- kimlik hırsızlığı/spoofing izlenimi vermesin.
            client.write('EHLO localhost\r\n');
            step++;
          } else if (step === 1 && code === '250') {
            client.write('AUTH LOGIN\r\n');
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
            client.write('DATA\r\n');
            step++;
          } else if (step === 7 && code === '354') {
            // Spam/milter filtrelerinden geçmesi için zorunlu başlıklar.
            const dateStr = new Date().toUTCString();
            const messageId = `<${crypto.randomUUID()}@fitfak.net>`;

            const emailContent = [
              `Date: ${dateStr}`,
              `Message-ID: ${messageId}`,
              'MIME-Version: 1.0',
              `Subject: ${subject}`,
              `From: <${from}>`,
              `To: <${to}>`,
              'Content-Type: text/html; charset=utf-8',
              '',
              `${message}`,
              '.',
            ].join('\r\n') + '\r\n';

            client.write(emailContent);
            step++;
          } else if (step === 8 && code === '250') {
            client.write('QUIT\r\n');
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

// ============================================================================
// E-posta şablonu -- tablo tabanlı düzen + satır-içi stil (e-posta istemcileri
// harici CSS/flexbox desteklemez).
// ============================================================================
function escHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function buildEmailHtml({ title, bodyHtml, footerNote }) {
  return `<!DOCTYPE html>
<html lang="tr">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${escHtml(title)}</title></head>
<body style="margin:0; padding:0; background-color:#f4f7f9;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f7f9; padding:32px 16px; font-family:'Segoe UI', Helvetica, Arial, sans-serif;">
  <tr><td align="center">
    <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px; width:100%; background-color:#ffffff; border-radius:10px; overflow:hidden; box-shadow:0 2px 12px rgba(44,62,80,0.08);">
      <tr><td style="background-color:#12142b; padding:20px 32px;">
        <span style="color:#ffffff; font-size:15px; font-weight:600; letter-spacing:.2px; font-family:'Segoe UI', Helvetica, Arial, sans-serif;">fitfak kimlik</span>
      </td></tr>
      <tr><td style="padding:32px 32px 8px; font-family:'Segoe UI', Helvetica, Arial, sans-serif;">
        <h1 style="margin:0 0 16px; font-size:19px; font-weight:600; color:#2c3e50; line-height:1.4;">${escHtml(title)}</h1>
        ${bodyHtml}
      </td></tr>
      <tr><td style="padding:18px 32px 26px; border-top:1px solid #eef1f3; margin-top:10px;">
        <p style="margin:16px 0 0; font-size:12px; color:#9aa3ab; line-height:1.6; font-family:'Segoe UI', Helvetica, Arial, sans-serif;">${footerNote || 'Bu e-postayı siz talep etmediyseniz güvenle yok sayabilirsiniz.'}</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;
}

function otpBadgeHtml(otp, introText) {
  return `<p style="margin:0 0 20px; font-size:14px; color:#5f6b76; line-height:1.65; font-family:'Segoe UI', Helvetica, Arial, sans-serif;">${escHtml(introText || 'Devam etmek için aşağıdaki doğrulama kodunu kullanın. Kod 15 dakika içinde geçerliliğini yitirir.')}</p>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:22px;"><tr><td style="background-color:#f8fafd; border:1px solid #e1e8ed; border-radius:8px; padding:18px; text-align:center;">
    <span style="font-size:30px; font-weight:700; letter-spacing:9px; color:#2c3e50; font-family:'Courier New', Courier, monospace;">${escHtml(otp)}</span>
  </td></tr></table>`;
}

module.exports = { SMTPService, buildEmailHtml, otpBadgeHtml, escHtml };
