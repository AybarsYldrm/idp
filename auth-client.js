const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto'); // PKCE için crypto modülü eklendi
const { IdentityClient } = require('./client/identity-client');

// --- YAPILANDIRMA ---
const PORT = 8443;
const RP_BASE_URL = `https://fitfak.net:8443`; // Gerçekte: https://dns.fitfak.net
const IDP_BASE_URL = 'https://session.fitfak.net';
const CLIENT_ID = '53fd2892-84a2-4ca1-8f50-492aaf665662';
const CLIENT_SECRET = process.env.DNS_CLIENT_SECRET || 'mm0PCeFUQJHZQNgQHaZF_-HS1k2Vvtwv';
const REDIRECT_URI = `${RP_BASE_URL}/oauth/callback`;

const identity = new IdentityClient({
  baseUrl: IDP_BASE_URL,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
});

// --- YARDIMCI FONKSİYONLAR ---
const parseCookies = (req) => {
  const header = req.headers.cookie;
  if (!header) return {};
  return Object.fromEntries(
    header.split(';').map(c => {
      const [key, ...v] = c.trim().split('=');
      return [key, decodeURIComponent(v.join('='))];
    })
  );
};

// Base64URL çevirici (PKCE verilerini URL'de güvenle taşımak için)
const base64URLEncode = (buffer) => {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

// Basit bir HTML şablon oluşturucu
const sendHtml = (res, statusCode, html) => {
  res.writeHead(statusCode, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
};

// --- SUNUCU ---
const tlsOptions = {
  key: fs.readFileSync(path.join(__dirname, 'certs', 'server.key')),
  cert: fs.readFileSync(path.join(__dirname, 'certs', 'server.crt'))
};

const server = https.createServer(tlsOptions, async (req, res) => {
  const url = new URL(req.url, RP_BASE_URL);

  try {
    // 1. ANA SAYFA VE GİRİŞ EKRANI
    if (req.method === 'GET' && url.pathname === '/') {
      const cookies = parseCookies(req);
      const userId = cookies['dns_session'];

      if (userId) {
        return sendHtml(res, 200, `
          <h1>DNS Paneline Hoş Geldin!</h1>
          <p>Giriş yapan kullanıcı ID: <strong>${userId}</strong></p>
          <a href="/api/protected-data">Gizli Verileri Gör</a> <br><br>
          <form method="POST" action="/logout"><button>Çıkış Yap</button></form>
        `);
      }

      return sendHtml(res, 200, `
        <div style="max-width: 400px; margin: 100px auto; font-family: sans-serif; text-align: center;">
          <h2>DNS Yönetim Paneli</h2>
          <p>Devam etmek için Fitfak kimliğinizle giriş yapmalısınız.</p>
          <a href="/login" style="display: inline-block; padding: 12px 24px; background: #d4a94e; color: #12142b; text-decoration: none; border-radius: 6px; font-weight: bold;">
            Fitfak Kimlik ile Giriş Yap
          </a>
        </div>
      `);
    }

    // 2. LOGİN TETİKLEYİCİSİ (IDP'ye yönlendirir)
    if (req.method === 'GET' && url.pathname === '/login') {
      const state = Math.random().toString(36).substring(2);
      
      // PKCE Üretimi: Doğrulayıcı (verifier) ve Meydan Okuma (challenge)
      const verifier = base64URLEncode(crypto.randomBytes(32));
      const challenge = base64URLEncode(crypto.createHash('sha256').update(verifier).digest());
      
      // Doğrulayıcıyı (verifier) callback aşamasında token takasında kullanmak üzere 5 dakikalık çereze yazıyoruz
      res.setHeader('Set-Cookie', `pkce_verifier=${verifier}; HttpOnly; Secure; SameSite=Lax; Max-Age=300; Path=/`);
      
      // authUrl içerisine code_challenge ve code_challenge_method parametreleri eklendi
      const authUrl = `${IDP_BASE_URL}/oauth/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid profile dns:read&state=${state}&code_challenge=${challenge}&code_challenge_method=S256`;
      
      res.writeHead(302, { 'Location': authUrl });
      return res.end();
    }

    // 3. CALLBACK (IDP'den başarıyla dönülen yer)
    if (req.method === 'GET' && url.pathname === '/oauth/callback') {
      const code = url.searchParams.get('code');
      if (!code) return sendHtml(res, 400, 'Kimlik doğrulama kodu bulunamadı.');

      // Yönlendirme öncesi sakladığımız PKCE doğrulayıcısını çerezden okuyoruz
      const cookies = parseCookies(req);
      const codeVerifier = cookies['pkce_verifier'];
      
      if (!codeVerifier) {
        return sendHtml(res, 400, 'PKCE doğrulayıcısı eksik veya süresi dolmuş. Lütfen tekrar giriş yapın.');
      }

      // Token takas isteğine 'code_verifier' alanını ekliyoruz
      // Kodu aldık, şimdi arka planda IDP'ye gidip Access Token ile takas edelim
      const tokenReqBody = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code_verifier: codeVerifier
      }).toString();

      const tokenRes = await fetch(`${IDP_BASE_URL}/oauth/token`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
          'User-Agent': 'Fitfak-DNS-Backend/1.0' // Cloudflare ve güvenlik duvarlarını aşmak için eklendi!
        },
        body: tokenReqBody
      });

      if (!tokenRes.ok) {
        // Hata JSON değilse (örn. Cloudflare 403 HTML) ne olduğunu görebilmek için ham metni okuyoruz
        const errText = await tokenRes.text();
        console.error("IDP'den Gelen Ham Hata (Log):", errText); 

        return sendHtml(res, 401, `
          <div style="max-width: 600px; margin: 50px auto; font-family: sans-serif;">
            <h2 style="color: #e2645a;">Token Takası Başarısız! (HTTP ${tokenRes.status})</h2>
            <p>İşlem reddedildi. Dönen yanıt bir JSON değil! Bu durum genellikle aradaki bir <strong>Güvenlik Duvarı (Cloudflare)</strong> veya <strong>Ters Proxy (Nginx)</strong> engellemesinden kaynaklanır.</p>
            <p>İşte karşıdaki sunucunun gönderdiği gerçek yanıt:</p>
            <textarea style="width: 100%; height: 250px; background: #1b1e42; color: #edeef7; padding: 10px; border-radius: 8px; border: 1px solid #33375f;">${errText}</textarea>
            <a href="/" style="display: block; margin-top: 15px; color: #d4a94e; font-weight: bold; text-decoration: none;">Başa Dön ve Yeni Bir Giriş Başlat</a>
          </div>
        `);
      }

      const tokenData = await tokenRes.json();
      
      const info = await identity.introspectToken(tokenData.access_token);
      if (!info.active) {
        return sendHtml(res, 401, 'Token geçersiz.');
      }

      const cookieVal = encodeURIComponent(info.sub);
      
      // Başarılı giriş sonrası hem asıl oturum çerezini (dns_session) ayarlıyor hem de geçici PKCE çerezini temizliyoruz
      res.setHeader('Set-Cookie', [
        `dns_session=${cookieVal}; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/`,
        `pkce_verifier=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/` 
      ]);
      
      res.writeHead(302, { 'Location': '/' });
      return res.end();
    }

    // 4. ÇIKIŞ YAP (Revoke)
    if (req.method === 'POST' && url.pathname === '/logout') {
      const userId = parseCookies(req)['dns_session'];
      if (userId) {
        try {
          const { sessions } = await identity.getUserSessions(userId);
          for (const session of sessions) await identity.revokeSession(session.sessionId);
        } catch (err) { console.error('IDP oturumu silinemedi', err); }
      }
      res.setHeader('Set-Cookie', 'dns_session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/');
      res.writeHead(302, { 'Location': '/' });
      return res.end();
    }

    // 5. KORUMALI ROTA
    if (req.method === 'GET' && url.pathname === '/api/protected-data') {
      const userId = parseCookies(req)['dns_session'];
      if (!userId) return sendHtml(res, 401, 'Yetkisiz erişim. <a href="/">Giriş yap</a>');
      
      return sendHtml(res, 200, `<h3>Çok Gizli DNS Ayarları</h3><p>Kullanıcı: ${userId}</p><a href="/">Geri Dön</a>`);
    }

    res.writeHead(404);
    res.end('Sayfa bulunamadi');

  } catch (err) {
    console.error('Sunucu Hatası:', err);
    res.writeHead(500);
    res.end('Sunucu Hatasi');
  }
});

server.listen(PORT, () => {
  console.log(`DNS RP Sunucusu başlatıldı: ${RP_BASE_URL}`);
  console.log(`IDP'ye yönlendirilecek: ${IDP_BASE_URL}`);
});