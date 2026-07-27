'use strict';

const deviceBinding = require('../core/device-binding');

// Bir girişin TAMAMLANMA anı -- parola/TOTP/WebAuthn hangi yoldan gelirse gelsin.
//
// Bu dosya var, çünkü "giriş başarılı" noktasından sonra yapılması gereken şeyler
// üç ayrı serviste (auth-service, webauthn-service, srp-auth-service) tekrarlanıyordu
// ve her biri biraz farklı davranıyordu. Oturum çoğalması tam olarak böyle bir
// ayrışmadan doğdu: hepsi koşulsuz `createSession` çağırıyordu.
//
// Buradaki sıra sabit:
//   1. cihazı çöz (çerezden; yoksa yeni)
//   2. cihazı kaydet -> ilk kez mi görülüyor?
//   3. aynı cihaz için AÇIK oturum var mı -> varsa tazele, yoksa aç
//   4. yeni cihazsa kullanıcıya haber ver

async function completeLogin({
  db, sessionManager, userId, ip, userAgent, fingerprintId,
  deviceId, isNewDeviceCookie, mailer = null, method = 'password',
}) {
  const { isNewDevice, isFirstEverDevice } = await deviceBinding.recordDevice({
    db, userId, deviceId, ip, userAgent,
  });

  // Var olan oturumu tazele. Bulunamazsa yeni açılır.
  const reusable = await deviceBinding.findReusableSession({ sessionManager, userId, deviceId });

  let session;
  if (reusable) {
    session = await sessionManager.refreshExistingSession({
      sessionId: reusable.sessionId, ip, userAgent,
    });
  } else {
    session = await sessionManager.createSession({
      userId, ip, userAgent, fingerprintId, deviceId,
    });
  }

  // Bildirim yalnızca GERÇEKTEN yeni bir cihaz için. Kullanıcının ilk cihazı
  // (kayıttan hemen sonraki ilk giriş) bildirim değildir -- her girişte e-posta
  // göndermek bildirimleri değersizleştirir ve gerçekten önemli olanı gizler.
  if (isNewDevice && !isFirstEverDevice) {
    await notifyNewDevice({ db, mailer, userId, ip, userAgent, method }).catch((e) => {
      // Bildirim gönderilemedi diye giriş İPTAL EDİLMEZ: kullanıcı meşruysa
      // onu dışarıda bırakmak zarar verir. Ama sessizce geçilmez.
      console.error('[login] yeni cihaz bildirimi gönderilemedi:', e.message);
    });
  }

  return {
    ...session,
    deviceId,
    isNewDevice,
    isNewDeviceCookie,
    // Adım yükseltme kararı: hiç görülmemiş bir tarayıcıda ikinci faktör
    // ATLANAMAZ, parola doğru olsa bile. Bilinen bir tarayıcıda politika
    // gevşetilebilir. Google'ın gizli sekmede doğrulama sorup normal
    // pencerede sormamasının sebebi budur.
    requiresStepUp: isNewDevice,
  };
}

async function notifyNewDevice({ db, mailer, userId, ip, userAgent, method }) {
  const user = await db.collection('users').get(userId);
  if (!user || !user.email) return;

  const label = deviceBinding.describeUserAgent(userAgent);
  const when = new Intl.DateTimeFormat('tr-TR', {
    timeZone: 'Europe/Istanbul', dateStyle: 'long', timeStyle: 'short',
  }).format(new Date());

  const body = `Merhaba ${user.username},

Hesabınıza YENİ BİR CİHAZDAN giriş yapıldı.

  Cihaz    : ${label}
  IP       : ${ip || 'bilinmiyor'}
  Yöntem   : ${method}
  Zaman    : ${when} (Europe/Istanbul)

Bu siz değilseniz PAROLANIZI HEMEN DEĞİŞTİRİN ve hesap sayfanızdan
diğer oturumları kapatın:

  https://session.fitfak.net/portal

Bu sizseniz bu e-postayı yok sayabilirsiniz.

FITFAK Kimlik
`;

  if (!mailer) {
    // SMTP yapılandırılmamışsa bildirim kaybolmasın: en azından operatör görsün.
    console.warn(`[login] YENİ CİHAZ (e-posta gönderilemedi, SMTP yok) user=${user.username} device=${label} ip=${ip}`);
    return;
  }
  await mailer.sendMail({
    to: user.email,
    subject: 'FITFAK — hesabınıza yeni bir cihazdan giriş yapıldı',
    text: body,
  });
}

module.exports = { completeLogin, notifyNewDevice };
