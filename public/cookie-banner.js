/* eslint-disable no-var */
'use strict';

// Çerez bandı. Tek dosya, bağımlılık yok; herhangi bir sayfaya
//   <script src="/static/cookie-banner.js"></script>
// eklemek yeterli.
//
// Bant SADECE karar verilmemişse çıkar. Verilmiş bir kararı her sayfada tekrar
// sormak, kullanıcıyı okumadan "kabul et"e basmaya alıştırır -- yani rızayı
// alırken rızayı anlamsızlaştırır.
//
// İki düğme de AYNI görsel ağırlıkta. "Kabul et" yeşil ve büyük, "reddet"
// küçük gri bir bağlantı olduğunda, ortada bir seçim kalmaz.

(function () {
  var CATEGORY = 'istatistik';

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function build(onDecide) {
    var wrap = el('div', 'fk-cookie-banner');
    wrap.setAttribute('role', 'dialog');
    wrap.setAttribute('aria-label', 'Çerez tercihi');

    var body = el('div', 'fk-cookie-banner__text');
    body.appendChild(el('strong', null, 'İstatistik çerezleri'));
    body.appendChild(el('p', 'fk-small',
      'Giriş akışının neresinde takıldığınızı toplu olarak görebilmek için bir '
      + 'çerez yazmak istiyoruz. Hesabınıza bağlanmaz. Oturum ve güvenlik '
      + 'çerezleri bundan ayrıdır ve zaten çalışmaktadır.'));

    var link = el('a', 'fk-small', 'Yazdığımız tüm çerezler');
    link.href = '/cookies';
    body.appendChild(link);

    var actions = el('div', 'fk-cookie-banner__actions');
    var reject = el('button', 'fk-btn fk-btn--secondary fk-btn--sm', 'İstemiyorum');
    var accept = el('button', 'fk-btn fk-btn--secondary fk-btn--sm', 'Olur');
    actions.appendChild(reject);
    actions.appendChild(accept);

    reject.addEventListener('click', function () { onDecide(false); });
    accept.addEventListener('click', function () { onDecide(true); });

    wrap.appendChild(body);
    wrap.appendChild(actions);
    return wrap;
  }

  var current = null;

  function dismiss() {
    if (current && current.parentNode) current.parentNode.removeChild(current);
    current = null;
  }

  function save(value) {
    return fetch('/api/cookies', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ istatistik: value }),
    }).then(dismiss, dismiss);
  }

  function show() {
    if (current) return;
    current = build(function (value) { save(value); });
    document.body.appendChild(current);
  }

  // Tercih sayfasının KENDİSİNDE bant gösterilmez: aynı soruyu, cevabı zaten
  // önünde duran kullanıcıya ikinci kez sormak, üstelik listenin üzerini
  // örterek sormak olurdu.
  var PREFERENCE_PAGES = ['/cookies', '/cerezler'];

  function init() {
    if (PREFERENCE_PAGES.indexOf(location.pathname) >= 0) return;
    fetch('/api/cookies', { credentials: 'same-origin' })
      .then(function (res) { return res.json(); })
      .then(function (data) { if (data.needsDecision) show(); })
      .catch(function () { /* bant gösterilemezse hiçbir istatistik çerezi de yazılmaz */ });
  }

  window.FitfakCookieBanner = { show: show, dismiss: dismiss, CATEGORY: CATEGORY };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
