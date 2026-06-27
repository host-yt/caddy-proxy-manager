(function () {
  'use strict';
  var overlay;
  function getOrCreateOverlay() {
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'r-sheet-overlay';
      overlay.className = 'r-sheet-overlay';
      overlay.setAttribute('aria-hidden', 'true');
      document.body.appendChild(overlay);
    }
    return overlay;
  }
  function openSheet(id) {
    var sheet = document.getElementById(id);
    if (!sheet) return;
    var ov = getOrCreateOverlay();
    ov.style.display = 'block';
    sheet.classList.add('is-open');
    document.body.style.overflow = 'hidden';
    var focusable = sheet.querySelectorAll('button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])');
    if (focusable.length) setTimeout(function () { focusable[0].focus(); }, 50);
    function escHandler(e) {
      if (e.key === 'Escape') { closeSheet(id); document.removeEventListener('keydown', escHandler); }
    }
    document.addEventListener('keydown', escHandler);
    ov.onclick = function () { closeSheet(id); ov.onclick = null; };
  }
  function closeSheet(id) {
    var sheet = document.getElementById(id);
    var ov = document.getElementById('r-sheet-overlay');
    if (sheet) { sheet.classList.remove('is-open'); }
    setTimeout(function () {
      if (ov) ov.style.display = 'none';
      document.body.style.overflow = '';
    }, 260);
  }
  document.addEventListener('click', function (e) {
    var trigger = e.target.closest('[data-sheet-open]');
    if (trigger) openSheet(trigger.dataset.sheetOpen);
    var closer = e.target.closest('[data-sheet-close]');
    if (closer) {
      var sheet = closer.closest('.r-sheet');
      if (sheet && sheet.id) closeSheet(sheet.id);
    }
  });
  window.hpgSheet = { open: openSheet, close: closeSheet };
})();
