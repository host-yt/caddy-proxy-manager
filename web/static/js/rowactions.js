/* Global row-action kebab menu. Document-level delegation so every table works
   without per-page JS. Menus are position:fixed and JS-positioned on open so
   they escape table card overflow clipping. */
(function () {
  'use strict';

  var openMenu = null;   // currently open .hpg-act-menu element
  var openBtn = null;    // its toggle button

  function close() {
    if (!openMenu) return;
    openMenu.classList.remove('is-open');
    if (openBtn) openBtn.setAttribute('aria-expanded', 'false');
    openMenu = null;
    openBtn = null;
  }

  // Position the (now-visible) menu fixed, right-aligned to the button.
  function position(menu, btn) {
    var rect = btn.getBoundingClientRect();
    var top = rect.bottom + 4;
    var menuW = menu.offsetWidth;
    var menuH = menu.offsetHeight;
    var left = Math.max(8, rect.right - menuW);
    // Flip upward if it would overflow the viewport bottom.
    if (top + menuH > window.innerHeight) {
      top = Math.max(8, rect.top - menuH - 4);
    }
    menu.style.top = top + 'px';
    menu.style.left = left + 'px';
  }

  function open(menu, btn) {
    close();
    menu.classList.add('is-open');
    btn.setAttribute('aria-expanded', 'true');
    openMenu = menu;
    openBtn = btn;
    // Measure after it is visible (offsetWidth/Height need a laid-out element).
    position(menu, btn);
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-hpg-act-btn]');
    if (btn) {
      e.preventDefault();
      e.stopPropagation();
      var menu = document.getElementById(btn.getAttribute('data-hpg-act-btn'));
      if (!menu) return;
      if (openMenu === menu) { close(); return; }
      open(menu, btn);
      return;
    }
    // Outside click: close unless inside the open menu.
    if (openMenu && !e.target.closest('.hpg-act-menu')) close();
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') close();
  });

  // Re-layout invalidates fixed coords; cheapest is to just close.
  window.addEventListener('scroll', close, true);
  window.addEventListener('resize', close);
})();
