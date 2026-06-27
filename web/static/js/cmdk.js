(function () {
  'use strict';
  var palette = document.getElementById('hpg-palette');
  var inp = document.getElementById('hpg-palette-input');
  var list = document.getElementById('hpg-palette-list');
  if (!palette || !inp || !list) return;

  var items = [];
  function collectItems() {
    items = [];
    document.querySelectorAll('#admin-sidebar a[href]').forEach(function (a) {
      var label = a.textContent.trim();
      if (label) items.push({ label: label, href: a.getAttribute('href') });
    });
  }

  function fuzzy(text, q) {
    if (!q) return 1;
    text = text.toLowerCase(); q = q.toLowerCase();
    var i = 0;
    for (var j = 0; j < text.length && i < q.length; j++) {
      if (text[j] === q[i]) i++;
    }
    return i === q.length ? (q.length / text.length) : 0;
  }

  var selIdx = 0;

  function render(q) {
    var res = items
      .map(function (it) { return { it: it, sc: fuzzy(it.label, q) }; })
      .filter(function (r) { return r.sc > 0; })
      .sort(function (a, b) { return b.sc - a.sc; })
      .slice(0, 8);
    list.innerHTML = '';
    selIdx = 0;
    res.forEach(function (r, i) {
      var li = document.createElement('li');
      li.setAttribute('role', 'option');
      li.dataset.href = r.it.href;
      li.style.cssText = 'display:flex;align-items:center;gap:10px;padding:10px 16px;cursor:pointer;font-size:14px;' +
        (i === 0 ? 'background:rgb(var(--surface-2))' : '');
      li.innerHTML = '<svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5" style="opacity:.4;flex-shrink:0"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg><span style="flex:1;color:rgb(var(--text))">' + r.it.label + '</span>';
      li.addEventListener('click', function () { go(this.dataset.href); });
      list.appendChild(li);
    });
    if (res.length === 0) {
      list.innerHTML = '<li style="padding:20px 16px;text-align:center;font-size:13px;color:rgb(var(--muted))">No results</li>';
    }
  }

  function setSelection(idx) {
    var lis = list.querySelectorAll('li');
    lis.forEach(function (li, i) {
      li.style.background = i === idx ? 'rgb(var(--surface-2))' : '';
    });
    selIdx = idx;
  }

  function go(href) { close(); window.location.href = href; }
  function open() {
    collectItems();
    palette.style.display = 'flex';
    inp.value = '';
    render('');
    inp.focus();
  }
  function close() { palette.style.display = 'none'; inp.value = ''; }

  inp.addEventListener('input', function () { render(this.value); });
  inp.addEventListener('keydown', function (e) {
    var lis = list.querySelectorAll('li[data-href]');
    if (!lis.length) return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelection(Math.min(selIdx + 1, lis.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelection(Math.max(selIdx - 1, 0));
    } else if (e.key === 'Enter') {
      var sel = lis[selIdx];
      if (sel) go(sel.dataset.href);
    }
  });
  palette.addEventListener('click', function (e) { if (e.target === palette) close(); });
  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); palette.style.display === 'none' ? open() : close(); }
    if (e.key === 'Escape' && palette.style.display !== 'none') close();
  });
  var btn = document.getElementById('cmd-palette-btn');
  if (btn) btn.addEventListener('click', open);

  // init: palette hidden by default (it may use style or hidden class)
  palette.style.display = 'none';
})();
