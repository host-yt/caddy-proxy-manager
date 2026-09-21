// Command palette: local nav (instant, fuzzy) + async /admin/search (debounced),
// merged into one result list, one keyboard/mouse handler set, one open/close state.
(function () {
  'use strict';
  var palette = document.getElementById('hpg-palette');
  var inp = document.getElementById('hpg-palette-input');
  var list = document.getElementById('hpg-palette-list');
  var btn = document.getElementById('cmd-palette-btn');
  if (!palette || !inp || !list) return;

  var kindClass = {
    host:   'bg-[rgb(var(--accent)/.12)] text-[rgb(var(--accent))]',
    client: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900 dark:text-emerald-300',
    node:   'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300',
    tunnel: 'bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300'
  };

  var navItems = [];
  function collectNavItems() {
    navItems = [];
    document.querySelectorAll('#admin-sidebar a[href]').forEach(function (a) {
      var label = a.textContent.trim();
      if (label) navItems.push({ kind: 'nav', label: label, url: a.getAttribute('href') });
    });
  }

  function fuzzy(text, q) {
    if (!q) return 1;
    text = text.toLowerCase(); q = q.toLowerCase();
    var i = 0;
    for (var j = 0; j < text.length && i < q.length; j++) if (text[j] === q[i]) i++;
    return i === q.length ? (q.length / text.length) : 0;
  }
  function localResults(q) {
    return navItems
      .map(function (it) { return { it: it, sc: fuzzy(it.label, q) }; })
      .filter(function (r) { return r.sc > 0; })
      .sort(function (a, b) { return b.sc - a.sc; })
      .slice(0, 8)
      .map(function (r) { return r.it; });
  }

  function escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  var items = [], cursor = -1;
  var reqSeq = 0, inflight = null, debTimer = null;

  function renderRow(r, i) {
    var li = document.createElement('li');
    li.setAttribute('role', 'option');
    li.setAttribute('data-idx', i);
    li.className = 'flex items-center gap-3 px-4 py-2.5 cursor-pointer select-none hover:bg-slate-50 dark:hover:bg-zinc-800 text-sm';
    var badge = r.kind === 'nav'
      ? '<svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5" class="shrink-0 opacity-40"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>'
      : '<span class="shrink-0 px-1.5 py-0.5 rounded text-[10px] font-medium ' + (kindClass[r.kind] || '') + '">' + escHtml(r.kind) + '</span>';
    li.innerHTML = badge +
      '<span class="flex-1 min-w-0"><span class="block truncate text-slate-900 dark:text-slate-100">' + escHtml(r.label) + '</span>' +
      (r.sub ? '<span class="block truncate text-xs text-slate-400 dark:text-slate-500">' + escHtml(r.sub) + '</span>' : '') + '</span>';
    li.addEventListener('click', function () { navigate(i); });
    li.addEventListener('mouseenter', function () { setCursor(i); });
    return li;
  }

  function render(results, message) {
    items = results; cursor = -1; list.innerHTML = '';
    if (message) {
      list.innerHTML = '<li class="px-4 py-3 text-sm text-slate-400 dark:text-slate-600">' + escHtml(message) + '</li>';
      return;
    }
    if (!results.length) {
      list.innerHTML = '<li class="px-4 py-3 text-sm text-slate-400 dark:text-slate-600">No results</li>';
      return;
    }
    results.forEach(function (r, i) { list.appendChild(renderRow(r, i)); });
    setCursor(0);
  }

  function setCursor(idx) {
    var els = list.querySelectorAll('[data-idx]');
    els.forEach(function (el) { el.classList.remove('bg-slate-50', 'dark:bg-zinc-800'); });
    cursor = idx;
    if (idx >= 0 && idx < els.length) {
      els[idx].classList.add('bg-slate-50', 'dark:bg-zinc-800');
      els[idx].scrollIntoView({ block: 'nearest' });
    }
  }

  function navigate(idx) {
    if (idx < 0 || idx >= items.length) return;
    close();
    window.location.href = items[idx].url;
  }

  function doSearch(q) {
    var local = localResults(q);
    if (inflight) inflight.abort();
    if (q.length < 2) { render(local); return; }
    render(local); // show instant nav matches while server results load
    var seq = ++reqSeq;
    var ac = ('AbortController' in window) ? new AbortController() : null;
    inflight = ac;
    fetch('/admin/search?q=' + encodeURIComponent(q), {
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json' },
      signal: ac ? ac.signal : undefined
    })
      .then(function (res) { if (!res.ok) throw new Error('http ' + res.status); return res.json(); })
      .then(function (data) {
        if (seq !== reqSeq) return; // stale response, a newer search superseded it
        render(local.concat(data.results || []));
      })
      .catch(function (err) {
        if (seq !== reqSeq || (err && err.name === 'AbortError')) return;
        render(local.length ? local : [], local.length ? null : 'Search failed - try again.');
      });
  }

  var lastFocus = null;
  function open() {
    collectNavItems();
    lastFocus = document.activeElement;
    palette.style.display = 'flex';
    inp.value = '';
    render(localResults(''));
    setTimeout(function () { inp.focus(); }, 30);
  }
  function close() {
    palette.style.display = 'none';
    clearTimeout(debTimer);
    if (inflight) { inflight.abort(); inflight = null; }
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  inp.addEventListener('input', function () {
    clearTimeout(debTimer);
    var q = inp.value.trim();
    debTimer = setTimeout(function () { doSearch(q); }, 180);
  });
  inp.addEventListener('keydown', function (e) {
    var len = items.length;
    if (e.key === 'ArrowDown') { e.preventDefault(); if (len) setCursor((cursor + 1) % len); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); if (len) setCursor((cursor - 1 + len) % len); }
    else if (e.key === 'Enter') { e.preventDefault(); navigate(cursor >= 0 ? cursor : 0); }
    else if (e.key === 'Escape') { e.preventDefault(); close(); }
  });
  palette.addEventListener('click', function (e) { if (e.target === palette) close(); });
  if (btn) btn.addEventListener('click', open);
  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      palette.style.display === 'none' || !palette.style.display ? open() : close();
    }
  });

  palette.style.display = 'none';
})();
