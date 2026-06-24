// Passkey/WebAuthn enrollment + list management. Loaded by /admin/2fa
// and /app/2fa. CSP-safe (no inline handlers - only addEventListener).
(function(){
  if (!window.PublicKeyCredential) return;

  function csrf(){
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.getAttribute('content') : '';
  }
  function jsonHeaders(){
    return { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() };
  }
  function postHeaders(){
    return { 'X-CSRF-Token': csrf() };
  }

  function b64uToBuf(s){
    s = (s||'').replace(/-/g,'+').replace(/_/g,'/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var b = new Uint8Array(bin.length);
    for (var i=0;i<bin.length;i++) b[i] = bin.charCodeAt(i);
    return b.buffer;
  }
  function bufToB64u(buf){
    var b = new Uint8Array(buf), s='';
    for (var i=0;i<b.length;i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }
  function reviveCreate(o){
    o = o.publicKey || o;
    o.challenge = b64uToBuf(o.challenge);
    if (o.user && o.user.id) o.user.id = b64uToBuf(o.user.id);
    if (o.excludeCredentials) o.excludeCredentials.forEach(function(c){ c.id = b64uToBuf(c.id); });
    return o;
  }
  function encodeAttestation(cred){
    return {
      id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
      response: {
        attestationObject: bufToB64u(cred.response.attestationObject),
        clientDataJSON:    bufToB64u(cred.response.clientDataJSON),
        transports: (cred.response.getTransports ? cred.response.getTransports() : [])
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
    };
  }

  function toast(msg, kind){
    if (window.hpgToast) { window.hpgToast(msg, kind); return; }
    alert(msg);
  }

  function renderList(scope, list, container){
    var u = scope === 'admin' ? '/admin/passkeys' : '/app/passkeys';
    container.innerHTML = '';
    if (!list || !list.length){
      container.innerHTML = '<p class="text-sm text-slate-500 dark:text-slate-400">No passkeys yet.</p>';
      return;
    }
    list.forEach(function(p){
      var row = document.createElement('div');
      row.className = 'flex items-center justify-between gap-3 py-2 border-b border-slate-100 dark:border-zinc-800 text-sm';
      var lu = p.last_used_at ? new Date(p.last_used_at).toLocaleString() : 'never';
      row.innerHTML = '<div><div class="font-medium">'+escapeHTML(p.name||'Passkey')+'</div>'+
        '<div class="text-xs text-slate-500 dark:text-slate-400">added '+new Date(p.created_at).toLocaleDateString()+' · last used '+lu+'</div></div>'+
        '<button data-pkid="'+p.id+'" class="text-xs px-2 py-1 rounded bg-rose-600 text-white hover:bg-rose-700">Remove</button>';
      container.appendChild(row);
    });
    container.querySelectorAll('button[data-pkid]').forEach(function(b){
      b.addEventListener('click', function(){
        var confirmFn = window.hpgConfirm ? window.hpgConfirm('Remove this passkey?') : Promise.resolve(confirm('Remove this passkey?'));
        confirmFn.then(function(ok){
          if (!ok) return;
          fetch(u + '/' + b.getAttribute('data-pkid'), { method:'DELETE', credentials:'same-origin', headers: postHeaders() })
            .then(function(r){ if (!r.ok) throw new Error('delete failed'); return loadList(scope, container); })
            .catch(function(e){ toast('Delete failed: '+e.message, 'error'); });
        });
      });
    });
  }
  function escapeHTML(s){
    return (s||'').replace(/[&<>"']/g, function(c){ return ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    })[c]; });
  }

  function loadList(scope, container){
    var u = scope === 'admin' ? '/admin/passkeys/' : '/app/passkeys/';
    return fetch(u, { credentials: 'same-origin' })
      .then(function(r){ return r.ok ? r.json() : []; })
      .then(function(list){ renderList(scope, list, container); });
  }

  function register(scope){
    var base = scope === 'admin' ? '/admin/passkeys' : '/app/passkeys';
    var nameP = window.hpgPrompt
      ? window.hpgPrompt('Name this passkey (e.g. "Macbook", "YubiKey 5"):', 'Passkey')
      : Promise.resolve(prompt('Name this passkey (e.g. "Macbook", "YubiKey 5"):', 'Passkey'));
    nameP.then(function(name){
      if (name === null) return;
      doRegister(base, name);
    });
  }

  function doRegister(base, name){
    var scope = base.indexOf('/admin/') === 0 ? 'admin' : 'client';
    fetch(base + '/register/begin', { method:'POST', credentials:'same-origin', headers: postHeaders() })
      .then(function(r){
        if (!r.ok) return r.text().then(function(t){ throw new Error(t || ('begin failed ('+r.status+')')); });
        return r.json();
      })
      .then(function(opts){
        return navigator.credentials.create({ publicKey: reviveCreate(opts) });
      })
      .then(function(cred){
        return fetch(base + '/register/finish?name=' + encodeURIComponent(name||'Passkey'), {
          method:'POST', credentials:'same-origin',
          headers: jsonHeaders(),
          body: JSON.stringify(encodeAttestation(cred))
        });
      })
      .then(function(r){
        if (!r.ok) return r.text().then(function(t){ throw new Error(t || 'finish failed'); });
        toast('Passkey added.', 'success');
        var c = document.getElementById('passkeys-list');
        if (c) loadList(scope, c);
      })
      .catch(function(e){ toast('Passkey enroll failed: '+e.message, 'error'); });
  }

  document.addEventListener('DOMContentLoaded', function(){
    var addBtn = document.getElementById('passkey-add-btn');
    var list   = document.getElementById('passkeys-list');
    if (!addBtn && !list) return;
    var scope  = (addBtn && addBtn.getAttribute('data-scope')) || (list && list.getAttribute('data-scope')) || 'admin';
    if (addBtn) addBtn.addEventListener('click', function(){ register(scope); });
    if (list) loadList(scope, list);
  });
})();
