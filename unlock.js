(function () {
  'use strict';
  var HOURS = 3600 * 1000;
  var $ = function (id) { return document.getElementById(id); };
  var status = $('status');

  function say(text, kind) { status.textContent = text; status.className = kind || ''; }
  function show(view) {
    ['unlock-view', 'open-view', 'unsupported-view'].forEach(function (v) { $(v).hidden = v !== view; });
  }

  // Where to go after unlocking. Only paths inside ./s/ are allowed.
  function target() {
    var next = new URLSearchParams(location.search).get('next') || '';
    var base = new URL('s/', location.href);
    try {
      var url = new URL(next.replace(/^\/+/, ''), base);
      // The worker's redirect can't carry a #section inside ?next=, but the browser keeps it on this page.
      if (!url.hash && next) url.hash = location.hash;
      if (url.origin === base.origin && url.href.startsWith(base.href)) return url.href;
    } catch (e) { /* fall through */ }
    return base.href;
  }

  async function ready() {
    await navigator.serviceWorker.register('sw.js', { scope: './' });
    return navigator.serviceWorker.ready;
  }

  async function unlockWith(text) {
    var raw;
    try { raw = BBCrypt.parseKeyText(text); } catch (e) { return say("That doesn't look like a BreathBand docs key.", 'err'); }
    say('Checking the key…');
    try {
      var key = await BBCrypt.importKey(raw);
      raw.fill(0);
      var res = await fetch('bundle.enc', { cache: 'no-cache' });
      if (!res.ok) throw new Error('bundle-missing');
      await BBCrypt.decryptBundle(key, await res.arrayBuffer());
      var expires = Date.now() + ($('remember').checked ? 30 * 24 : 12) * HOURS;
      await BBCrypt.saveUnlock(key, expires);
      var reg = await ready();
      if (reg.active) reg.active.postMessage('unlocked');
      say('Unlocked. Opening…', 'ok');
      location.assign(target());
    } catch (e) {
      if (e.message === 'wrong-key') say("This key doesn't open the current version of the site. Ask for the latest key file.", 'err');
      else if (e.message === 'bundle-missing') say("The site's content couldn't be loaded. Try again in a minute.", 'err');
      else say('Something went wrong (' + e.message + '). Try again, or use another browser.', 'err');
    }
  }

  function readFile(file) {
    if (!file) return;
    if (file.size > 4096) return say("That file is too large to be a key file.", 'err');
    file.text().then(unlockWith);
  }

  async function init() {
    if (!('serviceWorker' in navigator) || !window.crypto || !crypto.subtle || !window.indexedDB || !window.DecompressionStream) {
      return show('unsupported-view');
    }
    try { await ready(); } catch (e) { return show('unsupported-view'); }

    var current = null;
    try { current = await BBCrypt.loadUnlock(); } catch (e) { /* IndexedDB blocked: treat as locked */ }
    if (current) {
      $('until').textContent = new Date(current.expires).toLocaleString();
      show('open-view');
      if (new URLSearchParams(location.search).has('next')) location.replace(target());
    } else {
      show('unlock-view');
      if (new URLSearchParams(location.search).has('next')) say('Load the key file to continue.');
    }
  }

  $('file').addEventListener('change', function (e) { readFile(e.target.files[0]); e.target.value = ''; });
  var drop = $('drop');
  drop.addEventListener('dragover', function (e) { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', function () { drop.classList.remove('over'); });
  drop.addEventListener('drop', function (e) { e.preventDefault(); drop.classList.remove('over'); readFile(e.dataTransfer.files[0]); });
  $('paste-go').addEventListener('click', function () { unlockWith($('paste').value); $('paste').value = ''; });
  $('open').addEventListener('click', function () { location.assign(target()); });
  $('lock').addEventListener('click', async function () {
    await BBCrypt.clearUnlock();
    var reg = await navigator.serviceWorker.ready;
    if (reg.active) reg.active.postMessage('locked');
    history.replaceState(null, '', location.pathname);
    say('Locked. The key has been removed from this device.', 'ok');
    show('unlock-view');
  });

  init();
})();
