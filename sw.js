/*
 * Serves the decrypted site under ./s/ from memory. The key lives in IndexedDB
 * (non-extractable, with an expiry) so the site survives the browser stopping
 * this worker; the decrypted files are never written to disk.
 */
importScripts('bundle-crypto.js');

var SCOPE = self.registration.scope;            // e.g. https://breathband.github.io/breathband-docs-site/
var SITE = SCOPE + 's/';
var SITE_PATH = new URL(SITE).pathname;
var RECHECK_MS = 5 * 60 * 1000;                 // look for a newer bundle at most every 5 minutes
var HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  // The pages use inline <script>/<style> and same-origin iframes (the gallery).
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; media-src 'self'; frame-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none'"
};

var site = null;     // { files: Map, built, checkedAt, etag }
var loading = null;

self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });

self.addEventListener('message', function (e) {
  // The unlock page says "unlocked" or "locked"; drop whatever is in memory either way.
  if (e.data === 'unlocked' || e.data === 'locked') site = null;
});

async function fetchBundle(previousEtag) {
  var res = await fetch(SCOPE + 'bundle.enc', { cache: 'no-cache' });
  if (!res.ok) throw new Error('bundle-missing');
  var etag = res.headers.get('ETag');
  if (previousEtag && etag && etag === previousEtag) return { same: true };
  return { etag: etag, buffer: await res.arrayBuffer() };
}

async function load() {
  var unlock = await BBCrypt.loadUnlock();
  if (!unlock) { site = null; return null; }
  if (site && Date.now() - site.checkedAt < RECHECK_MS) return site;
  var got = await fetchBundle(site && site.etag);
  if (got.same) { site.checkedAt = Date.now(); return site; }
  try {
    var b = await BBCrypt.decryptBundle(unlock.key, got.buffer);
    site = { files: b.files, built: b.built, etag: got.etag, checkedAt: Date.now() };
    return site;
  } catch (err) {
    // The key was rotated: forget it, so the visitor is asked for the new one.
    if (err.message === 'wrong-key') await BBCrypt.clearUnlock();
    site = null;
    return null;
  }
}

function ensureLoaded() {
  if (!loading) loading = load().finally(function () { loading = null; });
  return loading;
}

function locked(request, url) {
  if (request.mode === 'navigate') {
    var next = url.pathname.slice(SITE_PATH.length) + url.search;
    return Response.redirect(SCOPE + '?next=' + encodeURIComponent(next), 302);
  }
  return new Response('Locked', { status: 401, headers: HEADERS });
}

async function serve(request, url) {
  var s = await ensureLoaded();
  if (!s) return locked(request, url);
  var p;
  try { p = decodeURIComponent(url.pathname.slice(SITE_PATH.length)); } catch (e) { p = ''; }
  if (p === '' || p.endsWith('/')) p += 'index.html';
  var f = s.files.get(p);
  if (!f && s.files.has(p + '/index.html')) {
    return Response.redirect(SITE + p + '/' + url.search, 301);
  }
  if (!f) return new Response('Not found', { status: 404, headers: HEADERS });
  var headers = Object.assign({ 'Content-Type': f.type }, HEADERS);
  return new Response(f.bytes, { status: 200, headers: headers });
}

self.addEventListener('fetch', function (e) {
  var url = new URL(e.request.url);
  if (url.origin !== self.location.origin || !url.href.startsWith(SITE)) return;
  e.respondWith(serve(e.request, url));
});
