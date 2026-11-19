/*
 * Shared by the unlock page and the service worker (plain script, no modules,
 * so importScripts() can load it). Bundle format, written by publish/build.mjs:
 *
 *   bundle.enc = IV (12 bytes) || AES-256-GCM( gzip( payload ) ), tag included
 *   payload    = header length (uint32, big-endian) || header JSON || file bytes
 *   header     = { v: 1, built: ISO date, files: { "path": [offset, length, type] } }
 *
 * The key file holds the raw 256-bit AES key as base64url. A wrong key fails
 * the GCM tag check, so decrypting doubles as checking the key.
 */
(function (root) {
  'use strict';
  var AAD = new TextEncoder().encode('breathband-docs bundle v1');

  function parseKeyText(text) {
    var m = String(text).match(/[A-Za-z0-9_-]{43}/);
    if (!m) throw new Error('not-a-key');
    var bin = atob(m[0].replace(/-/g, '+').replace(/_/g, '/') + '=');
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    if (bytes.length !== 32) throw new Error('not-a-key');
    return bytes;
  }

  function importKey(rawBytes) {
    // Not extractable: once imported, script can use the key but never read it back.
    return crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  }

  async function gunzip(bytes) {
    var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  async function decryptBundle(key, buffer) {
    var all = new Uint8Array(buffer);
    var plain;
    try {
      plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: all.slice(0, 12), additionalData: AAD }, key, all.slice(12));
    } catch (e) {
      throw new Error('wrong-key');
    }
    var payload = await gunzip(new Uint8Array(plain));
    var headerLen = new DataView(payload.buffer, payload.byteOffset).getUint32(0);
    var header = JSON.parse(new TextDecoder().decode(payload.subarray(4, 4 + headerLen)));
    var body = 4 + headerLen;
    var files = new Map();
    Object.keys(header.files).forEach(function (p) {
      var f = header.files[p];
      files.set(p, { type: f[2], bytes: payload.slice(body + f[0], body + f[0] + f[1]) });
    });
    return { built: header.built, files: files };
  }

  // One IndexedDB record holds the (non-extractable) CryptoKey and its expiry.
  var DB = 'breathband-docs', STORE = 'unlock', ID = 'current';
  function open() {
    return new Promise(function (resolve, reject) {
      var r = indexedDB.open(DB, 1);
      r.onupgradeneeded = function () { r.result.createObjectStore(STORE); };
      r.onsuccess = function () { resolve(r.result); };
      r.onerror = function () { reject(r.error); };
    });
  }
  function tx(mode, fn) {
    return open().then(function (d) {
      return new Promise(function (resolve, reject) {
        var t = d.transaction(STORE, mode);
        var req = fn(t.objectStore(STORE));
        t.oncomplete = function () { d.close(); resolve(req && req.result); };
        t.onerror = function () { d.close(); reject(t.error); };
      });
    });
  }
  function saveUnlock(key, expires) { return tx('readwrite', function (s) { return s.put({ key: key, expires: expires }, ID); }); }
  function clearUnlock() { return tx('readwrite', function (s) { return s.delete(ID); }); }
  async function loadUnlock() {
    var rec = await tx('readonly', function (s) { return s.get(ID); });
    if (!rec) return null;
    if (rec.expires < Date.now()) { await clearUnlock(); return null; }
    return rec;
  }

  root.BBCrypt = {
    parseKeyText: parseKeyText, importKey: importKey, decryptBundle: decryptBundle,
    saveUnlock: saveUnlock, clearUnlock: clearUnlock, loadUnlock: loadUnlock
  };
})(self);
