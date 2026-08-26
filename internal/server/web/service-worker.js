const CACHE = 'zentloop-static-v0310-pwa1';
const STATIC = new Set([
  '/style.css', '/app.js', '/login.css', '/login.js',
  '/favicon.png', '/zentloop-logo.png',
  '/pwa-icon-192.png', '/pwa-icon-512.png', '/pwa-maskable-512.png',
  '/manifest.webmanifest'
]);

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.addAll([
        '/favicon.png', '/zentloop-logo.png', '/pwa-icon-192.png',
        '/pwa-icon-512.png', '/pwa-maskable-512.png', '/manifest.webmanifest'
      ]))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys
        .filter(key => key.startsWith('zentloop-static-') && key !== CACHE)
        .map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin || !STATIC.has(url.pathname)) return;

  event.respondWith((async () => {
    try {
      const response = await fetch(req, {cache: 'no-cache'});
      if (response && response.ok) {
        const cache = await caches.open(CACHE);
        await cache.put(req, response.clone());
      }
      return response;
    } catch (_) {
      return caches.match(req);
    }
  })());
});
