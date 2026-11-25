// VyCheckout service worker: makes the site installable and shows a friendly page when offline.
// It never caches API calls or payment pages, so balances and prices are always live.
const CACHE = 'vy-shell-v1';
const OFFLINE = '/offline';
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll([OFFLINE, '/icon-192.png'])).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET' || req.mode !== 'navigate') return;   // only page loads; everything else goes straight to the network
  e.respondWith(fetch(req).catch(() => caches.match(OFFLINE)));
});
