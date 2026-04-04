const CACHE = 'payday-v2';
const ASSETS = ['/', '/index.html', '/manifest.json', '/db.js'];

// Install — cache all shell assets
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(ASSETS))
  );
  self.skipWaiting();
});

// Activate — clean up old caches
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch strategy:
// - API calls: network-first, fall through to offline response if network fails
// - Static assets: cache-first, update cache in background
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Let non-GET pass through (POST/PATCH/DELETE go directly to app logic)
  if (e.request.method !== 'GET') return;

  // API calls — network only (data handled by IndexedDB in the app)
  if (url.pathname.startsWith('/api/')) return;

  // Static assets — cache first, network fallback
  e.respondWith(
    caches.match(e.request).then(cached => {
      const networkFetch = fetch(e.request).then(res => {
        if (res.ok) {
          caches.open(CACHE).then(c => c.put(e.request, res.clone()));
        }
        return res;
      }).catch(() => cached);
      return cached || networkFetch;
    })
  );
});

// Background sync — triggered when network comes back
self.addEventListener('sync', e => {
  if (e.tag === 'payday-sync') {
    // Notify the app to flush its outbox
    e.waitUntil(
      self.clients.matchAll().then(clients =>
        clients.forEach(c => c.postMessage({ type: 'SYNC_NOW' }))
      )
    );
  }
});

// Push message from app to trigger a sync attempt
self.addEventListener('message', e => {
  if (e.data?.type === 'QUEUE_SYNC') {
    self.registration.sync?.register('payday-sync').catch(() => {
      // Background sync not supported — notify app directly
      self.clients.matchAll().then(clients =>
        clients.forEach(c => c.postMessage({ type: 'SYNC_NOW' }))
      );
    });
  }
});
