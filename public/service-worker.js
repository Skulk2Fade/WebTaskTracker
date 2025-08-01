const CACHE_NAME = 'tasktracker-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/board.html',
  '/calendar.html',
  '/dashboard.html',
  '/admin.html',
  '/help.html',
  '/style.css',
  '/script.js',
  '/board.js',
  '/calendar.js',
  '/dashboard.js',
  '/admin.js',
  '/sw-register.js',
  '/manifest.json'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(clients.claim());
});

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('task-queue', 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore('requests', { autoIncrement: true });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function broadcastQueueLength(length) {
  return self.clients.matchAll().then(clients => {
    clients.forEach(c => c.postMessage({ type: 'queueLength', length }));
  });
}

async function getQueueLength() {
  const db = await openDB();
  const tx = db.transaction('requests', 'readonly');
  const store = tx.objectStore('requests');
  const count = await new Promise((resolve, reject) => {
    const req = store.getAllKeys();
    req.onsuccess = () => resolve((req.result || []).length);
    req.onerror = () => reject(req.error);
  });
  return count;
}

async function notifyQueueChange() {
  const length = await getQueueLength();
  broadcastQueueLength(length);
}

function broadcastSyncComplete() {
  return self.clients.matchAll().then(clients => {
    clients.forEach(c => c.postMessage({ type: 'syncComplete' }));
  });
}

function storeRequest(data) {
  return openDB().then(db => {
    return new Promise((resolve, reject) => {
      const tx = db.transaction('requests', 'readwrite');
      tx.objectStore('requests').add(data);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }).then(() => {
    if (self.registration.sync) {
      self.registration.sync.register('task-sync').catch(() => {});
    }
    return notifyQueueChange();
  });
}

async function flushQueue() {
  const db = await openDB();
  const tx = db.transaction('requests', 'readwrite');
  const store = tx.objectStore('requests');
  const all = await new Promise((resolve, reject) => {
    const get = store.getAll();
    get.onsuccess = () => resolve(get.result || []);
    get.onerror = () => reject(get.error);
  });
  for (const r of all) {
    try {
      await fetch(r.url, {
        method: r.method,
        headers: r.headers,
        body: r.body ? JSON.stringify(r.body) : undefined
      });
    } catch (err) {
      // stop if network fails
      return;
    }
  }
  store.clear();
  await tx.complete;
  await notifyQueueChange();
  await broadcastSyncComplete();
  return;
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method === 'GET' && ASSETS.includes(url.pathname)) {
    event.respondWith(
      caches.match(event.request).then(res => res || fetch(event.request))
    );
    return;
  }
  if (url.pathname.startsWith('/api/') && event.request.method !== 'GET') {
    event.respondWith(
      fetch(event.request.clone()).catch(async () => {
        const headers = {};
        for (const [k, v] of event.request.headers.entries()) {
          headers[k] = v;
        }
        let body = null;
        try {
          body = await event.request.clone().json();
        } catch (e) {
          body = await event.request.clone().text();
        }
        await storeRequest({
          url: url.pathname + url.search,
          method: event.request.method,
          headers,
          body
        });
        return new Response(JSON.stringify({ queued: true }), {
          status: 202,
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
  }
});

self.addEventListener('message', event => {
  if (event.data && event.data.type === 'flush') {
    event.waitUntil(flushQueue());
  } else if (event.data && event.data.type === 'notify') {
    const d = event.data.data || {};
    const title = d._title || 'Task Update';
    const body = d._body || '';
    event.waitUntil(self.registration.showNotification(title, { body }));
  } else if (event.data && event.data.type === 'getQueueLength') {
    event.waitUntil(
      getQueueLength().then(length => {
        if (event.source) {
          event.source.postMessage({ type: 'queueLength', length });
        } else {
          broadcastQueueLength(length);
        }
      })
    );
  }
});

self.addEventListener('sync', event => {
  if (event.tag === 'task-sync') {
    event.waitUntil(flushQueue());
  }
});
