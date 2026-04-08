// ============================================================
// db.js — IndexedDB wrapper for offline-first storage
// Stores: stubs, settings, outbox (pending sync operations)
// ============================================================

const DB_NAME = 'payday-offline';
const DB_VERSION = 1;

let _db = null;

function openDB() {
  if (_db) return Promise.resolve(_db);
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('stubs')) {
        const s = db.createObjectStore('stubs', { keyPath: 'id' });
        s.createIndex('user_id', 'user_id');
        s.createIndex('date', 'date');
      }
      if (!db.objectStoreNames.contains('settings')) {
        db.createObjectStore('settings', { keyPath: 'user_id' });
      }
      if (!db.objectStoreNames.contains('outbox')) {
        const o = db.createObjectStore('outbox', { keyPath: 'opId', autoIncrement: true });
        o.createIndex('user_id', 'user_id');
      }
    };
    req.onsuccess = e => { _db = e.target.result; resolve(_db); };
    req.onerror = e => reject(e.target.error);
  });
}

function tx(store, mode = 'readonly') {
  return openDB().then(db => db.transaction(store, mode).objectStore(store));
}

function req2p(r) {
  return new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
}

// ── Stubs ──────────────────────────────────────────────────
export async function idbSaveStubs(stubs, userId) {
  const store = await tx('stubs', 'readwrite');
  // Clear this user's stubs first, then write fresh
  await req2p(store.index('user_id').openCursor(IDBKeyRange.only(userId))).then ? null : null;
  // Simpler: delete all for user then re-add
  const all = await req2p((await tx('stubs')).getAll());
  const others = all.filter(s => s.user_id !== userId);
  const rw = await tx('stubs', 'readwrite');
  await req2p(rw.clear());
  // Re-add others
  for (const s of others) await req2p(rw.put(s));
  // Add this user's stubs
  for (const s of stubs) await req2p(rw.put({ ...s, user_id: userId }));
}

export async function idbGetStubs(userId) {
  const store = await tx('stubs');
  const all = await req2p(store.getAll());
  return all.filter(s => s.user_id === userId).sort((a, b) => b.date.localeCompare(a.date));
}

export async function idbPutStub(stub, userId) {
  const store = await tx('stubs', 'readwrite');
  await req2p(store.put({ ...stub, user_id: userId }));
}

export async function idbDeleteStub(id) {
  const store = await tx('stubs', 'readwrite');
  await req2p(store.delete(id));
}

// ── Settings ───────────────────────────────────────────────
export async function idbSaveSettings(settings, userId) {
  const store = await tx('settings', 'readwrite');
  await req2p(store.put({ ...settings, user_id: userId }));
}

export async function idbGetSettings(userId) {
  const store = await tx('settings');
  const row = await req2p(store.get(userId));
  if (!row) return {};
  const { user_id, ...rest } = row;
  return rest;
}

// ── Outbox ─────────────────────────────────────────────────
export async function idbEnqueue(op) {
  // op = { type: 'stub_create'|'stub_update'|'stub_delete'|'settings_update', payload, userId, path, method, body }
  const store = await tx('outbox', 'readwrite');
  await req2p(store.add({ ...op, queuedAt: Date.now() }));
}

export async function idbGetOutbox(userId) {
  const store = await tx('outbox');
  const all = await req2p(store.getAll());
  return all.filter(o => o.userId === userId).sort((a, b) => a.queuedAt - b.queuedAt);
}

export async function idbDequeue(opId) {
  const store = await tx('outbox', 'readwrite');
  await req2p(store.delete(opId));
}

export async function idbOutboxCount(userId) {
  const all = await idbGetOutbox(userId);
  return all.length;
}

export async function idbClearOutbox(userId) {
  const store = await tx('outbox', 'readwrite');
  const all = await req2p(store.getAll());
  for (const o of all.filter(o => o.userId === userId)) {
    await req2p(store.delete(o.opId));
  }
}
