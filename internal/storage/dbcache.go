package storage

import (
	"os"
	"sync"
)

// DBCache pools open *DB handles by file path for the read-heavy API layer.
// Without it, every GET /api/... handler calls Open(dbPath), which runs the
// full schema migration (17 CREATE TABLE/INDEX statements) and tears down a
// connection on every request — including the 1s WebSocket/dashboard poll.
//
// It is reference-counted so a handle in active use is never closed out from
// under a reader (e.g. when a target is deleted mid-request). The scan WRITE
// path does NOT use this cache — scanmgr opens and closes its own short-lived
// handle per scan, so writers and cached readers never share a *sql.DB.
//
// Concurrency: WAL mode + busy_timeout lets one writer (the scan) coexist with
// many cached readers (the API) without "database is locked".
type DBCache struct {
	mu    sync.Mutex
	items map[string]*cacheItem
}

type cacheItem struct {
	db   *DB
	refs int  // active readers; the handle is only closed once this hits 0
	dirty bool // eviction requested — close as soon as refs reach 0
}

// NewDBCache creates an empty handle cache.
func NewDBCache() *DBCache {
	return &DBCache{items: make(map[string]*cacheItem)}
}

// Acquire returns a cached, already-migrated *DB for dbPath, opening and
// migrating exactly once. Each Acquire MUST be paired with a Release(dbPath)
// (the handle's Close() does this automatically via onClose).
//
// If dbPath does not exist, Acquire returns the os.Stat error WITHOUT creating
// the file — a read probe for a target that was never scanned should surface as
// a 404, not mint an empty scan.db that then pollutes the cache. The scan
// WRITE path uses Open() directly, which does create the DB.
// Thread-safe.
func (c *DBCache) Acquire(dbPath string) (*DB, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if item, ok := c.items[dbPath]; ok {
		item.refs++
		c.mu.Unlock()
		return item.db, nil
	}
	db, err := Open(dbPath)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	// Route the handle's Close() back to Release so API readers can keep using
	// the idiomatic `defer db.Close()` without tearing down the shared pool.
	path := dbPath
	db.onClose = func() { c.Release(path) }
	c.items[dbPath] = &cacheItem{db: db, refs: 1}
	c.mu.Unlock()
	return db, nil
}

// Release decrements the refcount for dbPath. If eviction was requested and no
// readers remain, the handle is closed and dropped from the cache. Calling
// Release with a path that isn't cached (or was already evicted) is a no-op.
func (c *DBCache) Release(dbPath string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[dbPath]
	if !ok {
		return
	}
	item.refs--
	if item.refs <= 0 && item.dirty {
		c.closeLocked(item, dbPath)
	}
}

// closeLocked performs the real underlying close of a cached handle. It MUST
// be called while holding c.mu. It clears onClose first so db.Close() calls
// conn.Close() directly instead of re-entering Release (which would deadlock
// on the mutex we already hold).
func (c *DBCache) closeLocked(item *cacheItem, dbPath string) {
	item.db.onClose = nil
	item.db.Close()
	delete(c.items, dbPath)
}

// Evict asks the cache to close the handle for dbPath. If no readers are using
// it, it is closed immediately; otherwise it is marked dirty and closed when
// the last reader Releases. Used when a target (and its scan.db) is deleted so
// we don't keep a handle to a removed file.
func (c *DBCache) Evict(dbPath string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[dbPath]
	if !ok {
		return
	}
	if item.refs <= 0 {
		c.closeLocked(item, dbPath)
		return
	}
	item.dirty = true
}

// CloseAll closes every cached handle regardless of refcount. Intended for
// graceful shutdown.
func (c *DBCache) CloseAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for path, item := range c.items {
		c.closeLocked(item, path)
	}
}
