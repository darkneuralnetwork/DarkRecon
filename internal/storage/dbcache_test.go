package storage

import (
	"path/filepath"
	"testing"
)

// TestDBCache_AcquireReleaseClosesOnEvict verifies the refcount contract that
// fixes BUG-6 (per-request open+migrate) without introducing use-after-close:
// a handle in active use is not closed when Evict is called, and is closed
// only once the last reader Releases it.
func TestDBCache_AcquireReleaseClosesOnEvict(t *testing.T) {
	c := NewDBCache()
	dbPath := filepath.Join(t.TempDir(), "scan.db")

	// Simulate a scan having already created + migrated the DB. Acquire is a
	// read path and deliberately does NOT create the file (so probes for
	// never-scanned targets 404 instead of minting empty DBs).
	seed, err := Open(dbPath)
	if err != nil {
		t.Fatalf("seed Open: %v", err)
	}
	seed.Close()

	// First Acquire opens + migrates.
	db1, err := c.Acquire(dbPath)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	// Second Acquire returns the SAME cached handle and bumps the refcount.
	db2, err := c.Acquire(dbPath)
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	if db1 != db2 {
		t.Fatal("expected the same cached *DB for concurrent readers")
	}

	// Evict while a reader is active must NOT close the handle (dirty flag set
	// instead), so db1/db2 remain usable.
	c.Evict(dbPath)
	if err := ping(db1); err != nil {
		t.Fatalf("handle closed while still in use after Evict: %v", err)
	}

	// Releasing the first reader keeps the handle alive (second reader still
	// holds a ref).
	db1.Close()
	if err := ping(db2); err != nil {
		t.Fatalf("handle closed before last reader released: %v", err)
	}

	// Releasing the last reader (via Close -> onClose -> Release) triggers the
	// deferred eviction: the handle is closed and removed from the cache.
	db2.Close()
	if _, ok := c.items[dbPath]; ok {
		t.Fatal("expected cached handle to be removed after last reader + Evict")
	}

	// A subsequent Acquire re-opens a fresh handle.
	db3, err := c.Acquire(dbPath)
	if err != nil {
		t.Fatalf("Acquire after eviction: %v", err)
	}
	if db3 == db1 {
		t.Fatal("expected a new *DB after eviction, got the closed one")
	}
	db3.Close()
}

// TestDBCache_AcquireMissingFileDoesNotCreate ensures a read probe for a
// target that was never scanned surfaces as an error instead of minting an
// empty scan.db that pollutes the cache. The scan WRITE path uses Open()
// directly, which does create.
func TestDBCache_AcquireMissingFileDoesNotCreate(t *testing.T) {
	c := NewDBCache()
	dbPath := filepath.Join(t.TempDir(), "does-not-exist", "scan.db")

	if _, err := c.Acquire(dbPath); err == nil {
		t.Fatal("expected an error acquiring a non-existent DB, got nil")
	}
	if _, ok := c.items[dbPath]; ok {
		t.Fatal("a failed Acquire must not leave a cache entry")
	}
}

// ping runs a trivial query to confirm the handle is still open/usable.
func ping(db *DB) error {
	_, err := db.conn.Exec("SELECT 1")
	return err
}
