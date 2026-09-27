package tofu_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/whaleshell/whaleshell-core/internal/tofu"
)

func TestTOFUFirstThenMismatch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := tofu.Open(filepath.Join(dir, "tofu.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyOrCache(bin); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyOrCache(bin); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("v2-changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyOrCache(bin); err == nil {
		t.Fatal("expected fingerprint mismatch")
	}
}

func TestTOFUCanonicalPathAndConcurrentStores(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin, []byte("v1"), 0755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "tool-alias")
	if err := os.Symlink(bin, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	path := filepath.Join(dir, "tofu.json")
	a, err := tofu.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tofu.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for _, tc := range []struct {
		store *tofu.Store
		path  string
	}{{a, bin}, {b, alias}} {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := tc.store.VerifyOrCache(tc.path); err != nil {
				t.Errorf("verify %s: %v", tc.path, err)
			}
		}()
	}
	group.Wait()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), bin) || strings.Contains(string(raw), alias) {
		t.Fatalf("TOFU did not use canonical path: %s", raw)
	}
}
