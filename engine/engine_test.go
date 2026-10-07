package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/whaleshell/whaleshell-core/engine"
	"github.com/whaleshell/whaleshell-core/internal/tofu"
	"github.com/whaleshell/whaleshell-core/policy"
)

func TestBinaryTOFU(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("policy.binaries require Unix-absolute paths (path.IsAbs)")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "curl")
	_ = os.WriteFile(bin, []byte("bin"), 0o755)
	store, err := tofu.Open(filepath.Join(dir, "tofu.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc := policy.Document{Version: 1, Binaries: []string{bin}}
	doc.SetNetworkAllows([]policy.AllowRule{{Host: "example.com", Port: 443}})
	var eng engine.Allowlist
	eng.SetTOFU(store)
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	d, _ := eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443, Binary: bin})
	if !d.Allow {
		t.Fatalf("first: %v", d)
	}
	_ = os.WriteFile(bin, []byte("changed"), 0o755)
	d, _ = eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443, Binary: bin})
	if d.Allow {
		t.Fatal("expected tofu deny")
	}
}

func TestPinnedPortListOverridesScalarPortAtRuntime(t *testing.T) {
	const source = `version: 1
network_policies:
  pinned-ports:
    endpoints:
      - host: api.example.com
        port: 8443
        ports: [9443, 10443]
`
	doc, err := policy.Parse([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	var allowlist engine.Allowlist
	if err := allowlist.Apply(doc); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{9443, 10443} {
		decision, err := allowlist.Decide(context.Background(), engine.EgressRequest{Host: "api.example.com", Port: port})
		if err != nil || !decision.Allow {
			t.Errorf("ports list value %d must be allowed: decision=%+v err=%v", port, decision, err)
		}
	}
	decision, err := allowlist.Decide(context.Background(), engine.EgressRequest{Host: "api.example.com", Port: 8443})
	if err != nil || decision.Allow {
		t.Fatalf("non-empty ports must override scalar port: decision=%+v err=%v", decision, err)
	}
}
