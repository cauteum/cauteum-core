package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whaleshell/whaleshell-core/engine"
)

func TestDenyListGateRejectsUnsupportedExpressions(t *testing.T) {
	for _, expression := range []string{
		`allow = true { input.host == "evil.example.com" }`,
		`allow = false { startswith(input.path, "/admin") }`,
		`deny host evil.example.com trailing`,
		`package whaleshell`,
	} {
		t.Run(expression, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "deny.rego")
			if err := os.WriteFile(file, []byte("# comment\n"+expression+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := engine.LoadRegoFile(file); err == nil || !strings.Contains(err.Error(), ":2:") {
				t.Fatalf("expected line-numbered rejection, got %v", err)
			}
		})
	}
}

func TestDenyListGateAppliesAllSupportedRules(t *testing.T) {
	file := filepath.Join(t.TempDir(), "deny.rego")
	data := "deny host evil.example.com\ndeny method DELETE\ndeny path /admin/**\n" +
		`allow = false { input.host == "legacy.example.com" }` + "\n"
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	gate, err := engine.LoadRegoFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct{ host, method, path string }{
		{"evil.example.com", "GET", "/"},
		{"legacy.example.com", "GET", "/"},
		{"safe.example.com", "DELETE", "/"},
		{"safe.example.com", "GET", "/admin/users"},
	} {
		if allow, _ := gate.Allow(context.Background(), request.host, request.method, request.path, ""); allow {
			t.Fatalf("expected deny for %+v", request)
		}
	}
}
