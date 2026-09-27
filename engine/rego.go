package engine

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
)

// DenyListGate is an optional post-allow deny hook. It is not a Rego interpreter.
// It accepts only these single-line rules:
//
//	# whaleshell-rego
//	deny host evil.example.com
//	deny method DELETE
//	deny path /admin/**
//
//	allow = false { input.host == "evil.example.com" }
//
// Missing/empty path = no-op (Go policy only).
type DenyListGate struct {
	denyHosts   []string
	denyMethods []string
	denyPaths   []string
}

// RegoGate preserves the existing API name for callers.
type RegoGate = DenyListGate

var legacyDeny = regexp.MustCompile(`^allow\s*=\s*false\s*\{\s*input\.(host|method|path)\s*==\s*"([^"]+)"\s*\}$`)

// LoadRegoFile loads an optional deny-list Rego/whaleshell-rego file.
func LoadRegoFile(pathName string) (*RegoGate, error) {
	pathName = strings.TrimSpace(pathName)
	if pathName == "" {
		return nil, nil
	}
	f, err := os.Open(pathName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	g := &DenyListGate{}
	sc := bufio.NewScanner(f)
	lineNumber := 0
	for sc.Scan() {
		lineNumber++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "deny" && fields[2] != "" {
			switch strings.ToLower(fields[1]) {
			case "host":
				g.denyHosts = append(g.denyHosts, fields[2])
				continue
			case "method":
				g.denyMethods = append(g.denyMethods, strings.ToUpper(fields[2]))
				continue
			case "path":
				g.denyPaths = append(g.denyPaths, fields[2])
				continue
			}
		}
		if matches := legacyDeny.FindStringSubmatch(line); matches != nil {
			switch matches[1] {
			case "host":
				g.denyHosts = append(g.denyHosts, matches[2])
			case "method":
				g.denyMethods = append(g.denyMethods, strings.ToUpper(matches[2]))
			case "path":
				g.denyPaths = append(g.denyPaths, matches[2])
			}
			continue
		}
		return nil, fmt.Errorf("%s:%d: unsupported deny-gate expression %q; use `deny host|method|path VALUE`", pathName, lineNumber, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return g, nil
}

// Allow reports whether the request passes the Rego gate (true = keep Go allow).
func (g *DenyListGate) Allow(_ context.Context, host, method, pathName, _ string) (bool, string) {
	if g == nil {
		return true, ""
	}
	for _, h := range g.denyHosts {
		if strings.EqualFold(h, host) {
			return false, "rego deny host " + h
		}
	}
	method = strings.ToUpper(method)
	for _, m := range g.denyMethods {
		if m == method {
			return false, "rego deny method " + m
		}
	}
	for _, p := range g.denyPaths {
		if matchRegoPath(p, pathName) {
			return false, "rego deny path " + p
		}
	}
	return true, ""
}

func matchRegoPath(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return name == prefix || strings.HasPrefix(name, prefix+"/")
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}
