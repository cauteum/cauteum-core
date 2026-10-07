<h1 align="center">whaleshell-core</h1>

<p align="center">
  <strong>Policy & egress engine</strong><br>
  Canonical policy schema, L4/L7 allowlists, host patterns, TOFU, and env placeholders.
</p>
<p align="center">
  <a href="https://github.com/whaleshell/whaleshell-core/actions/workflows/ci.yml"><img src="https://github.com/whaleshell/whaleshell-core/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pkg.go.dev/github.com/whaleshell/whaleshell-core"><img src="https://pkg.go.dev/badge/github.com/whaleshell/whaleshell-core.svg" alt="Go Reference"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/whaleshell/whaleshell-core"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>
</p>
<p align="center">
  <sub>Part of the <a href="https://github.com/whaleshell">whaleshell / whaleshell</a> ecosystem</sub>
</p>

---

## Overview

Policy behavior and its security boundaries are documented in the [policy guide](https://whaleshell.github.io/guides/policy/) and [security reference](https://whaleshell.github.io/concepts/security/).

**whaleshell-core** is the shared policy library for whaleshell. Every data-plane and control-plane component evaluates egress and filesystem rules from this schema.

### Key Features

| Category | Capabilities |
|----------|--------------|
| **Schema** | `filesystem_policy`, `landlock`, `network_policies`, inference, display, credentials |
| **Engine** | Default-deny allowlist with L7 REST / GraphQL / MCP matching |
| **Hosts** | Glob host patterns (`**.example.com`), ports, binaries, credential binding |
| **Inference** | Builtin provider presets (`anthropic`, `openai`, `local` → `host.whaleshell.internal`) |
| **Safety** | Binary TOFU store, env placeholder expansion for guest inject |

---

## Installation

Build this checkout inside the sibling `go.work` workspace with `go test ./...`. Published alpha tags still require a coordinated module-path release; see [compatibility status](https://whaleshell.github.io/reference/openshell-compatibility/).

**Requirements:** Go 1.27+

---

## Quick Start

```go
package main

import (
    "fmt"

    "github.com/whaleshell/whaleshell-core/engine"
    "github.com/whaleshell/whaleshell-core/policy"
)

func main() {
    doc, err := policy.Load("policy.yaml")
    if err != nil {
        panic(err)
    }
    var al engine.Allowlist
    if err := al.Apply(doc); err != nil {
        panic(err)
    }
    d, _ := al.Decide(nil, engine.EgressRequest{Host: "api.github.com", Port: 443})
    fmt.Println(d.Allow, d.Reason)
}
```

---

## Package Structure

| Package | Purpose |
|---------|---------|
| `policy/` | Document load/validate, L7 rules, inference presets |
| `engine/` | `Allowlist` Decide / DecideHTTP |
| `hostpattern/` | Host glob matching |
| `tofu/` | Trust-on-first-use binary fingerprints |
| `env/` | Host→guest credential placeholder helpers |
| `defaults/` | Shared paths and image names |


---

## Related

| Resource | Link |
|----------|------|
| Roadmap | [ROADMAP.md](./ROADMAP.md) |
| Organization | [https://github.com/whaleshell](https://github.com/whaleshell) |
| Organization overview | [github.com/whaleshell](https://github.com/whaleshell) |
| pkg.go.dev | [`github.com/whaleshell/whaleshell-core`](https://pkg.go.dev/github.com/whaleshell/whaleshell-core) |

## License

[Apache-2.0](./LICENSE) © whaleshell
