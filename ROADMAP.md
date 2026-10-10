# Roadmap — cauteum-core

Status: **v0.1.3** (stable numbered release) · Part of [cauteum/cauteum](https://github.com/cauteum-haven)

Shared policy schema and egress engine.

## This module

| ID | Item | Notes |
|----|------|-------|
| C1 | **MCP / L7 depth** | First-class `protocol: mcp` method/tool matchers (hub R5) |
| C2 | **Policy decision integrations** | Use native OpenShell-shaped policy rules; remote PDP remains an explicit middleware integration (hub R4) |
| C3 | **Policy schema freeze** | Stabilize YAML for alpha consumers; versioned migration notes |
| C4 | **Engine concurrency** | Expand race tests around hot-reload + DecideHTTP |

## Non-goals (alpha)

- Embedding a full OPA SDK as the primary path; policy schema does not claim Rego support
- Managed `inference.local` hostname rewrite

## Release

Cascade: tag **this repo before its dependents**; downstream modules pin the released version.
