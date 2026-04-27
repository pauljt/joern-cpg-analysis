# Joern CPG Analysis Plugin

This is a Claude Code plugin that adds Joern Code Property Graph skills for structural code investigation.

## Skills

| Skill | Type | Purpose |
|-------|------|---------|
| `/cpg-setup` | User-invoked | Install Joern and Java |
| `/cpg-build <path>` | User-invoked | Build a CPG from source code |
| `cpg-query` | Model-invoked | Run CPGQL queries during investigation |
| `cpg-status` | Model-invoked | Check if a CPG exists and is fresh |

## Workflow

1. Run `/cpg-setup` once to install Joern
2. Run `/cpg-build /path/to/project` to build a CPG for a target codebase
3. CPG queries are then available automatically during code investigation

## CPG Storage

CPGs are stored in `<project>/.cpg/cpg.bin.zip` alongside the target project (like `.git/`). Metadata is in `.cpg/meta.json`.

## When to Use CPG Queries vs Grep

- **Grep**: Simple text search, finding string literals, locating files
- **CPG Query**: Call graphs, data flow tracing, vulnerability detection, structural patterns, dead code analysis
