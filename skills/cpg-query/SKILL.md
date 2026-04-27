---
name: cpg-query
description: Run structural code queries using Joern CPGQL against a built Code Property Graph. This skill should be used when investigating code structure, tracing data flow, finding callers or callees, analyzing control flow, searching for vulnerability patterns, finding dead code, checking taint paths, or performing any code analysis where structural understanding beyond text search would help. Requires a built CPG (see /cpg-build).
allowed-tools: [Read, Bash, Glob, Grep, Write]
---

# CPG Query — Structural Code Analysis

Run CPGQL queries against a Joern Code Property Graph to answer structural questions about code that grep cannot efficiently answer.

## When to Use This Skill

Use CPG queries instead of (or alongside) grep when you need to:
- **Find callers/callees**: "What calls this function?" or "What does this function call?"
- **Trace data flow**: "Does user input reach this dangerous function?"
- **Analyze control flow**: "What execution paths lead to this code?"
- **Find patterns**: "All functions that allocate memory without freeing it"
- **Detect vulnerabilities**: Taint analysis, injection paths, unsafe patterns
- **Understand structure**: Type hierarchies, method signatures, parameter types

Grep is still better for simple text searches, string matching, and finding specific literals.

## Before Querying

Read the CPGQL reference at `references/cpgql-reference.md` for the full query API.
Read common patterns at `references/query-patterns.md` for ready-to-use query templates.

## Locating the CPG

Search for a built CPG by checking for `.cpg/cpg.bin.zip` starting from the current working directory, then walking up parent directories:

```bash
dir="$(pwd)"
while [ "$dir" != "/" ]; do
  if [ -f "$dir/.cpg/cpg.bin.zip" ]; then
    echo "$dir/.cpg/cpg.bin.zip"
    break
  fi
  dir="$(dirname "$dir")"
done
```

If no CPG is found, inform the user they need to run `/cpg-build <path>` first.

## Executing Queries

### Step 1: Write a Temporary Script

Create a `.sc` file with the CPGQL query. The script must import the CPG and print results:

```bash
cat > /tmp/cpg-query-$(date +%s).sc << 'SCRIPT'
importCpg("<CPG_PATH>")

// --- Your CPGQL query here ---
val result = cpg.method.name.l

// Print results
result.foreach(println)
SCRIPT
```

Replace `<CPG_PATH>` with the absolute path to the `.cpg/cpg.bin.zip` file.

### Step 2: Execute

```bash
joern --script /tmp/cpg-query-<timestamp>.sc 2>&1
```

The JVM takes 5-15 seconds to start. For efficiency, combine multiple related questions into a single script rather than running separate queries.

### Step 3: Parse Results

The output will be printed to stdout. Parse and present the results to the user in a meaningful way — map back to source files and line numbers where possible.

### Step 4: Clean Up

```bash
rm /tmp/cpg-query-<timestamp>.sc
```

## Composing Compound Queries

To minimize JVM startup overhead, combine multiple questions in one script:

```scala
importCpg("<CPG_PATH>")

println("=== CALLERS OF targetFunction ===")
cpg.method.name("targetFunction").caller.name.l.foreach(println)

println("\n=== METHODS IN file.c ===")
cpg.method.file.nameExact("file.c").method.name.l.foreach(println)

println("\n=== DANGEROUS CALLS ===")
cpg.call.name("system|exec|popen").code.l.foreach(println)
```

## Error Handling

If a query fails with a Scala/JVM error:
1. Check the CPGQL reference for correct syntax
2. Common issues:
   - Missing `.l` or `.toList` at the end (queries are lazy)
   - Wrong node type (e.g., `cpg.function` should be `cpg.method`)
   - Regex syntax errors in `.name("pattern")`
3. Simplify the query and retry — start with `cpg.method.name.l` to verify the CPG loads
