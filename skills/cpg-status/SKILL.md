---
name: cpg-status
description: Check whether a Code Property Graph exists for the current project, whether it needs rebuilding, or what its current state is. This skill should be used before running CPG queries to verify readiness, or when the user asks "is there a CPG", "do I need to rebuild", "cpg status".
allowed-tools: [Read, Bash, Glob, Grep]
---

# CPG Status — Check Graph Readiness

Check whether a Joern CPG exists for the current project and whether it is up to date.

## Steps

### 1. Locate CPG

Walk up from the current working directory looking for `.cpg/cpg.bin.zip`:

```bash
dir="$(pwd)"
while [ "$dir" != "/" ]; do
  if [ -f "$dir/.cpg/cpg.bin.zip" ]; then
    echo "FOUND: $dir/.cpg/cpg.bin.zip"
    break
  fi
  dir="$(dirname "$dir")"
done
if [ ! -f "$dir/.cpg/cpg.bin.zip" ]; then
  echo "NOT FOUND"
fi
```

### 2. If Not Found

Report that no CPG exists for this project. Suggest running `/cpg-build <project-path>` to create one. Stop here.

### 3. If Found — Read Metadata

Read `<cpg-dir>/.cpg/meta.json` for build info. Report:
- **Source directory**: Where the CPG was built from
- **Built at**: Timestamp and how long ago
- **Languages**: Detected languages
- **File count**: Number of source files
- **CPG size**: Size of the .bin.zip file
- **Joern version**: Version used to build

### 4. Staleness Check

Find the most recently modified source file and compare against the CPG build time:

```bash
# Find newest source file modification time
find <source_dir> -type f \( -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "*.java" -o -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.go" -o -name "*.rb" -o -name "*.php" -o -name "*.kt" -o -name "*.cs" -o -name "*.swift" \) -newer <cpg-dir>/.cpg/cpg.bin.zip | head -5
```

### 5. Report Status

Report one of:
- **Ready**: CPG exists and is up to date. Queries can proceed.
- **Stale**: CPG exists but source files have been modified since it was built. List the changed files. Suggest `/cpg-build <path> --rebuild`.
- **Missing**: No CPG found. Suggest `/cpg-build <path>`.
