---
name: cpg-build
description: Build a Joern Code Property Graph from a codebase. Use when the user asks to "build a cpg", "parse code into a graph", "create a code property graph", or needs to analyze a codebase structurally.
argument-hint: <target-directory> [--rebuild] [--memory 8G]
allowed-tools: [Read, Bash, Glob, Grep, Write]
disable-model-invocation: true
---

# CPG Build — Create a Code Property Graph

Build a Joern CPG from source code and store it alongside the target project.

## Arguments

$ARGUMENTS

- **target-directory** (required): Path to the codebase to analyze. Use cwd if omitted.
- **--rebuild**: Delete existing CPG and rebuild from scratch.
- **--memory SIZE**: JVM heap size (default: 8G). Use 16G-30G for large codebases.

## Steps

### 1. Verify Joern is Installed

```bash
which joern-parse >/dev/null 2>&1
```

If not found, tell the user to run `/cpg-setup` first and stop.

### 2. Resolve Target Directory

Resolve the target path to an absolute path. Verify the directory exists.

### 3. Detect Languages

Count source files by extension to determine what languages are present:

```bash
find <target> -type f \( -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "*.java" -o -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.go" -o -name "*.rb" -o -name "*.php" -o -name "*.kt" -o -name "*.cs" -o -name "*.swift" \) | head -1000 | sed 's/.*\.//' | sort | uniq -c | sort -rn
```

Report the detected languages and file counts.

### 4. Check for Existing CPG

If `<target>/.cpg/cpg.bin.zip` exists and `--rebuild` was NOT passed:
- Read `<target>/.cpg/meta.json`
- Find the newest source file modification time
- Compare against the CPG build timestamp
- If the CPG is fresh, report its age and ask if the user wants to rebuild
- If stale, warn and suggest `--rebuild`

If `--rebuild` was passed, delete `<target>/.cpg/` and continue.

### 5. Build the CPG

```bash
mkdir -p <target>/.cpg
joern-parse <target> \
  -J-Xmx<memory> \
  --output <target>/.cpg/cpg.bin.zip \
  2>&1
```

This may take several minutes for large codebases. Report progress.

### 6. Write Metadata

After a successful build, write `<target>/.cpg/meta.json`:

```json
{
  "source_dir": "<absolute-path-to-target>",
  "built_at": "<ISO-8601-timestamp>",
  "joern_version": "<output of joern --version>",
  "languages": ["<detected-languages>"],
  "file_count": <number>,
  "cpg_size_bytes": <size of cpg.bin.zip>,
  "build_duration_seconds": <elapsed>
}
```

Use Bash to gather the values and Write to create the file.

### 7. Update .gitignore

If `<target>/.gitignore` exists, check if `.cpg/` is already listed. If not, append it:

```bash
echo ".cpg/" >> <target>/.gitignore
```

If no `.gitignore` exists, create one with just `.cpg/`.

### 8. Report Results

Report:
- CPG file location and size
- Languages detected
- Number of source files parsed
- Build duration
- Remind the user they can now use CPG queries for investigation in this project
