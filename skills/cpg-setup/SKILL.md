---
name: cpg-setup
description: Install and configure Joern for CPG analysis. Use when the user asks to "install joern", "set up cpg", "configure joern", or when Joern is needed but not installed.
argument-hint: "[--force]"
allowed-tools: [Read, Bash, Glob, Grep]
disable-model-invocation: true
---

# CPG Setup — Install Joern

Install and verify the Joern Code Property Graph toolchain.

## Arguments

$ARGUMENTS

If `--force` is passed, reinstall even if Joern is already present.

## Steps

### 1. Check Current State

Run these checks and report the results:

```bash
# Check Java
java -version 2>&1

# Check Joern
which joern-parse 2>/dev/null && joern-parse --help 2>&1 | head -3
which joern 2>/dev/null && joern --version 2>&1
```

If both `joern` and `joern-parse` are found and `--force` was not passed, report the installed version and stop.

### 2. Install Java (if missing)

Java 11+ is required. On macOS:

```bash
brew install openjdk
```

After install, verify with `java -version`. If the user is not on macOS or doesn't have Homebrew, tell them to install a JDK 11+ manually and re-run `/cpg-setup`.

### 3. Install Joern

Download and run the official installer:

```bash
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o /tmp/joern-install.sh
chmod u+x /tmp/joern-install.sh
/tmp/joern-install.sh --install-dir="$HOME/.local/share/joern"
```

Then ensure the binaries are on PATH. Add to the user's shell profile if needed:

```bash
export PATH="$HOME/.local/share/joern/joern-cli:$PATH"
```

### 4. Verify Installation

```bash
joern --version
joern-parse --help | head -5
```

Report the installed Joern version, Java version, and confirm readiness.

### 5. Report Supported Languages

Tell the user Joern supports: C/C++, Java, JavaScript/TypeScript, Python, Go, Ruby, PHP, Kotlin, C#, Swift, and LLVM bitcode.
