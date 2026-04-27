# LLM vs LLM+Joern vs LLM+TrailMark: Security Audit Benchmark

This repo is a quick investigation into giving an LLM structural code analysis improve its ability to find vulnerabilities. While I was playing with this Trail of Bits published [Trailmark](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/) so I added that to the comparison too. 

| Arm | F1 Score | Accuracy | Precision | Recall | Cost |
|-----|----------|----------|-----------|--------|------|
| A: LLM-only | 48.7% | 64.5% | 88.1% | 33.6% | $3.07 |
| B: LLM + Joern CPG | **91.8%** | **91.4%** | 87.6% | 96.4% | $10.81 |
| C: LLM + TrailMark | 83.8% | 80.9% | 72.7% | 99.1% | $12.92 |

All differences statistically significant (McNemar's test, p < 0.001).

Tested on 220 cases from [OWASP Benchmark Java v1.2](https://owasp.org/www-project-benchmark/) across 11 vulnerability categories, using Claude via CLI.

**[Read the full writeup](blog/llm-vs-llm-plus-cpg.md)** for methodology, per-category breakdown, and analysis of why the tools fail differently.

## How it works

Both tools precompute structural summaries in batch (3-4 seconds total), then inject the context into each LLM prompt alongside the source code. No live tool calls at inference time.

- **Joern** extracts HTTP input sources and dangerous sinks (focused, ~5 lines per file)
- **TrailMark** extracts full call graphs, branch conditions, complexity, and taint annotations (~30 lines per file)

Joern wins on precision (fewer false positives). TrailMark wins on recall (misses almost nothing). The type of structural data matters more than the amount.

## Quick start

```bash
# Prerequisites: Java 11+, Python 3.12+

# Install Joern
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o /tmp/joern-install.sh
chmod u+x /tmp/joern-install.sh && /tmp/joern-install.sh --install-dir="$HOME/.local/share/joern"
export PATH="$HOME/.local/share/joern/joern-cli:$PATH"

# Clone OWASP Benchmark and build CPG
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git /tmp/BenchmarkJava
joern-parse /tmp/BenchmarkJava/src/main/java --output /tmp/BenchmarkJava/.cpg/cpg.bin

# Install TrailMark
python3 -m venv benchmark/.venv
benchmark/.venv/bin/pip install trailmark

# Precompute structural contexts (~4s each)
python3 benchmark/run_benchmark.py --precompute --arm b
python3 benchmark/run_benchmark.py --precompute --arm c

# Run the benchmark
python3 benchmark/run_benchmark.py --arm a
python3 benchmark/run_benchmark.py --arm b
python3 benchmark/run_benchmark.py --arm c

# Generate report
python3 benchmark/analyze.py
```

## Repository structure

```
benchmark/
  run_benchmark.py          # Main harness: sample, precompute, run arms, save JSON
  analyze.py                # Compute metrics, McNemar's test, generate report
  results/
    arm_a_results.json      # LLM-only (220 cases)
    arm_b_results.json      # LLM + Joern (220 cases)
    arm_c_results.json      # LLM + TrailMark (220 cases)
    cpg_contexts.json       # Precomputed Joern source/sink data
    trailmark_contexts.json # Precomputed TrailMark call graphs
    report.md               # Generated comparison report
blog/
  llm-vs-llm-plus-cpg.md   # Full writeup
skills/                     # Claude Code plugin for Joern CPG analysis
  cpg-setup/                # Install Joern
  cpg-build/                # Build CPG from source
  cpg-query/                # Run CPGQL queries
  cpg-status/               # Check CPG state
```

## Key findings

- LLM-only scored **0% F1 on 7 of 11 categories** — it defaulted to "safe" for cmdi, crypto, hash, trustbound, securecookie, ldapi, and xpathi
- Both tools rescued all 7 categories, but Joern's focused source/sink data gave better precision
- Crypto and hash false positives are hard for both tools — distinguishing `DES` from `AES/GCM` is a string-value problem, not structural
- TrailMark is 3x faster per file despite using more tokens — richer context helps the model decide quicker

## License

Apache-2.0
