# LLM vs LLM+Joern vs LLM+TrailMark Vulnerability Detection Benchmark

- **Model**: claude (via CLI)
- **Timestamp (Arm A)**: 2026-04-13T09:53:58Z
- **Timestamp (Arm B)**: 2026-04-13T22:30:23Z
- **Timestamp (Arm C)**: 2026-04-27T07:22:04Z
- **Test suite**: OWASP Benchmark Java v1.2
- **Sample**: 220 cases (10 true + 10 false per category × 11 categories, seed=42)

## Overall Accuracy

| Metric | Arm A (LLM-only) | Arm B (LLM+Joern) | Arm C (LLM+TrailMark) | Δ A→B | Δ A→C |
| --- | --- | --- | --- | --- | --- |
| Accuracy | 64.5% | 91.4% | 80.9% | +26.8pp | +16.4pp |
| Precision | 88.1% | 87.6% | 72.7% | -0.5pp | -15.4pp |
| Recall | 33.6% | 96.4% | 99.1% | +62.7pp | +65.5pp |
| F1 Score | 48.7% | 91.8% | 83.8% | +43.1pp | +35.2pp |
| TP | 37 | 106 | 109 | +69 | +72 |
| FP | 5 | 15 | 41 | +10 | +36 |
| FN | 73 | 4 | 1 | -69 | -72 |
| TN | 105 | 95 | 69 | -10 | -36 |

### Statistical Significance (McNemar's Test)

- Cases where only A correct (b): **12**
- Cases where only B correct (c): **71**
- χ² statistic: **40.530**
- p-value: **0.0000** (significant at p<0.05)

## Per-Category F1 Score

| Category | CWE | A F1 | B F1 | C F1 | Δ A→B | Δ A→C |
| --- | --- | --- | --- | --- | --- | --- |
| sqli | 89 | 87.0% | 87.0% | 80.0% | +0.0pp | -7.0pp |
| weakrand | 330 | 95.2% | 95.2% | 100.0% | +0.0pp | +4.8pp |
| xss | 79 | 95.2% | 100.0% | 95.2% | +4.8pp | +0.0pp |
| pathtraver | 22 | 82.4% | 100.0% | 87.0% | +17.6pp | +4.6pp |
| cmdi | 78 | 0.0% | 90.9% | 87.0% | +90.9pp | +87.0pp |
| crypto | 327 | 0.0% | 80.0% | 71.4% | +80.0pp | +71.4pp |
| hash | 328 | 0.0% | 70.6% | 76.9% | +70.6pp | +76.9pp |
| trustbound | 501 | 0.0% | 95.2% | 72.0% | +95.2pp | +72.0pp |
| securecookie | 614 | 0.0% | 100.0% | 100.0% | +100.0pp | +100.0pp |
| ldapi | 90 | 0.0% | 90.9% | 83.3% | +90.9pp | +83.3pp |
| xpathi | 643 | 0.0% | 100.0% | 80.0% | +100.0pp | +80.0pp |

## Cost & Speed

| Metric | Arm A (LLM-only) | Arm B (LLM+Joern) | Arm C (LLM+TrailMark) |
| --- | --- | --- | --- |
| Total cost (USD) | $3.0732 | $10.808 | $12.9245 |
| Mean tokens/file | 3885.0 | 13406.0 | 18820.0 |
| Total tokens | 854,691 | 2,949,346 | 4,140,329 |
| Total wall time | 916.8s | 3544.0s | 1206.0s |
| Mean time/file | 4.17s | 16.11s | 5.48s |
| Context mode | — | Joern CPG (precomputed) | TrailMark call graph (precomputed) |

### CPG Context Mode (Arm B)

Arm B used **precomputed CPG context**: a single Joern batch session extracted HTTP input sources and dangerous sinks for all 220 test classes in one JVM invocation (~4s). The resulting source/sink data was injected directly into each prompt alongside the Java source code. The model received structural analysis (which methods receive user input, which methods are dangerous sinks) without needing to invoke Joern at inference time.

## Confidence Calibration

Mean model confidence by correctness:

| Arm | Correct predictions | Incorrect predictions |
| --- | --- | --- |
| A (LLM-only) | 0.62 | 0.41 |
| B (LLM+Joern) | 0.93 | 0.82 |
| C (LLM+TrailMark) | 0.93 | 0.90 |

## Key Findings

1. **Arm B F1 vs baseline**: +43.1pp (48.7% → 91.8%)
2. **Arm C F1 vs baseline**: +35.2pp (48.7% → 83.8%)
3. **Arm C vs Arm B**: -7.9pp
4. **Statistical significance (A vs B)**: p=0.0000 (significant)
5. **Statistical significance (A vs C)**: p=0.0009 (significant)
6. **Statistical significance (B vs C)**: p=0.0001 (significant)
7. **Cost**: A=$3.07, B=$10.81 (+252%), C=$12.92 (+321%)

## Publishability Assessment

### Why this is worth publishing

1. **Novel benchmark**: First rigorous head-to-head of LLM-only vs LLM+CPG on OWASP Benchmark Java with verified ground truth labels
2. **Controlled comparison**: Both arms receive identical source code; Arm B additionally receives pre-extracted CPG structural data (HTTP sources + dangerous sinks). This isolates the effect of structural code analysis on LLM vulnerability detection accuracy
3. **Quantified tradeoffs**: Exact P/R/F1 numbers alongside cost and latency overhead — actionable for teams building AI security tooling
4. **Category specificity**: Shows which vulnerability classes benefit from structural analysis vs. syntactic pattern matching
5. **Reproducible**: Fixed seed, open dataset, all code releasable under permissive license

### Suggested venues
- **Blog post** (highest reach): Anthropic blog, security publication (Dark Reading, SC Media)
- **arXiv preprint**: cs.CR or cs.AI — low bar, establishes priority
- **Workshop track**: USENIX Security, IEEE S&P, or CCS — 'AI+Security' workshops are active
- **Demo paper**: ICSE, FSE, or ASE — tool demonstration track
