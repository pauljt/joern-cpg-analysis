# Comparison With Published SAST Tool Results

How do our LLM-augmented approaches compare to established static analysis tools on the same benchmark?

## OWASP Benchmark v1.2 — F1 Score Comparison

| Tool / Approach | F1 | Precision | Recall | Accuracy | FPR | Source |
|-----------------|-----|-----------|--------|----------|-----|--------|
| **LLM + Joern CPG (Arm B)** | **91.8%** | **87.6%** | 96.4% | **91.4%** | 13.6% | This study (220 cases) |
| **LLM + TrailMark (Arm C)** | 83.8% | 72.7% | **99.1%** | 80.9% | 37.3% | This study (220 cases) |
| CodeQL | 74.4% | 60.3% | 97.0% | 65.5% | 68.2% | arXiv:2601.22952 (2,740 cases) |
| Semgrep CE | 69.4% | 56.3% | 90.4% | 58.9% | 74.8% | arXiv:2601.22952 (2,740 cases) |
| SonarQube | 67.3% | 51.9% | 95.6% | 52.0% | 94.6% | arXiv:2601.22952 (2,740 cases) |
| LLM-only (Arm A) | 48.7% | 88.1% | 33.6% | 64.5% | 4.5% | This study (220 cases) |
| Joern (standalone) | 14.3% | 54.7% | 8.2% | 49.1% | 7.2% | arXiv:2601.22952 (2,740 cases) |

### Additional published results (Benchmark Score = TPR - FPR)

| Tool | TPR | FPR | Benchmark Score | Source |
|------|-----|-----|-----------------|--------|
| Fluid Attacks SAST | 100% | 0% | 100 | Self-published, 2021 |
| Qwiet AI / ShiftLeft | 100% | 25% | 75 | Self-published |
| ThunderScan | ~73% | ~27% | 46 | Self-published |
| FindSecBugs | 97% | 58% | 39 | OWASP scorecard |
| Commercial SAST average (6 tools) | — | — | 26 | OWASP, 2016 |

## Key observations

### 1. LLM + Joern CPG beats every published standalone SAST tool on F1

At 91.8% F1, Arm B outperforms CodeQL (74.4%) by 17.4 percentage points. The gap is driven almost entirely by precision: 87.6% vs 60.3%. Both have high recall (96-97%), but CodeQL generates far more false positives (FPR 68.2% vs 13.6%).

### 2. Even LLM + TrailMark (Arm C) beats CodeQL

At 83.8% F1 with 99.1% recall, Arm C outperforms all standalone SAST tools. It has the highest recall of any approach tested, missing just 1 vulnerability out of 110. The tradeoff is a higher false positive rate (37.3%) than Arm B, though still far lower than CodeQL (68.2%) or SonarQube (94.6%).

### 3. The precision gap is the headline

Traditional SAST tools have a well-documented false positive problem:

| Tool | Precision | What this means |
|------|-----------|-----------------|
| SonarQube | 51.9% | ~1 in 2 alerts is wrong |
| Semgrep CE | 56.3% | ~4 in 9 alerts are wrong |
| CodeQL | 60.3% | ~2 in 5 alerts are wrong |
| LLM + TrailMark | 72.7% | ~1 in 4 alerts is wrong |
| **LLM + Joern CPG** | **87.6%** | ~1 in 8 alerts is wrong |

Developers consistently cite false positive fatigue as the main reason they ignore SAST findings. An approach that cuts the false positive rate from ~50% to ~12% while maintaining 96%+ recall changes the usability equation.

### 4. Standalone Joern scores 14.3% F1 — but enables 91.8% with an LLM

Joern ships with minimal default rules for the OWASP benchmark vulnerability categories. Its standalone recall is just 8.2%. But when used as a structural oracle — extracting sources and sinks and feeding them to an LLM — it enables the highest F1 of any approach. The LLM provides the reasoning and security knowledge that Joern's rule set lacks.

This is the core finding: **the combination is far more powerful than either component alone**.

### 5. LLM-only has high precision but catastrophically low recall

Arm A (LLM-only) actually has the highest precision (88.1%) of any approach — when it does flag something, it's almost always right. But it only flags 33.6% of real vulnerabilities, scoring 0% F1 on 7 of 11 categories. The structural context doesn't make the LLM more careful — it makes it more willing to flag issues it would otherwise overlook.

## Caveats on comparison fairness

1. **Sample size**: Our results are on a 220-case stratified sample (seed=42). The SAST tool results from arXiv:2601.22952 use the full 2,740 cases. The stratified sample should be representative, but exact numbers may differ on the full set.

2. **Default rulesets**: CodeQL, Semgrep, and SonarQube scores are from their default/recommended Java security rulesets. Custom rules tuned to the benchmark would score higher. Similarly, Semgrep Pro (commercial) likely outperforms Semgrep CE.

3. **Self-published claims**: Fluid Attacks' 100/100 score and Qwiet AI's results are self-published, not independently verified. The OWASP project notes that commercial tool results may be affected by license restrictions on public disclosure.

4. **Cost model differs**: SAST tools run locally with no per-query cost. Our LLM approach costs $0.05-0.06 per file in API tokens. At scale (thousands of files), this adds up — though the precompute step (Joern/TrailMark) is negligible.

5. **Scoring methodology**: The OWASP Benchmark traditionally uses TPR - FPR (Youden Index) as its scoring metric. We report F1, precision, recall, and accuracy, which give a more complete picture but make direct comparison with older OWASP scorecards difficult.

## References

- "Sifting the Noise: A Comparative Study of LLM Agents in Vulnerability False Positive Filtering" — [arXiv:2601.22952](https://arxiv.org/abs/2601.22952) (Jan 2025). Source of CodeQL, Semgrep, SonarQube, and Joern standalone results.
- Fluid Attacks OWASP Benchmark score — [fluidattacks.com](https://fluidattacks.com/blog/owasp-benchmark-fluid-attacks) (Apr 2021)
- Qwiet AI / ShiftLeft OWASP Benchmark — [qwiet.ai](https://qwiet.ai/news-press/shiftleft-achieves-highest-ever-sast-score-on-owasp-benchmark/)
- Doyensec: Comparing Semgrep and CodeQL — [blog.doyensec.com](https://blog.doyensec.com/2022/10/06/semgrep-codeql.html) (Oct 2022)
- OWASP Benchmark Project — [owasp.org](https://owasp.org/www-project-benchmark/)
- Cycode SAST tool benchmarking — [cycode.com](https://cycode.com/blog/benchmarking-top-sast-products/)
