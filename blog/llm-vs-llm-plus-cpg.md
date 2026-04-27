# Giving an LLM a Map: How Structural Code Analysis Turned a 49% Security Auditor Into a 92% One

*Draft. 2026-04-27.*

I spent a couple of weekends measuring something that's been nagging me: when you ask an LLM to find security vulnerabilities in Java code, how much does it actually help to give it structural analysis of the code? I ran the experiment with two different tools — Joern and TrailMark — on the OWASP Benchmark, and the results surprised me in three distinct ways.

**TL;DR** — LLM-only hit **48.7% F1**. LLM plus Joern source/sink analysis hit **91.8% F1**. LLM plus TrailMark call-graph analysis hit **83.8% F1**. Same model, same source code, same prompt structure. Both tools massively beat the baseline — but they fail in different ways, and the *type* of structural data matters more than the *amount*.

## The setup

I used [OWASP Benchmark Java v1.2](https://owasp.org/www-project-benchmark/) — 2,740 Java servlet test cases across 11 vulnerability categories (SQL injection, XSS, path traversal, command injection, weak crypto, weak hash, weak randomness, trust boundary violations, insecure cookies, LDAP injection, XPath injection). Every test case has a verified ground-truth label: is this code actually exploitable, or is it a safe pattern that looks suspicious?

I stratified-sampled 220 cases — 10 true positives + 10 false positives per category — and ran them through three arms:

| | Arm A | Arm B | Arm C |
|---|---|---|---|
| Source code in prompt | yes | yes | yes |
| Structural data | none | Joern CPG (sources + sinks) | TrailMark (full call graph) |
| Tools available | none | none | none |

All three arms ran on the same model (Claude, via CLI) with the same system prompt template: "decide if this is vulnerable or safe, return JSON." No chain-of-thought tricks, no tool use, no agentic loops. The only variable was the structural context appended to each prompt.

### What each arm actually saw

**Arm B (Joern)** received a short, targeted summary — which methods receive HTTP input and which methods are dangerous sinks:

```
CPG Structural Analysis:
HTTP Input Sources (1):
  L44 getHeaders: getHeaders("BenchmarkTest01210")
Dangerous Sinks (3):
  L61 prepareStatement: connection.prepareStatement(sql, ...)
  L66 execute: statement.execute()
  L70 println: getWriter().println("Error processing request.")
```

**Arm C (TrailMark)** received the full call graph — every method call with line numbers, entrypoint annotations, cyclomatic complexity, branch conditions, and taint/blast-radius annotations:

```
Method: doPost  (complexity=7) [ENTRYPOINT: untrusted_external]
  Parameters: request: HttpServletRequest, response: HttpServletResponse
  Call graph (18 calls):
    L44: request.getHeaders
    L51: java.net.URLDecoder.decode
    L61: connection.prepareStatement
    L66: statement.execute
    ...
  Branch conditions (6):
    L46: (headers != null && headers.hasMoreElements())
    L69: (cookies != null)
    ...
  [taint_propagation] tainted via: doGet, doPost
```

Both were precomputed in batch — Joern took ~4 seconds for 220 files, TrailMark ~3 seconds. No per-file tool calls at inference time.

## The results

| Metric | Arm A (LLM-only) | Arm B (Joern) | Arm C (TrailMark) |
|---|---|---|---|
| Accuracy | 64.5% | **91.4%** | 80.9% |
| Precision | **88.1%** | 87.6% | 72.7% |
| Recall | 33.6% | 96.4% | **99.1%** |
| F1 | 48.7% | **91.8%** | 83.8% |
| Cost | **$3.07** | $10.81 | $12.92 |
| Speed | 4.2s/file | 16.1s/file | **5.5s/file** |

All pairwise differences are statistically significant (McNemar's test, p < 0.001 for each pair).

The headline: both structural tools massively beat the baseline. But they do it differently.

**Joern wins on precision.** It has 15 false positives vs TrailMark's 41. By telling the model exactly which methods are sources and sinks — and nothing else — it focuses attention on what matters.

**TrailMark wins on recall.** It missed just 1 vulnerability across 110 true positives. The full call graph makes the model aggressive about flagging anything that looks suspicious. But it also flags a lot of safe code.

**TrailMark is 3× faster.** Despite injecting more tokens (18,820/file vs 13,406), the model responds quicker — the richer structure seems to help it decide faster, even if the decision is more often wrong.

## The finding I didn't expect

Look at per-category F1:

| Category | Arm A | Arm B (Joern) | Arm C (TrailMark) |
|---|---|---|---|
| sqli | 87.0% | 87.0% | 80.0% |
| weakrand | 95.2% | 95.2% | **100.0%** |
| xss | 95.2% | **100.0%** | 95.2% |
| pathtraver | 82.4% | **100.0%** | 87.0% |
| cmdi | **0.0%** | **90.9%** | 87.0% |
| crypto | **0.0%** | **80.0%** | 71.4% |
| hash | **0.0%** | 70.6% | **76.9%** |
| trustbound | **0.0%** | **95.2%** | 72.0% |
| securecookie | **0.0%** | **100.0%** | **100.0%** |
| ldapi | **0.0%** | **90.9%** | 83.3% |
| xpathi | **0.0%** | **100.0%** | 80.0% |

Arm A scored **zero F1 on seven of eleven categories**. Not "low recall" — zero. The model called every single case in those categories safe.

This isn't that the LLM doesn't know what command injection is. It's that when presented with a Java servlet that happens to be a command injection test case, it defaulted to "looks fine." The source code has `Runtime.getRuntime().exec(args)` right there. The model just... didn't flag it.

My best theory: when a model is asked "is this vulnerable?" without any structural guidance, it appears to weight the social prior ("most code I see in training isn't flagged") more than the syntactic signal. Give it a line-numbered pointer that says "line 44 reads a cookie, line 66 calls `exec`" and suddenly it connects the dots. The structural output isn't teaching the model anything it doesn't know about security — it's telling the model what to pay attention to.

## Where the tools diverge

The per-category breakdown reveals when each type of structural analysis helps.

**Joern dominates on categories where the source→sink relationship is the whole question**: trustbound (+95pp vs A, vs TrailMark's +72pp), xpathi (+100pp vs +80pp), pathtraver (+100pp vs +87pp). These are data-flow vulnerabilities: does user input reach a dangerous operation? Joern's explicit labeling of sources and sinks answers that directly.

**TrailMark edges Joern on purely syntactic categories**: weakrand (100% vs 95.2%) and hash (76.9% vs 70.6%). These vulnerabilities are about *which API was called* (`new Random()` vs `SecureRandom`, `MD5` vs `SHA-256`), not about data flow. The full call graph with every method invocation actually gives more context here.

**Both tools fail similarly on crypto false positives.** The model sees `Cipher.getInstance(...)` and flags it regardless of whether the argument is `"DES"` (weak) or `"AES/GCM/NoPadding"` (strong). Neither tool passes the string argument to the model — it's visible in the source code, but the structural data doesn't highlight it. A smarter CPG query that extracted cipher algorithm strings would likely fix this.

**The confidence calibration tells the story.** Both tools make the model more confident — but Joern makes it more *accurately* confident:

| Arm | Confidence (correct) | Confidence (incorrect) |
|---|---|---|
| A (LLM-only) | 0.62 | 0.41 |
| B (Joern) | 0.93 | 0.82 |
| C (TrailMark) | 0.93 | 0.90 |

TrailMark's model is 0.90 confident even when wrong. The call graph gives it *more* to reason about, which makes it feel more certain — but that certainty doesn't correlate with accuracy. Joern's narrower context creates a larger gap between correct and incorrect confidence (0.93 vs 0.82), making it a better-calibrated signal.

## The cost

| | Arm A | Arm B (Joern) | Arm C (TrailMark) |
|---|---|---|---|
| Cost per file | $0.014 | $0.049 | $0.059 |
| Total cost | $3.07 | $10.81 | $12.92 |
| Tokens per file | 3,885 | 13,406 | 18,820 |
| Wall clock per file | 4.2s | 16.1s | 5.5s |

TrailMark is the most expensive per file (more tokens) but the fastest (3× faster than Joern). The speed difference is surprising — more context but quicker decisions. My guess: the full call graph is so explicit that the model doesn't need to reason as much before committing to a verdict.

Both precompute steps are negligible: Joern batch takes ~4s, TrailMark takes ~3s. The cost is entirely in inference.

For any of these to be practical at scale, you'd want to think about prompt compression — many of TrailMark's call edges are noise for security purposes, and Joern's sink list includes `println` calls that aren't really dangerous. Smarter extraction would reduce tokens without reducing accuracy.

## What this means

The big takeaway isn't "Joern beats TrailMark" or vice versa. It's that **the type of structural summary matters more than the amount of information**.

Joern gave the model a *curated* view: here are your sources, here are your sinks. That's 3–8 lines of context. TrailMark gave it *everything*: every call, every branch, every annotation. That's 20–60 lines. The model performed better with less context because the Joern output directly answered the question it needed to answer: "does user input reach a dangerous sink?"

This suggests a design principle for LLM-augmented code analysis: **don't give the model a map of the whole city — give it directions to the destination.** The model already knows what SQL injection is. It needs to know whether *this specific code* has a path from user input to an unparameterised query. A targeted structural query beats a comprehensive structural dump.

The ideal tool would probably combine both: TrailMark's speed and call-graph coverage for initial triage, then Joern's focused source-sink analysis for the cases that need precision. Whether that's worth building depends on your false-positive tolerance.

## Caveats

This is one model, one benchmark, one sample size. OWASP Benchmark Java is synthetic — the test cases are cleanly isolated, one vulnerability per file, with limited cross-file flow. Real codebases have context that won't fit in a prompt, and real vulnerabilities often span files. TrailMark's call-graph and blast-radius analysis would likely add more value on real multi-file codebases where understanding the bigger picture matters.

The 0% F1 in seven categories for Arm A is partially an artifact of a minimal system prompt. A more security-tuned prompt, chain-of-thought, or few-shot examples of each category would likely lift the LLM-only baseline substantially. I didn't try — I wanted a clean comparison where the only variable was the structural context.

The Joern extraction was deliberately simple: method-name matching for known source/sink patterns. Real CPGQL queries can do inter-procedural taint analysis, which would be substantially more powerful. Similarly, TrailMark's `preanalysis()` computes taint propagation at the call-graph level, but the per-file servlets don't have enough cross-method flow for that to shine.

## Reproducing

All code is in [joern-cpg-analysis/benchmark](https://github.com/example/joern-cpg-analysis):

```bash
# 1. Install Joern and build the OWASP CPG
/cpg-setup
/cpg-build /tmp/BenchmarkJava

# 2. Install TrailMark
pip install trailmark

# 3. Precompute all contexts (Joern ~4s, TrailMark ~3s)
python benchmark/run_benchmark.py --precompute --arm b
python benchmark/run_benchmark.py --precompute --arm c

# 4. Run all three arms
python benchmark/run_benchmark.py --arm a
python benchmark/run_benchmark.py --arm b
python benchmark/run_benchmark.py --arm c

# 5. Analyse
python benchmark/analyze.py
```

Fixed seed (42), stratified sample, 220 cases, full JSON results committed. If you run it yourself and get different numbers, I'd genuinely like to know.
