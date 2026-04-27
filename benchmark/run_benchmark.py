#!/usr/bin/env python3
"""
LLM vs LLM+Joern vs LLM+TrailMark Vulnerability Detection Benchmark
=====================================================================
Compares three arms on OWASP Benchmark Java v1.2 using `claude -p` (no API key needed).

  Arm A: LLM reads source code, classifies directly — no tools
  Arm B: LLM reads source code + pre-computed Joern CPG context (sources/sinks)
  Arm C: LLM reads source code + pre-computed TrailMark call graph (calls/branches/taint)
  Arm B (live): LLM reads source code + can call Bash/Joern live — agentic (slow)

Usage:
  python run_benchmark.py --dry-run            # Validate paths, show sample, no calls
  python run_benchmark.py --precompute         # Build all caches (Joern + TrailMark)
  python run_benchmark.py --arm a --limit 5    # Smoke test Arm A, 5 files
  python run_benchmark.py --arm b --limit 5    # Smoke test Arm B (Joern), 5 files
  python run_benchmark.py --arm c --limit 5    # Smoke test Arm C (TrailMark), 5 files
  python run_benchmark.py --arm b --live       # Arm B with live Joern (slow, agentic)
  python run_benchmark.py                      # Full run: precompute + arms A & B
  python run_benchmark.py --arm c              # Full run: Arm C only
"""

import argparse
import csv
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ── Configuration ───────────────────────────────────────────────────────────────

BENCHMARK_DIR = Path("/tmp/BenchmarkJava")
CPG_PATH      = BENCHMARK_DIR / ".cpg" / "cpg.bin"
JOERN_BIN     = Path.home() / ".local/share/joern/joern-cli/joern"
GROUND_TRUTH  = BENCHMARK_DIR / "expectedresults-1.2.csv"
TESTCODE_DIR  = BENCHMARK_DIR / "src/main/java/org/owasp/benchmark/testcode"
RESULTS_DIR   = Path(__file__).parent / "results"
CPG_CACHE     = RESULTS_DIR / "cpg_contexts.json"
TM_CACHE      = RESULTS_DIR / "trailmark_contexts.json"
CLAUDE_BIN    = "claude"
VENV_PYTHON   = Path(__file__).parent / ".venv" / "bin" / "python3"

JOERN_ENV = {**os.environ,
             "PATH": f"/opt/homebrew/opt/openjdk/bin:{os.environ['PATH']}"}

SEED    = 42
N_TRUE  = 10
N_FALSE = 10

CATEGORIES = [
    "sqli", "weakrand", "xss", "pathtraver", "cmdi",
    "crypto", "hash", "trustbound", "securecookie", "ldapi", "xpathi"
]

# Sink method names queried by the CPG batch
CPG_SINK_METHODS = (
    "executeQuery|executeUpdate|prepareStatement|prepareCall|execute"
    "|exec|evaluate|format|println|print|search"
    "|setAttribute|putValue|getInstance"
    "|nextInt|nextDouble|nextLong|nextFloat|nextBoolean|nextGaussian"
    "|addCookie|setSecure"
)
CPG_SOURCE_METHODS = (
    "getParameter|getHeader|getCookies|getHeaders"
    "|getHeaderNames|getQueryString|getInputStream|getPathInfo|getRequestURI"
)

# ── System prompts ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT_A = """\
You are a security auditor reviewing a Java servlet from the OWASP Benchmark v1.2.

TASK: Decide whether this code contains a REAL, exploitable vulnerability, or \
whether it is safe (a false positive — code that looks suspicious but is actually secure).

IMPORTANT: Output ONLY a JSON object as your complete response (no other text):
{
  "vulnerable": <true|false>,
  "category": "<one of: sqli, weakrand, xss, pathtraver, cmdi, crypto, hash, trustbound, securecookie, ldapi, xpathi>",
  "confidence": <0.0-1.0>,
  "reasoning": "<1-3 sentences citing specific lines>"
}

Criteria:
- vulnerable=true: user-controlled input reaches a dangerous sink without adequate sanitisation/parameterisation
- vulnerable=false: the code uses proper defences (prepared statements, encoding, safe APIs, strong algorithms)
"""

SYSTEM_PROMPT_B_PRECOMPUTED = """\
You are a security auditor reviewing a Java servlet from the OWASP Benchmark v1.2.

TASK: Decide whether this code contains a REAL, exploitable vulnerability, or \
whether it is safe (a false positive — code that looks suspicious but is actually secure).

You will receive both:
  1. The Java source code
  2. Code Property Graph (CPG) analysis showing HTTP input sources and dangerous sinks

The key question: does user-controlled input flow from a Source to a Sink \
WITHOUT adequate sanitisation or parameterisation?

IMPORTANT: Output ONLY a JSON object as your complete response (no other text):
{
  "vulnerable": <true|false>,
  "category": "<one of: sqli, weakrand, xss, pathtraver, cmdi, crypto, hash, trustbound, securecookie, ldapi, xpathi>",
  "confidence": <0.0-1.0>,
  "reasoning": "<1-3 sentences citing specific lines and what the CPG data reveals>"
}

Criteria:
- vulnerable=true: taint flows from Source to Sink without sanitisation/parameterisation
- vulnerable=false: proper defences prevent exploitation (prepared statements, encoding, safe APIs, strong algorithms)
"""

SYSTEM_PROMPT_B_LIVE = """\
You are a security auditor reviewing a Java servlet from the OWASP Benchmark v1.2.

TASK: Decide whether this code contains a REAL, exploitable vulnerability, or \
whether it is safe (a false positive — code that looks suspicious but is actually secure).

You have access to a Bash tool. Use it to run Joern Code Property Graph queries \
if you want structural analysis (data flow tracing, call graph, taint paths).
The CPG for the full project is pre-built at: """ + str(CPG_PATH) + """

Example — write a .sc script and run it:
  cat > /tmp/q.sc << 'JOERN'
  importCpg(\"""" + str(CPG_PATH) + """\")
  cpg.method.filter(_.location.filename.contains("BenchmarkTestXXXXX"))
    .call.name("getParameter|getHeader|getCookies").l
    .foreach(c => println(s"L${c.lineNumber.getOrElse("?")} ${c.name}: ${c.code.take(80)}"))
  JOERN
  PATH="/opt/homebrew/opt/openjdk/bin:$PATH" """ + str(JOERN_BIN) + """ --script /tmp/q.sc 2>&1 | grep -v "^WARNING:" | grep -v "^\\["

IMPORTANT: Output ONLY a JSON object as your FINAL response (no other text around the JSON):
{
  "vulnerable": <true|false>,
  "category": "<one of: sqli, weakrand, xss, pathtraver, cmdi, crypto, hash, trustbound, securecookie, ldapi, xpathi>",
  "confidence": <0.0-1.0>,
  "reasoning": "<1-3 sentences citing specific lines>"
}

Criteria:
- vulnerable=true: user-controlled input reaches a dangerous sink without adequate sanitisation/parameterisation
- vulnerable=false: the code uses proper defences (prepared statements, encoding, safe APIs, strong algorithms)
"""

SYSTEM_PROMPT_C = """\
You are a security auditor reviewing a Java servlet from the OWASP Benchmark v1.2.

TASK: Decide whether this code contains a REAL, exploitable vulnerability, or \
whether it is safe (a false positive — code that looks suspicious but is actually secure).

You will receive both:
  1. The Java source code
  2. TrailMark call-graph analysis: every method call with line numbers, \
entrypoints (untrusted HTTP inputs), cyclomatic complexity, and branch conditions

Use the call graph to trace whether user input from an entrypoint reaches a \
dangerous operation. Pay attention to:
  - Calls to methods like getParameter, getCookies, getHeader (HTTP sources)
  - Calls to methods like executeQuery, exec, println, addCookie (potential sinks)
  - Whether sanitisation calls (encodeForHTML, prepareStatement, etc.) appear between source and sink
  - Branch conditions that gate the data flow

IMPORTANT: Output ONLY a JSON object as your complete response (no other text):
{
  "vulnerable": <true|false>,
  "category": "<one of: sqli, weakrand, xss, pathtraver, cmdi, crypto, hash, trustbound, securecookie, ldapi, xpathi>",
  "confidence": <0.0-1.0>,
  "reasoning": "<1-3 sentences citing specific lines and what the call graph reveals>"
}

Criteria:
- vulnerable=true: user-controlled input reaches a dangerous sink without adequate sanitisation/parameterisation
- vulnerable=false: the code uses proper defences (prepared statements, encoding, safe APIs, strong algorithms)
"""

# ── Data loading ────────────────────────────────────────────────────────────────

def load_ground_truth():
    truth = {}
    with open(GROUND_TRUTH) as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            test, cat, real, cwe = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
            truth[test] = {"category": cat, "real": real.lower() == "true", "cwe": cwe}
    return truth


def stratified_sample(truth):
    rng = random.Random(SEED)
    by_cat = {}
    for test, info in truth.items():
        by_cat.setdefault(info["category"], {"true": [], "false": []})
        by_cat[info["category"]]["true" if info["real"] else "false"].append(test)

    sample = []
    for cat in CATEGORIES:
        b = by_cat.get(cat, {"true": [], "false": []})
        trues  = rng.sample(b["true"],  min(N_TRUE,  len(b["true"])))
        falses = rng.sample(b["false"], min(N_FALSE, len(b["false"])))
        for test in trues + falses:
            sample.append({"test": test, **truth[test]})
    return sample


def read_source(test_name):
    return (TESTCODE_DIR / f"{test_name}.java").read_text()

# ── CPG pre-computation ─────────────────────────────────────────────────────────

def build_joern_batch_script(test_names):
    """
    Build a single Scala script that queries all test classes in one JVM session.
    Uses string concatenation to avoid Python f-string / Scala interpolation conflicts.
    """
    # Scala list literal: List("Name1", "Name2", ...)
    name_list = ", ".join(f'"{n}"' for n in test_names)

    lines = [
        'importCpg("' + str(CPG_PATH) + '")',
        "",
        "val testClasses = List(" + name_list + ")",
        "",
        "testClasses.foreach { cls =>",
        '  println(s"=== ${cls} ===")',
        "",
        "  val sources = cpg.method",
        '    .filter(_.location.filename.contains(cls))',
        '    .call.name("' + CPG_SOURCE_METHODS + '").l',
        '  println(s"SOURCES=${sources.size}")',
        '  sources.foreach(c => println(s"  src L${c.lineNumber.getOrElse(-1)} ${c.name}: ${c.code.take(100)}"))',
        "",
        "  val sinks = cpg.method",
        '    .filter(_.location.filename.contains(cls))',
        '    .call.name("' + CPG_SINK_METHODS + '").l',
        '  println(s"SINKS=${sinks.size}")',
        '  sinks.foreach(c => println(s"  sink L${c.lineNumber.getOrElse(-1)} ${c.name}: ${c.code.take(100)}"))',
        "}",
    ]
    return "\n".join(lines)


def parse_joern_batch_output(stdout):
    """Parse the batch Joern output into {test_name: {sources: [...], sinks: [...]}}."""
    contexts = {}
    current  = None
    sources  = []
    sinks    = []
    in_sinks = False

    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue

        # Skip JVM / Joern boilerplate
        if any(line.startswith(p) for p in (
            "WARNING:", "[INFO", "executing ", "Creating ", "Project with",
            "Loading base", "Overlay ", "The graph has", "closing/saving",
        )):
            continue

        if line.startswith("=== ") and line.endswith(" ==="):
            # Save previous
            if current:
                contexts[current] = {"sources": sources, "sinks": sinks}
            current  = line[4:-4].strip()
            sources  = []
            sinks    = []
            in_sinks = False

        elif line.startswith("SOURCES="):
            in_sinks = False

        elif line.startswith("SINKS="):
            in_sinks = True

        elif line.startswith("src "):
            sources.append(line[4:])

        elif line.startswith("sink "):
            sinks.append(line[5:])

    if current:
        contexts[current] = {"sources": sources, "sinks": sinks}

    return contexts


def precompute_cpg_contexts(sample):
    """Run one Joern session for all 220 test cases. Returns context dict."""
    test_names = [tc["test"] for tc in sample]
    script     = build_joern_batch_script(test_names)

    with tempfile.NamedTemporaryFile(suffix=".sc", mode="w", delete=False) as f:
        f.write(script)
        script_path = f.name

    print(f"  Running Joern batch over {len(test_names)} test classes "
          f"(one JVM startup)...", flush=True)
    t0 = time.perf_counter()
    try:
        result = subprocess.run(
            [str(JOERN_BIN), "--script", script_path],
            capture_output=True, text=True, timeout=600, env=JOERN_ENV
        )
    finally:
        os.unlink(script_path)

    elapsed = time.perf_counter() - t0
    contexts = parse_joern_batch_output(result.stdout)
    print(f"  Done in {elapsed:.0f}s — got CPG context for {len(contexts)} test cases")

    if len(contexts) < len(test_names) * 0.9:
        print(f"  WARNING: expected ~{len(test_names)}, got {len(contexts)} — "
              "check Joern stderr below:")
        print(result.stderr[-500:] if result.stderr else "(no stderr)")

    return contexts


def load_cpg_cache():
    if CPG_CACHE.exists():
        with open(CPG_CACHE) as f:
            return json.load(f)
    return None


def format_cpg_context(context):
    """Format a single test's CPG data as readable text for prompt injection."""
    if not context:
        return "  (no CPG data — class not found in graph)"
    sources = context.get("sources", [])
    sinks   = context.get("sinks", [])
    lines   = []
    lines.append(f"HTTP Input Sources ({len(sources)}):")
    for s in sources:
        lines.append(f"  {s}")
    if not sources:
        lines.append("  (none found)")
    lines.append(f"Dangerous Sinks ({len(sinks)}):")
    for s in sinks:
        lines.append(f"  {s}")
    if not sinks:
        lines.append("  (none found)")
    return "\n".join(lines)

# ── TrailMark pre-computation ──────────────────────────────────────────────────

def precompute_trailmark_contexts(sample):
    """
    Parse the OWASP testcode directory with TrailMark, run preanalysis,
    and extract per-test-class call graphs, entrypoints, complexity, branches,
    and taint annotations. Returns dict {test_name: {...}}.
    """
    # We run in a subprocess using the venv Python so trailmark is importable
    script = '''
import json, sys
from trailmark.query.api import QueryEngine
from trailmark.models.edges import EdgeKind
from trailmark.models.annotations import AnnotationKind

test_names = json.loads(sys.argv[1])
engine = QueryEngine.from_directory(sys.argv[2], language="java")
pa = engine.preanalysis()
store = engine._store
graph = store._graph

contexts = {}
for test_name in test_names:
    class_id = f"{test_name}:{test_name}"
    if class_id not in graph.nodes:
        contexts[test_name] = None
        continue

    # Find methods in this class
    methods = {}
    for nid, node in graph.nodes.items():
        if node.kind.value == "method" and nid.startswith(class_id + "."):
            methods[nid] = node

    method_data = []
    for mid, method in methods.items():
        # Call edges from this method
        calls = []
        for e in graph.edges:
            if e.source_id == mid and e.kind == EdgeKind.CALLS:
                line = e.location.start_line if e.location else 0
                target = e.target_id.split(".")[-1] if "." in e.target_id else e.target_id
                # Also keep full target for context
                calls.append({
                    "line": line,
                    "target": e.target_id,
                    "short": target,
                })
        calls.sort(key=lambda c: c["line"])

        branches = []
        for b in method.branches:
            branches.append({
                "line": b.location.start_line,
                "condition": b.condition[:120] if b.condition else "",
            })

        # Annotations (taint, blast radius)
        anns = engine.annotations_of(mid)

        is_entrypoint = mid in graph.entrypoints
        ep_trust = graph.entrypoints[mid].trust_level.value if is_entrypoint else None

        method_data.append({
            "name": method.name,
            "complexity": method.cyclomatic_complexity,
            "entrypoint": is_entrypoint,
            "trust_level": ep_trust,
            "params": [(p.name, p.type_ref.name if p.type_ref else "?") for p in method.parameters],
            "calls": calls,
            "branches": branches,
            "annotations": [{"kind": a["kind"], "desc": a["description"]} for a in anns],
        })

    contexts[test_name] = {
        "methods": method_data,
        "preanalysis": {
            "tainted": pa["taint_propagation"]["tainted_nodes"],
            "blast_max": pa["blast_radius"]["max_radius"],
        },
    }

print(json.dumps(contexts))
'''
    test_names = [tc["test"] for tc in sample]
    print(f"  Running TrailMark over {len(test_names)} test classes...", flush=True)
    t0 = time.perf_counter()

    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        result = subprocess.run(
            [str(VENV_PYTHON), script_path,
             json.dumps(test_names), str(TESTCODE_DIR)],
            capture_output=True, text=True, timeout=120,
        )
    finally:
        os.unlink(script_path)

    elapsed = time.perf_counter() - t0

    if result.returncode != 0:
        print(f"  ERROR: TrailMark failed (exit {result.returncode})")
        print(result.stderr[-800:] if result.stderr else "(no stderr)")
        sys.exit(1)

    contexts = json.loads(result.stdout)
    print(f"  Done in {elapsed:.1f}s — got TrailMark context for {len(contexts)} test cases")
    return contexts


def load_tm_cache():
    if TM_CACHE.exists():
        with open(TM_CACHE) as f:
            return json.load(f)
    return None


def format_trailmark_context(context):
    """Format a single test's TrailMark data as readable text for prompt injection."""
    if not context:
        return "  (no TrailMark data — class not found in graph)"

    lines = []
    for m in context.get("methods", []):
        ep_str = f" [ENTRYPOINT: {m['trust_level']}]" if m.get("entrypoint") else ""
        lines.append(f"Method: {m['name']}  (complexity={m['complexity']}){ep_str}")
        if m.get("params"):
            lines.append(f"  Parameters: {', '.join(f'{n}: {t}' for n, t in m['params'])}")
        if m.get("calls"):
            lines.append(f"  Call graph ({len(m['calls'])} calls):")
            for c in m["calls"]:
                lines.append(f"    L{c['line']}: {c['target']}")
        else:
            lines.append("  Call graph: (no calls)")
        if m.get("branches"):
            lines.append(f"  Branch conditions ({len(m['branches'])}):")
            for b in m["branches"]:
                lines.append(f"    L{b['line']}: {b['condition']}")
        if m.get("annotations"):
            for a in m["annotations"]:
                lines.append(f"  [{a['kind']}] {a['desc']}")
    return "\n".join(lines)

# ── Stream-JSON parsing ─────────────────────────────────────────────────────────

def parse_stream(stdout_text):
    """
    Parse NDJSON from `claude -p --output-format stream-json --verbose`.
    Returns: (result_text, cost_usd, duration_ms, tokens_in, tokens_out,
              joern_calls, bash_outputs)
    """
    result_text  = ""
    cost_usd     = 0.0
    duration_ms  = 0
    tokens_in    = 0
    tokens_out   = 0
    joern_calls  = 0
    bash_outputs = []

    for line in stdout_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue

        ev_type = ev.get("type", "")

        if ev_type == "assistant":
            for block in ev.get("message", {}).get("content", []):
                if block.get("type") == "tool_use" and block.get("name") == "Bash":
                    cmd = block.get("input", {}).get("command", "")
                    if "joern" in cmd.lower():
                        joern_calls += 1

        if ev_type == "user":
            for block in ev.get("message", {}).get("content", []):
                if block.get("type") == "tool_result":
                    content = block.get("content", "")
                    if isinstance(content, list):
                        content = " ".join(
                            c.get("text", "") for c in content if isinstance(c, dict)
                        )
                    bash_outputs.append(str(content)[:500])

        if ev_type == "result":
            result_text = ev.get("result", "")
            if "hit your limit" in result_text.lower() or "rate limit" in result_text.lower():
                result_text = "RATE_LIMITED"
            cost_usd    = ev.get("total_cost_usd", 0.0)
            duration_ms = ev.get("duration_ms", 0)
            usage       = ev.get("usage", {})
            tokens_in   = (usage.get("input_tokens", 0)
                           + usage.get("cache_read_input_tokens", 0)
                           + usage.get("cache_creation_input_tokens", 0))
            tokens_out  = usage.get("output_tokens", 0)

    return result_text, cost_usd, duration_ms, tokens_in, tokens_out, joern_calls, bash_outputs


def extract_verdict(text, category):
    """Pull the JSON verdict out of the model's response text."""
    for pat in [r'\{[^{}]*"vulnerable"[^{}]*\}',
                r'\{[\s\S]*?"vulnerable"[\s\S]*?\}']:
        m = re.search(pat, text, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group())
                if "vulnerable" in obj:
                    return {
                        "vulnerable": bool(obj["vulnerable"]),
                        "category":   obj.get("category", category),
                        "confidence": float(obj.get("confidence", 0.5)),
                        "reasoning":  str(obj.get("reasoning", ""))[:500],
                    }
            except (json.JSONDecodeError, ValueError):
                continue

    lower = text.lower()
    vuln  = any(w in lower for w in
                ["vulnerable", "real vulnerability", "exploitable", "injection"])
    return {
        "vulnerable": vuln,
        "category":   category,
        "confidence": 0.4,
        "reasoning":  "(extracted from text — JSON not found in response)",
    }

# ── Claude CLI runner ───────────────────────────────────────────────────────────

def run_claude(prompt_text, system_prompt, allow_bash=False, timeout_secs=300):
    cmd = [
        CLAUDE_BIN, "-p",
        "--output-format", "stream-json",
        "--verbose",
        "--no-session-persistence",
        "--system-prompt", system_prompt,
    ]
    if allow_bash:
        cmd += ["--allowedTools", "Bash", "--dangerously-skip-permissions"]
    # No --allowedTools flag for Arm A / precomputed Arm B: system prompt
    # directs JSON-only output, model won't reach for tools unprompted.

    cmd.append(prompt_text)

    t0 = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_secs)
    except subprocess.TimeoutExpired:
        wall = int((time.perf_counter() - t0) * 1000)
        return "", 0.0, wall, 0, 0, 0, [], "TIMEOUT"

    wall_ms = int((time.perf_counter() - t0) * 1000)
    stderr  = proc.stderr.strip() if proc.stderr else ""
    result_text, cost_usd, duration_ms, tok_in, tok_out, joern_calls, bash_outputs = \
        parse_stream(proc.stdout)

    if not duration_ms:
        duration_ms = wall_ms

    return result_text, cost_usd, duration_ms, tok_in, tok_out, joern_calls, bash_outputs, stderr

# ── Arm runner ──────────────────────────────────────────────────────────────────

def run_arm(test_cases, arm_name, limit=None, cpg_contexts=None, tm_contexts=None, live=False):
    """
    cpg_contexts:  dict of {test_name: {sources, sinks}} for Arm B precomputed.
    tm_contexts:   dict of {test_name: {methods, ...}} for Arm C (TrailMark).
    live:          Arm B only — use live Joern via Bash tool.
    """
    cases = test_cases[:limit] if limit else test_cases

    if arm_name == "a":
        system    = SYSTEM_PROMPT_A
        allow_bash = False
        mode_label = "LLM-only"
    elif arm_name == "c":
        system    = SYSTEM_PROMPT_C
        allow_bash = False
        mode_label = "LLM + TrailMark (precomputed)"
    elif live:
        system    = SYSTEM_PROMPT_B_LIVE
        allow_bash = True
        mode_label = "LLM + Joern (live)"
    else:
        system    = SYSTEM_PROMPT_B_PRECOMPUTED
        allow_bash = False
        mode_label = "LLM + CPG (precomputed)"

    print(f"\n{'='*60}")
    print(f"ARM {arm_name.upper()}: {len(cases)} test cases  ({mode_label})")
    print(f"{'='*60}")

    results = []
    for i, tc in enumerate(cases, 1):
        test_name = tc["test"]
        category  = tc["category"]
        label     = "VULN" if tc["real"] else "SAFE"
        print(f"  [{i:3d}/{len(cases)}] {test_name} ({category}, {label})", end="", flush=True)

        source_code = read_source(test_name)
        prompt = f"Analyse this Java servlet test case ({test_name}):\n\n```java\n{source_code}\n```"

        # Inject pre-computed context for Arm B (Joern CPG) or Arm C (TrailMark)
        if arm_name == "b" and not live and cpg_contexts is not None:
            ctx_str = format_cpg_context(cpg_contexts.get(test_name))
            prompt += f"\n\n---\nCPG Structural Analysis:\n{ctx_str}"
        elif arm_name == "c" and tm_contexts is not None:
            ctx_str = format_trailmark_context(tm_contexts.get(test_name))
            prompt += f"\n\n---\nTrailMark Call-Graph Analysis:\n{ctx_str}"

        result_text, cost_usd, duration_ms, tok_in, tok_out, joern_calls, bash_outputs, stderr = \
            run_claude(prompt, system, allow_bash=allow_bash)

        if result_text == "RATE_LIMITED":
            print(" → RATE LIMITED — skipping")
            results.append({
                "test": test_name, "category": category,
                "ground_truth": tc["real"], "cwe": tc["cwe"],
                "verdict": None, "correct": None,
                "wall_time_sec": round(duration_ms / 1000, 2),
                "cost_usd": 0.0, "tokens_in": 0, "tokens_out": 0,
                "tokens_total": 0, "joern_calls": 0,
                "raw_response": "RATE_LIMITED", "stderr": "",
                "mode": mode_label,
            })
            continue

        verdict = extract_verdict(result_text, category)
        correct = verdict["vulnerable"] == tc["real"]
        mark    = "✓" if correct else "✗"
        j_str   = f", {joern_calls} joern" if joern_calls else ""
        print(f" → {'VULN' if verdict['vulnerable'] else 'SAFE'} {mark} "
              f"({duration_ms/1000:.1f}s, ${cost_usd:.4f}{j_str})")

        results.append({
            "test":          test_name,
            "category":      category,
            "ground_truth":  tc["real"],
            "cwe":           tc["cwe"],
            "verdict":       verdict,
            "correct":       correct,
            "wall_time_sec": round(duration_ms / 1000, 2),
            "cost_usd":      round(cost_usd, 6),
            "tokens_in":     tok_in,
            "tokens_out":    tok_out,
            "tokens_total":  tok_in + tok_out,
            "joern_calls":   joern_calls,
            "raw_response":  result_text[:800],
            "stderr":        stderr[:200] if stderr else "",
            "mode":          mode_label,
        })

    return results

# ── Main ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LLM vs LLM+Joern benchmark")
    parser.add_argument("--dry-run",    action="store_true",
                        help="Validate paths and show sample — no calls")
    parser.add_argument("--precompute", action="store_true",
                        help="Run Joern batch to build CPG cache, then exit")
    parser.add_argument("--arm",        choices=["a", "b", "c"], default=None,
                        help="Run only one arm (default: a+b)")
    parser.add_argument("--live",       action="store_true",
                        help="Arm B: use live Joern via Bash tool (slow, agentic)")
    parser.add_argument("--limit",      type=int, default=None,
                        help="Limit to N test cases per arm (smoke testing)")
    parser.add_argument("--resume",     action="store_true",
                        help="Re-run only rate-limited entries from previous run, merge back")
    args = parser.parse_args()

    # Validate paths
    claude_path = subprocess.run(["which", CLAUDE_BIN],
                                 capture_output=True, text=True).stdout.strip()
    checks = [
        ("Ground truth",  GROUND_TRUTH,  True),
        ("Test code dir", TESTCODE_DIR,  True),
        ("claude CLI",    Path(claude_path) if claude_path else Path("not-found"), True),
        ("CPG binary",    CPG_PATH,      args.arm in (None, "b")),
        ("Joern binary",  JOERN_BIN,     args.arm in (None, "b")),
        ("Venv Python",   VENV_PYTHON,   args.arm in (None, "c")),
    ]
    all_ok = True
    for label, path, required in checks:
        ok     = path.exists()
        status = "✓" if ok else ("✗ MISSING" if required else "- (not needed)")
        print(f"  {label}: {path} [{status}]")
        if not ok and required:
            all_ok = False
    print()

    if not all_ok:
        print("ERROR: Missing required files.", file=sys.stderr)
        sys.exit(1)

    truth  = load_ground_truth()
    sample = stratified_sample(truth)

    print(f"Sample: {len(sample)} test cases across {len(CATEGORIES)} categories")
    by_cat = {}
    for tc in sample:
        by_cat.setdefault(tc["category"], {"true": 0, "false": 0})
        by_cat[tc["category"]]["true" if tc["real"] else "false"] += 1
    for cat in CATEGORIES:
        c = by_cat.get(cat, {})
        print(f"  {cat:15s}: {c.get('true',0)} true, {c.get('false',0)} false")

    if args.dry_run:
        print("\nDry run complete — no calls made.")
        return

    RESULTS_DIR.mkdir(exist_ok=True)

    # ── Pre-compute contexts ────────────────────────────────────────────────
    cpg_contexts = None
    tm_contexts  = None

    # Joern CPG: needed for arm B (precomputed mode), not for --arm c
    need_cpg = ((args.precompute and args.arm in (None, "b"))
                or (args.arm in (None, "b") and not args.live))
    if need_cpg:
        if CPG_CACHE.exists() and not args.precompute:
            print(f"\nLoading cached CPG contexts from {CPG_CACHE}")
            cpg_contexts = load_cpg_cache()
            print(f"  Loaded {len(cpg_contexts)} entries")
        else:
            print("\nPre-computing CPG contexts (single Joern session)...")
            cpg_contexts = precompute_cpg_contexts(sample)
            with open(CPG_CACHE, "w") as f:
                json.dump(cpg_contexts, f, indent=2)
            print(f"  Cached to {CPG_CACHE}")

    # TrailMark: needed for arm C
    need_tm = ((args.precompute and args.arm in (None, "c"))
               or args.arm == "c")
    if need_tm:
        if TM_CACHE.exists() and not args.precompute:
            print(f"\nLoading cached TrailMark contexts from {TM_CACHE}")
            tm_contexts = load_tm_cache()
            print(f"  Loaded {len(tm_contexts)} entries")
        else:
            print("\nPre-computing TrailMark contexts (tree-sitter parse)...")
            tm_contexts = precompute_trailmark_contexts(sample)
            with open(TM_CACHE, "w") as f:
                json.dump(tm_contexts, f, indent=2)
            print(f"  Cached to {TM_CACHE}")

    if args.precompute:
        print("Done — run without --precompute to start the benchmark.")
        return

    # ── Resume mode: re-run only rate-limited entries ─────────────────────
    if args.resume:
        arm = args.arm or "b"
        out_path = RESULTS_DIR / f"arm_{arm}_results.json"
        if not out_path.exists():
            print(f"ERROR: {out_path} not found — nothing to resume.", file=sys.stderr)
            sys.exit(1)

        with open(out_path) as f:
            data = json.load(f)
        prev_results = data["results"]

        # Find rate-limited entries
        limited_tests = {r["test"] for r in prev_results if r.get("correct") is None}
        if not limited_tests:
            print(f"No rate-limited entries in {out_path} — nothing to resume.")
            return

        # Build test cases for just the rate-limited ones (preserving original order)
        retry_cases = [tc for tc in sample if tc["test"] in limited_tests]
        print(f"\nResuming: {len(retry_cases)} rate-limited entries from {out_path}")

        new_results = run_arm(
            retry_cases, arm,
            limit        = args.limit,
            cpg_contexts = cpg_contexts if arm == "b" else None,
            tm_contexts  = tm_contexts if arm == "c" else None,
            live         = args.live if arm == "b" else False,
        )

        # Merge: replace rate-limited entries with new results
        new_by_test = {r["test"]: r for r in new_results}
        merged = []
        for r in prev_results:
            if r["test"] in new_by_test:
                merged.append(new_by_test[r["test"]])
            else:
                merged.append(r)

        with open(out_path, "w") as f:
            json.dump({
                "arm":       arm,
                "mode":      merged[0]["mode"] if merged else "unknown",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "seed":      SEED,
                "results":   merged,
            }, f, indent=2)
        print(f"\n  Merged → {out_path}")

        valid   = [r for r in merged if r["correct"] is not None]
        correct = sum(r["correct"] for r in valid)
        n_valid = len(valid)
        cost    = sum(r["cost_usd"] for r in merged)
        skipped = len(merged) - n_valid

        pct = f"{100*correct/n_valid:.1f}%" if n_valid else "n/a"
        print(f"  Arm {arm.upper()}: {correct}/{n_valid} correct ({pct}),  "
              f"${cost:.3f} total"
              + (f",  {skipped} still rate-limited" if skipped else ""))
        print("\nDone. Run:  python analyze.py")
        return

    # ── Run arms ─────────────────────────────────────────────────────────────
    arms_to_run = ["a", "b"] if args.arm is None else [args.arm]

    for arm in arms_to_run:
        results = run_arm(
            sample, arm,
            limit       = args.limit,
            cpg_contexts= cpg_contexts if arm == "b" else None,
            tm_contexts = tm_contexts if arm == "c" else None,
            live        = args.live if arm == "b" else False,
        )

        out_path = RESULTS_DIR / f"arm_{arm}_results.json"
        with open(out_path, "w") as f:
            json.dump({
                "arm":       arm,
                "mode":      results[0]["mode"] if results else "unknown",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "seed":      SEED,
                "results":   results,
            }, f, indent=2)
        print(f"\n  Saved → {out_path}")

        valid   = [r for r in results if r["correct"] is not None]
        correct = sum(r["correct"] for r in valid)
        n_valid = len(valid)
        cost    = sum(r["cost_usd"] for r in results)
        secs    = sum(r["wall_time_sec"] for r in results)
        joern   = sum(r["joern_calls"] for r in results)
        skipped = len(results) - n_valid

        pct = f"{100*correct/n_valid:.1f}%" if n_valid else "n/a"
        print(f"  Arm {arm.upper()}: {correct}/{n_valid} correct ({pct}),  "
              f"${cost:.3f} total,  {secs:.0f}s wall time"
              + (f",  {joern} joern calls" if arm == "b" and joern else "")
              + (f",  {skipped} skipped (rate limited)" if skipped else ""))

    print("\nDone. Run:  python analyze.py")


if __name__ == "__main__":
    main()
