# CPGQL Query Patterns

Ready-to-use query templates for common code investigation tasks. Replace placeholder names with actual targets.

## Call Graph Analysis

### Find all callers of a function
```scala
cpg.method.name("targetFunction").caller.map(m =>
  s"${m.name} at ${m.file.name.headOption.getOrElse("?")}:${m.lineNumber.getOrElse("?")}"
).l
```

### Find all functions called by a function
```scala
cpg.method.name("targetFunction").callee.filterNot(_.isExternal).map(m =>
  s"${m.name} at ${m.file.name.headOption.getOrElse("?")}:${m.lineNumber.getOrElse("?")}"
).l
```

### Find call sites of a function (with arguments)
```scala
cpg.call.name("targetFunction").map(c =>
  s"${c.file.name.head}:${c.lineNumber.getOrElse("?")} | ${c.code}"
).l
```

### Build a call chain (who calls who calls who)
```scala
cpg.method.name("entryPoint").repeat(_.callee)(_.maxDepth(3)).dedup.name.l
```

## Data Flow / Taint Analysis

### Check if input reaches a dangerous sink
```scala
val source = cpg.call.name("recv|read|fgets|scanf|getenv|getParameter").argument
val sink = cpg.call.name("system|exec|popen|eval|query").argument
sink.reachableBy(source).map(s =>
  s"TAINT: ${s.file.name.head}:${s.lineNumber.getOrElse("?")} | ${s.code}"
).l
```

### Full taint flow paths (detailed)
```scala
val source = cpg.call.name("getenv").argument
val sink = cpg.call.name("system").argument
sink.reachableByFlows(source).p
```

### Track a specific parameter through a function
```scala
val param = cpg.method.name("processRequest").parameter.name("userInput")
val calls = cpg.method.name("processRequest").call
calls.reachableBy(param).map(c => s"${c.name}: ${c.code}").l
```

## Vulnerability Patterns

### Command injection
```scala
val userInput = cpg.call.name("getenv|getParameter|readline|input|argv").argument
val cmdExec = cpg.call.name("system|exec|popen|Runtime.exec|os.system|subprocess.call").argument
cmdExec.reachableBy(userInput).location.l
```

### SQL injection
```scala
val userInput = cpg.call.name("getParameter|request.get|readline|input").argument
val sqlCall = cpg.call.name("execute|query|raw|executeQuery|cursor.execute").argument
sqlCall.reachableBy(userInput).location.l
```

### Buffer overflow (C/C++)
```scala
// Calls to unsafe string functions
cpg.call.name("strcpy|strcat|sprintf|gets").map(c =>
  s"UNSAFE: ${c.file.name.head}:${c.lineNumber.getOrElse("?")} | ${c.code}"
).l
```

### Unchecked malloc return
```scala
// malloc calls whose return value is used without null check
cpg.call.name("malloc").whereNot(
  _.inAst.isControlStructure.code(".*NULL.*|.*!.*")
).map(c =>
  s"${c.file.name.head}:${c.lineNumber.getOrElse("?")} | ${c.code}"
).l
```

### Use after free
```scala
// Find free() calls and check if the same variable is used afterward
cpg.call.name("free").argument(1).map(a =>
  (a.code, a.file.name.head, a.lineNumber)
).l
```

## Code Structure Analysis

### List all methods in a file
```scala
cpg.method.file.nameExact("path/to/file.c").method
  .filterNot(_.isExternal)
  .map(m => s"${m.name} (line ${m.lineNumber.getOrElse("?")})")
  .l
```

### Find methods with too many parameters
```scala
cpg.method.filter(_.parameter.size > 5).map(m =>
  s"${m.name}: ${m.parameter.size} params | ${m.file.name.headOption.getOrElse("?")}"
).l
```

### Find long methods (by line count)
```scala
cpg.method.filterNot(_.isExternal).filter { m =>
  val start = m.lineNumber.getOrElse(0)
  val end = m.lineNumberEnd.getOrElse(0)
  (end - start) > 100
}.map(m =>
  s"${m.name}: ${m.lineNumberEnd.getOrElse(0) - m.lineNumber.getOrElse(0)} lines | ${m.file.name.headOption.getOrElse("?")}"
).l
```

### Find unused/dead methods
```scala
cpg.method.filterNot(_.isExternal)
  .filter(_.caller.size == 0)
  .filterNot(_.name.matches("main|init|setup|constructor"))
  .map(m => s"${m.name} at ${m.file.name.headOption.getOrElse("?")}:${m.lineNumber.getOrElse("?")}")
  .l
```

### Find all classes/types and their members
```scala
cpg.typeDecl.filterNot(_.isExternal).map(t =>
  s"${t.name}: ${t.member.name.l.mkString(", ")}"
).l
```

## Search and Navigation

### Find methods by regex
```scala
cpg.method.name(".*[Aa]uth.*").filterNot(_.isExternal).map(m =>
  s"${m.name} at ${m.file.name.headOption.getOrElse("?")}:${m.lineNumber.getOrElse("?")}"
).l
```

### Find all string literals matching a pattern
```scala
cpg.literal.code("\".*password.*\"").map(l =>
  s"${l.file.name.head}:${l.lineNumber.getOrElse("?")} | ${l.code}"
).l
```

### Find all TODO/FIXME comments
```scala
cpg.comment.code(".*TODO|FIXME|HACK|XXX.*").map(c =>
  s"${c.file.name.head}:${c.lineNumber.getOrElse("?")} | ${c.code.take(80)}"
).l
```

### Find all error handling (try/catch/if-error patterns)
```scala
cpg.controlStructure.controlStructureType("TRY").map(cs =>
  s"${cs.file.name.head}:${cs.lineNumber.getOrElse("?")} | ${cs.code.take(60)}"
).l
```

## Dependency Analysis

### Find all external library calls
```scala
cpg.call.callee.isExternal(true).name.dedup.sorted.l
```

### Find which internal methods use a specific library function
```scala
cpg.call.name("libraryFunction").method.filterNot(_.isExternal).map(m =>
  s"${m.name} at ${m.file.name.headOption.getOrElse("?")}"
).dedup.l
```

## Tips for Composing Queries

1. **Start broad, narrow down**: Begin with `cpg.method.name.l` to verify the CPG loads, then add filters.
2. **Combine in one script**: Put multiple `println("=== SECTION ===")` blocks in one `.sc` file to avoid repeated JVM startup.
3. **Use `.map` for readable output**: Transform nodes into strings with file/line info rather than dumping raw objects.
4. **Filter early**: Place `.name("pattern")` and `.where()` as early as possible in the chain to reduce traversal size.
5. **Use `.dedup`**: Many traversals produce duplicates — dedup before output.
