# CPGQL Reference

CPGQL (Code Property Graph Query Language) is a Scala-based DSL for traversing Joern CPGs. All queries start from the `cpg` object and chain traversal steps.

## Query Structure

```
cpg.<node-type>.<traversal-steps>.<filters>.<output>
```

Every query must end with an execution step (`.l`, `.toList`, `.size`, `.head`, etc.) — traversals are lazy.

## Node Types (Starting Points)

| Step | Description |
|------|-------------|
| `cpg.method` | All methods/functions |
| `cpg.call` | All call sites (function invocations) |
| `cpg.parameter` | All method parameters |
| `cpg.local` | All local variables |
| `cpg.identifier` | All identifier usages |
| `cpg.literal` | All literal values (strings, numbers) |
| `cpg.typeDecl` | All type/class declarations |
| `cpg.member` | All class/struct members |
| `cpg.fieldAccess` | All field access expressions |
| `cpg.controlStructure` | All if/for/while/switch statements |
| `cpg.comment` | All comments |
| `cpg.file` | All source files |
| `cpg.namespace` | All namespaces/packages |
| `cpg.methodReturn` | All method return nodes |
| `cpg.ret` | All return statements |
| `cpg.argument` | All call arguments |

## Property Access

| Property | Description |
|----------|-------------|
| `.name` | Name of the node |
| `.fullName` | Fully qualified name |
| `.code` | Source code text |
| `.lineNumber` | Line number in source file |
| `.columnNumber` | Column number |
| `.typeFullName` | Full type name |
| `.signature` | Method signature |
| `.order` | Argument position (1-based for arguments) |
| `.file.name` | Source file path |

## Navigation Steps

### Call Graph

| Step | Description |
|------|-------------|
| `.caller` | Methods that call this method |
| `.callee` | Methods called by this method |
| `.call` | Call sites within a method |
| `.argument` | Arguments of a call |
| `.parameter` | Parameters of a method |
| `.methodReturn` | Return type node of a method |

### AST Navigation

| Step | Description |
|------|-------------|
| `.astChildren` | Direct AST children |
| `.astParent` | AST parent node |
| `.astSiblings` | AST siblings |
| `.isCallTo(name)` | Filter to calls matching name |
| `.depth(_.isCall)` | Depth of matching descendant |

### Control Flow Graph

| Step | Description |
|------|-------------|
| `.cfgNext` | Next nodes in control flow |
| `.cfgPrev` | Previous nodes in control flow |

### Program Dependence Graph

| Step | Description |
|------|-------------|
| `.reachableBy(source)` | Nodes reachable via data flow from source |
| `.reachableByFlows(source)` | Full flow paths from source to this node |

## Filter Steps

### Property Filters

```scala
cpg.method.name("main")                    // Exact match
cpg.method.name("get.*")                   // Regex match
cpg.method.nameExact("main")               // Strict exact match (no regex)
cpg.call.name("malloc|free|realloc")       // Alternation
cpg.method.name("(?i)process.*")           // Case-insensitive regex

cpg.literal.typeFullName(".*String.*")     // Filter by type
cpg.method.signature(".*int.*")            // Filter by signature
cpg.method.file.nameExact("main.c")       // Filter by file
cpg.call.lineNumber(42)                    // Filter by line
```

### Boolean Filters

```scala
cpg.method.isExternal(false)               // Only internal methods
cpg.method.isExternal(true)                // Only external/library methods
```

### Lambda Filters

```scala
cpg.method.filter(_.parameter.size > 5)             // Methods with 6+ params
cpg.call.filter(_.argument.size > 3)                 // Calls with 4+ arguments
cpg.method.filter(_.name.startsWith("test"))         // Custom predicate
```

### Where / WhereNot

```scala
// Methods that contain a call to "malloc"
cpg.method.where(_.call.name("malloc"))

// Methods that do NOT call "free"
cpg.method.whereNot(_.call.name("free"))

// Calls to "system" where any argument contains user input
cpg.call.name("system").where(_.argument.code(".*argv.*"))
```

### Combining Filters

```scala
cpg.method
  .name("process.*")
  .file.nameExact("handler.c")
  .method                                    // Navigate back to method
  .where(_.call.name("malloc"))
  .name.l
```

## Data Flow Analysis

### Basic Reachability

```scala
// Define sources and sinks
val source = cpg.method.name("readInput").methodReturn
val sink = cpg.call.name("exec").argument

// Check if data flows from source to sink
sink.reachableBy(source).l

// Get full flow paths
sink.reachableByFlows(source).p
```

### Taint Tracking Patterns

```scala
// User input to dangerous function
val userInput = cpg.call.name("recv|read|fgets|scanf|getenv").argument
val dangerousSink = cpg.call.name("system|exec|popen|eval").argument
dangerousSink.reachableBy(userInput).l

// Parameter to return value (what does a function do with its input?)
val param = cpg.method.name("processData").parameter
val ret = cpg.method.name("processData").methodReturn
ret.reachableBy(param).l
```

## Output / Execution Steps

| Step | Description |
|------|-------------|
| `.l` / `.toList` | Execute and return as List |
| `.size` | Count of results |
| `.head` | First result (throws if empty) |
| `.headOption` | First result as Option |
| `.toSet` | Results as Set (deduplicated) |
| `.p` | Pretty-print with source context |
| `.toJson` | Results as JSON string |
| `.toJsonPretty` | Pretty-printed JSON |

### Output to File

```scala
cpg.method.name.l #> "/tmp/methods.txt"        // Write (overwrite)
cpg.method.name.l #>> "/tmp/methods.txt"       // Append
```

## Map and Transform

```scala
// Extract specific fields as tuples
cpg.method.map(m => (m.name, m.file.name.headOption, m.lineNumber)).l

// Custom formatting
cpg.call.name("malloc").map(c =>
  s"${c.file.name.head}:${c.lineNumber.getOrElse("?")} - ${c.code}"
).l
```

## Deduplication

```scala
cpg.call.name("printf").code.dedup.l           // Unique code strings
cpg.method.caller.dedup.name.l                 // Unique callers
```

## Location Info

```scala
// Get full location details for any node
cpg.call.name("system").location.l

// Location includes: filename, lineNumber, methodFullName, nodeLabel
cpg.method.name("vulnerable").location.map(l =>
  s"${l.filename}:${l.lineNumber}"
).l
```

## Common Gotchas

1. **Lazy evaluation**: `cpg.method.name` returns a traversal, not results. You must end with `.l` or similar.
2. **`.name` vs `.name("x")`**: Without an argument, `.name` accesses the property. With an argument, it filters.
3. **Regex by default**: `.name("foo.*")` uses regex. Use `.nameExact("foo")` for literal match.
4. **Navigation resets**: After filtering through a relationship (e.g., `.file.nameExact("x")`), you're now on file nodes. Use `.method` to navigate back.
5. **`cpg.function` doesn't exist**: Use `cpg.method` for all functions/methods.
6. **External methods**: Library/system calls are "external" methods — use `.isExternal(false)` to exclude them.
