# Total Security SAST

STEP 1 provides Java source parsing and concrete syntax tree inspection. STEP 2 adds a Java-specific semantic extractor and a Tree-sitter-independent Java IR. STEP 2B adds an ordered statement hierarchy to method bodies. STEP 3 builds method-level control-flow graphs from that IR without accessing Tree-sitter nodes. It uses Tree-sitter with the official Java grammar packaged for the Java binding.

The extractor currently preserves package/import declarations, classes, interfaces, methods, constructors, parameters, fields, local variables, assignments, method calls, returns, and annotations. Expressions are represented structurally as variable references, literals, binary and assignment expressions, method calls, object creation, field access, parenthesized expressions, or explicit unknown expressions.

Concrete method and constructor bodies contain ordered `Statement` IR. The current statement variants are blocks, variable declarations, expression statements, returns, if/else, while, do-while, classic for, enhanced for, switch cases, break, continue, throw, and explicit unknown statements. Every statement retains a `SourceLocation`.

The IR does not assign Spring or security meaning to annotations or API names.

## Method-level CFG

`ControlFlowGraphBuilder` groups consecutive straight-line statements into basic blocks and splits at branch, loop, switch, and terminating control transfers. Graph edges distinguish normal flow, true/false branches, loop back-edges, break, continue, return, throw, and switch case/default dispatch. Nested loop and switch targets are resolved with an explicit control-context stack.

The CFG currently supports ordered blocks, if/else, while, do-while, classic for, an abstract enhanced-for iteration model, colon-style switch fall-through, break, continue, return, and throw-to-method-exit. `UnknownStatement` is retained sequentially and reported through `unsupportedControlFlow`; it is not treated as fully supported.

Switch arrow-rule value/yield semantics, labeled break/continue, precise try/catch/finally exception flow, and exceptions thrown by called methods are not fully modeled. Data flow, reaching definitions, worklists/fixpoints, taint analysis, call graphs, type resolution, vulnerability rules, and pattern analysis are not implemented.

## Requirements

- JDK 25 or newer

## Build and test

On Windows:

```powershell
.\gradlew.bat clean build
```

On Linux or macOS:

```shell
./gradlew clean build
```

## Print a Java syntax tree

```powershell
.\gradlew.bat run --args="src/test/resources/fixtures/SampleController.java"
```

Raw syntax-tree printer positions are zero-based and use Tree-sitter's `row:column` representation. Source text is printed for named leaf nodes and truncated when it is long.

IR `SourceLocation` positions are consistently **1-based** for lines and columns. Columns are Tree-sitter UTF-8 byte columns converted from zero-based to one-based; they are not UTF-16 character indexes.
