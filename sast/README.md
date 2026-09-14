# Total Security SAST

STEP 1 provides Java source parsing and concrete syntax tree inspection. STEP 2 adds a Java-specific semantic extractor and a Tree-sitter-independent Java IR. STEP 2B adds an ordered statement hierarchy to method bodies. STEP 3 builds method-level control-flow graphs from that IR without accessing Tree-sitter nodes. STEP 4 adds intraprocedural flow-sensitive reaching-definitions analysis over the IR and CFG. STEP 5 adds intraprocedural flow-sensitive taint propagation over those reaching definitions. Java parsing uses Tree-sitter with the official Java grammar packaged for the Java binding.

The extractor currently preserves package/import declarations, classes, interfaces, methods, constructors, parameters, fields, local variables, assignments, method calls, returns, and annotations. Expressions are represented structurally as variable references, literals, binary and assignment expressions, method calls, object creation, field access, parenthesized expressions, or explicit unknown expressions.

Concrete method and constructor bodies contain ordered `Statement` IR. The current statement variants are blocks, variable declarations, expression statements, returns, if/else, while, do-while, classic for, enhanced for, switch cases, break, continue, throw, and explicit unknown statements. Every statement retains a `SourceLocation`.

The IR does not assign Spring or security meaning to annotations or API names.

## Method-level CFG

`ControlFlowGraphBuilder` groups consecutive straight-line statements into basic blocks and splits at branch, loop, switch, and terminating control transfers. Graph edges distinguish normal flow, true/false branches, loop back-edges, break, continue, return, throw, and switch case/default dispatch. Nested loop and switch targets are resolved with an explicit control-context stack.

The CFG currently supports ordered blocks, if/else, while, do-while, classic for, an abstract enhanced-for iteration model, colon-style switch fall-through, break, continue, return, and throw-to-method-exit. `UnknownStatement` is retained sequentially and reported through `unsupportedControlFlow`; it is not treated as fully supported.

Switch arrow-rule value/yield semantics, labeled break/continue, precise try/catch/finally exception flow, and exceptions thrown by called methods are not fully modeled. Call graphs, type resolution, vulnerability rules, and pattern analysis are not implemented.

## Intraprocedural data flow

`ReachingDefinitionsAnalysis` uses only `MethodInfo`, ordered Statement/Expression IR, and `ControlFlowGraph`. It computes immutable `IN` and `OUT` states for reachable basic blocks with a worklist until state equality reaches a fixpoint. Predecessor states are joined by union; a parameter, initialized local declaration, or assignment generates a stable `Definition`, and a new definition kills older definitions of the same `VariableSymbol` on that path.

Variable identity is based on a parameter or local declaration's name, kind, declared type, and source location rather than name alone. Resolution is limited to references that can be linked through the method's lexical scopes. Results retain statement-before states and resolved use sites so callers can query which definitions reach a specific `VariableReference`, including uses nested in supported binary, assignment, method-call, object-creation, field-target, and parenthesized expressions. Unknown expression source text is never searched to guess uses.

The reaching-definitions layer does not perform Java type resolution, alias or points-to analysis, heap identity, field-sensitive analysis, interprocedural flow, or security rule evaluation. Arbitrary field assignments remain unsupported. Compound assignment records a local read and replacement definition but does not interpret the operator's value semantics. Enhanced-for iterable uses are analyzed, but the per-iteration element definition is reported as unsupported because the current CFG does not expose that true-edge assignment separately. Unresolved references and other unsupported inputs are retained explicitly in the result.

## Intraprocedural taint propagation

`IntraproceduralTaintAnalysis` accepts a `DataFlowResult` and explicit definition or expression seeds supplied by its caller. It does not infer sources from annotations or API names. The finite may-taint lattice is `CLEAN < UNKNOWN < TAINTED`; a tainted predecessor therefore dominates clean and unknown alternatives at a merge. Definition dependencies are reevaluated with a worklist only when an upstream value changes, and stable STEP 4 definition identities ensure loop dependencies reach a fixpoint.

Variable references join the taint of their reaching definitions. Literals are clean, binary operands are joined, and parenthesized expressions forward their inner value. Receiver and argument taint are retained separately for method calls. Without an explicit expression seed or propagation model, arbitrary method-call returns, constructed objects, field values, unresolved references, and unknown expressions are `UNKNOWN`; their source text is not searched to infer taint.

Results expose definition, expression, variable-use, method receiver, and argument taint. A finite static provenance graph links external seeds, definitions, use sites, and supported expression steps, preserving multiple seed origins and representing loop cycles without growing an iteration-specific trace. Framework source/sink/sanitizer rules, vulnerability decisions, interprocedural taint, call graphs, alias/points-to analysis, heap-sensitive analysis, and complete field-sensitive analysis are not implemented in STEP 5.

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
