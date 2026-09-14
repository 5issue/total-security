# Total Security SAST

STEP 1 provides Java source parsing and concrete syntax tree inspection. STEP 2 adds a Java-specific semantic extractor and a Tree-sitter-independent Java IR. STEP 2B adds an ordered statement hierarchy to method bodies. STEP 3 builds method-level control-flow graphs from that IR without accessing Tree-sitter nodes. STEP 4 adds intraprocedural flow-sensitive reaching-definitions analysis over the IR and CFG. STEP 5 adds intraprocedural flow-sensitive taint propagation over those reaching definitions. STEP 6 adds Java/Spring rule matching and injectable method-call taint semantics without creating vulnerability findings. STEP 6B makes model precedence explicit and provides rule-aware taint orchestration. Java parsing uses Tree-sitter with the official Java grammar packaged for the Java binding.

The extractor currently preserves package/import declarations, classes, interfaces, methods, constructors, parameters, fields, local variables, assignments, method calls, returns, and annotations. Expressions are represented structurally as variable references, literals, binary and assignment expressions, method calls, object creation, field access, parenthesized expressions, or explicit unknown expressions.

Concrete method and constructor bodies contain ordered `Statement` IR. The current statement variants are blocks, variable declarations, expression statements, returns, if/else, while, do-while, classic for, enhanced for, switch cases, break, continue, throw, and explicit unknown statements. Every statement retains a `SourceLocation`.

The IR does not assign Spring or security meaning to annotations or API names.

## Method-level CFG

`ControlFlowGraphBuilder` groups consecutive straight-line statements into basic blocks and splits at branch, loop, switch, and terminating control transfers. Graph edges distinguish normal flow, true/false branches, loop back-edges, break, continue, return, throw, and switch case/default dispatch. Nested loop and switch targets are resolved with an explicit control-context stack.

The CFG currently supports ordered blocks, if/else, while, do-while, classic for, an abstract enhanced-for iteration model, colon-style switch fall-through, break, continue, return, and throw-to-method-exit. `UnknownStatement` is retained sequentially and reported through `unsupportedControlFlow`; it is not treated as fully supported.

Switch arrow-rule value/yield semantics, labeled break/continue, precise try/catch/finally exception flow, and exceptions thrown by called methods are not fully modeled. Call graphs, complete type resolution, vulnerability Finding generation, and pattern analysis are not implemented.

## Intraprocedural data flow

`ReachingDefinitionsAnalysis` uses only `MethodInfo`, ordered Statement/Expression IR, and `ControlFlowGraph`. It computes immutable `IN` and `OUT` states for reachable basic blocks with a worklist until state equality reaches a fixpoint. Predecessor states are joined by union; a parameter, initialized local declaration, or assignment generates a stable `Definition`, and a new definition kills older definitions of the same `VariableSymbol` on that path.

Variable identity is based on a parameter or local declaration's name, kind, declared type, and source location rather than name alone. Resolution is limited to references that can be linked through the method's lexical scopes. Results retain statement-before states and resolved use sites so callers can query which definitions reach a specific `VariableReference`, including uses nested in supported binary, assignment, method-call, object-creation, field-target, and parenthesized expressions. Unknown expression source text is never searched to guess uses.

The reaching-definitions layer does not perform Java type resolution, alias or points-to analysis, heap identity, field-sensitive analysis, interprocedural flow, or security rule evaluation. Arbitrary field assignments remain unsupported. Compound assignment records a local read and replacement definition but does not interpret the operator's value semantics. Enhanced-for iterable uses are analyzed, but the per-iteration element definition is reported as unsupported because the current CFG does not expose that true-edge assignment separately. Unresolved references and other unsupported inputs are retained explicitly in the result.

## Intraprocedural taint propagation

`IntraproceduralTaintAnalysis` accepts a `DataFlowResult` and explicit definition or expression seeds supplied by its caller. It does not infer sources from annotations or API names. The finite may-taint lattice is `CLEAN < UNKNOWN < TAINTED`; a tainted predecessor therefore dominates clean and unknown alternatives at a merge. Definition dependencies are reevaluated with a worklist only when an upstream value changes, and stable STEP 4 definition identities ensure loop dependencies reach a fixpoint.

Variable references join the taint of their reaching definitions. Literals are clean, binary operands are joined, and parenthesized expressions forward their inner value. Receiver and argument taint are retained separately for method calls. Without an explicit expression seed or injected propagation model, arbitrary method-call returns, constructed objects, field values, unresolved references, and unknown expressions are `UNKNOWN`; their source text is not searched to infer taint.

Results expose definition, expression, variable-use, method receiver, and argument taint. A finite static provenance graph links external seeds, definitions, use sites, and supported expression steps, preserving multiple seed origins and representing loop cycles without growing an iteration-specific trace. The STEP 5 core does not infer framework meaning; STEP 6 supplies explicit seeds and method semantics. Vulnerability decisions, interprocedural taint, call graphs, alias/points-to analysis, heap-sensitive analysis, and complete field-sensitive analysis remain unsupported.

## Java/Spring rules and call-taint semantics

`CallSiteContextResolver` builds a Tree-sitter-independent context from `JavaFileInfo`, the enclosing class and method, `DataFlowResult`, and the concrete `MethodCallExpression`. It resolves only direct parameter/local/field declarations plus explicit imports, fully qualified names, an unambiguous wildcard import, and `java.lang.String`. It does not perform compiler symbol solving, overload resolution, subtype inference, or dynamic dispatch; unresolved or ambiguous receiver types do not match type-specific rules.

The default registry matches Spring MVC parameter sources for imported or fully qualified `RequestParam`, `PathVariable`, `RequestBody`, `RequestHeader`, and `CookieValue` annotations. It also matches `jakarta.servlet.http.HttpServletRequest.getParameter`, `getHeader`, and `getQueryString` return expressions when the receiver type is directly resolvable. Source matches convert to `DefinitionTaintSeed` or `ExpressionTaintSeed` without making a vulnerability decision.

SQL-text sink matching currently covers argument zero of `java.sql.Statement.execute`, `executeQuery`, and `executeUpdate`; `java.sql.Connection.prepareStatement`; Spring `JdbcTemplate.query`, `queryForObject`, `update`, and `execute`; and `jakarta.persistence.EntityManager.createNativeQuery`, when the receiver and SQL argument type are directly supported by the lightweight context. `PreparedStatement.setString`/other binding methods and JPA `Query.setParameter` are not SQL-text sinks. Placeholder data arguments are not marked as SQL-text positions. A sink match exposes its stable rule ID, call occurrence, sensitive argument indexes, location, and evidence for a later detector.

Method-call return semantics are injected into taint analysis. The model supports unknown returns, receiver propagation, all-argument propagation, selected-argument propagation, combined receiver/argument propagation, and sanitized returns. Competing models use explicit `SANITIZER > FRAMEWORK_SPECIFIC_PROPAGATION > GENERIC_PROPAGATION` priority. Equivalent semantics at the same highest priority are accepted; conflicting semantics at that priority raise `AmbiguousMethodTaintModelException` instead of depending on registration order. The default Java model conservatively propagates `String` receiver taint through supported `trim`, `strip`, `substring`, case conversion, `concat`, and `replace` forms. These transformations are not registered as security sanitizers. The production sanitizer registry is currently empty; sanitizer behavior is verified with an explicit synthetic test rule.

`RuleAwareTaintAnalysis` is the recommended STEP 6/7 entry point. It matches sources, converts them to seeds, injects the registry's method semantics into `IntraproceduralTaintAnalysis`, and retains both source and sink matches with the taint result. The low-level two-argument taint API remains available for framework-independent STEP 5 use, but it intentionally has no method models and is not the recommended path when framework rules are enabled.

STEP 6 does not generate SQL Injection or other vulnerability findings, CWE/severity data, or Finding JSON. It also does not implement call graphs, interprocedural taint, full overload/type resolution, alias/points-to analysis, dynamic dispatch, pattern analysis, or hardcoded-secret detection.

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
