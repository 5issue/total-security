# Total Security SAST

STEP 1 provides Java source parsing and concrete syntax tree inspection. STEP 2 adds a Java-specific semantic extractor and a Tree-sitter-independent Java IR. STEP 2B adds an ordered statement hierarchy to method bodies. STEP 3 builds method-level control-flow graphs from that IR without accessing Tree-sitter nodes. STEP 4 adds intraprocedural flow-sensitive reaching-definitions analysis over the IR and CFG. STEP 5 adds intraprocedural flow-sensitive taint propagation over those reaching definitions. STEP 6 adds Java/Spring rule matching and injectable method-call taint semantics. STEP 6B makes model precedence explicit and provides rule-aware taint orchestration. STEP 7 adds the first vulnerability detector and produces evidence-backed SQL Injection (CWE-89) findings for supported flows. STEP 8 adds an independent Java IR pattern-analysis path and its first Hardcoded Credential (CWE-798) detector. STEP 9 adds OS Command Injection (CWE-78) findings for supported `java.lang.Runtime.exec` String-command flows. STEP 10 adds Path Traversal (CWE-22) findings for supported `java.nio.file.Files` Path arguments. Java parsing uses Tree-sitter with the official Java grammar packaged for the Java binding.

The extractor currently preserves package/import declarations, classes, interfaces, methods, constructors, parameters, fields, local variables, assignments, method calls, returns, and annotations. Expressions are represented structurally as variable references, literals, binary and assignment expressions, method calls, object creation, field access, parenthesized expressions, or explicit unknown expressions.

Concrete method and constructor bodies contain ordered `Statement` IR. The current statement variants are blocks, variable declarations, expression statements, returns, if/else, while, do-while, classic for, enhanced for, switch cases, break, continue, throw, and explicit unknown statements. Every statement retains a `SourceLocation`.

The IR does not assign Spring or security meaning to annotations or API names.

## Method-level CFG

`ControlFlowGraphBuilder` groups consecutive straight-line statements into basic blocks and splits at branch, loop, switch, and terminating control transfers. Graph edges distinguish normal flow, true/false branches, loop back-edges, break, continue, return, throw, and switch case/default dispatch. Nested loop and switch targets are resolved with an explicit control-context stack.

The CFG currently supports ordered blocks, if/else, while, do-while, classic for, an abstract enhanced-for iteration model, colon-style switch fall-through, break, continue, return, and throw-to-method-exit. `UnknownStatement` is retained sequentially and reported through `unsupportedControlFlow`; it is not treated as fully supported.

Switch arrow-rule value/yield semantics, labeled break/continue, precise try/catch/finally exception flow, and exceptions thrown by called methods are not fully modeled. Call graphs, complete type resolution, and general finding serialization/output are not implemented.

## Intraprocedural data flow

`ReachingDefinitionsAnalysis` uses only `MethodInfo`, ordered Statement/Expression IR, and `ControlFlowGraph`. It computes immutable `IN` and `OUT` states for reachable basic blocks with a worklist until state equality reaches a fixpoint. Predecessor states are joined by union; a parameter, initialized local declaration, or assignment generates a stable `Definition`, and a new definition kills older definitions of the same `VariableSymbol` on that path.

Variable identity is based on a parameter or local declaration's name, kind, declared type, and source location rather than name alone. Resolution is limited to references that can be linked through the method's lexical scopes. Results retain statement-before states and resolved use sites so callers can query which definitions reach a specific `VariableReference`, including uses nested in supported binary, assignment, method-call, object-creation, field-target, and parenthesized expressions. Unknown expression source text is never searched to guess uses.

The reaching-definitions layer does not perform Java type resolution, alias or points-to analysis, heap identity, field-sensitive analysis, interprocedural flow, or security rule evaluation. Arbitrary field assignments remain unsupported. Compound assignment records a local read and replacement definition but does not interpret the operator's value semantics. Enhanced-for iterable uses are analyzed, but the per-iteration element definition is reported as unsupported because the current CFG does not expose that true-edge assignment separately. Unresolved references and other unsupported inputs are retained explicitly in the result.

## Intraprocedural taint propagation

`IntraproceduralTaintAnalysis` accepts a `DataFlowResult` and explicit definition or expression seeds supplied by its caller. It does not infer sources from annotations or API names. The finite may-taint lattice is `CLEAN < UNKNOWN < TAINTED`; a tainted predecessor therefore dominates clean and unknown alternatives at a merge. Definition dependencies are reevaluated with a worklist only when an upstream value changes, and stable STEP 4 definition identities ensure loop dependencies reach a fixpoint.

Variable references join the taint of their reaching definitions. Literals are clean, binary operands are joined, and parenthesized expressions forward their inner value. Receiver and argument taint are retained separately for method calls. Without an explicit expression seed or injected propagation model, arbitrary method-call returns, constructed objects, field values, unresolved references, and unknown expressions are `UNKNOWN`; their source text is not searched to infer taint.

Results expose definition, expression, variable-use, method receiver, and argument taint. A finite static provenance graph links external seeds, definitions, use sites, and supported expression steps, preserving multiple seed origins and representing loop cycles without growing an iteration-specific trace. The STEP 5 core does not infer framework meaning or make vulnerability decisions; STEP 6 supplies explicit seeds and method semantics, and STEP 7 consumes those results in a separate detector. Interprocedural taint, call graphs, alias/points-to analysis, heap-sensitive analysis, and complete field-sensitive analysis remain unsupported.

## Java/Spring rules and call-taint semantics

`CallSiteContextResolver` builds a Tree-sitter-independent context from `JavaFileInfo`, the enclosing class and method, `DataFlowResult`, and the concrete `MethodCallExpression`. It resolves direct parameter/local/field declarations plus explicit imports, fully qualified names, an unambiguous wildcard import, and selected `java.lang` types. A small exact-signature allowlist supplies return types only for supported `Runtime` and Java NIO Path calls needed by registered rules. It does not perform compiler symbol solving, general overload resolution, subtype inference, or dynamic dispatch; unresolved or ambiguous receiver types do not match type-specific rules.

The default registry matches Spring MVC parameter sources for imported or fully qualified `RequestParam`, `PathVariable`, `RequestBody`, `RequestHeader`, and `CookieValue` annotations. It also matches `jakarta.servlet.http.HttpServletRequest.getParameter`, `getHeader`, and `getQueryString` return expressions when the receiver type is directly resolvable. Source matches convert to `DefinitionTaintSeed` or `ExpressionTaintSeed` without making a vulnerability decision.

SQL-text sink matching currently covers argument zero of `java.sql.Statement.execute`, `executeQuery`, and `executeUpdate`; `java.sql.Connection.prepareStatement`; Spring `JdbcTemplate.query`, `queryForObject`, `update`, and `execute`; and `jakarta.persistence.EntityManager.createNativeQuery`, when the receiver and SQL argument type are directly supported by the lightweight context. `PreparedStatement.setString`/other binding methods and JPA `Query.setParameter` are not SQL-text sinks. Placeholder data arguments are not marked as SQL-text positions. A sink match exposes its stable rule ID, call occurrence, sensitive argument indexes, location, and evidence for a later detector.

Method-call return semantics are injected into taint analysis. The model supports unknown returns, receiver propagation, all-argument propagation, selected-argument propagation, combined receiver/argument propagation, and sanitized returns. Competing models use explicit `SANITIZER > FRAMEWORK_SPECIFIC_PROPAGATION > GENERIC_PROPAGATION` priority. Equivalent semantics at the same highest priority are accepted; conflicting semantics at that priority raise `AmbiguousMethodTaintModelException` instead of depending on registration order. The default Java models conservatively propagate `String` receiver taint through supported `trim`, `strip`, `substring`, case conversion, `concat`, and `replace` forms, and path taint through the exact Java NIO calls documented below. These transformations are not registered as security sanitizers. The production sanitizer registry is currently empty; sanitizer behavior is verified with an explicit synthetic test rule.

`RuleAwareTaintAnalysis` is the recommended STEP 6+ entry point. It matches sources, converts them to seeds, injects the registry's method semantics into `IntraproceduralTaintAnalysis`, and retains both source and sink matches with the taint result. The low-level two-argument taint API remains available for framework-independent STEP 5 use, but it intentionally has no method models and is not the recommended path when framework rules are enabled.

## SQL Injection findings

`SqlInjectionDetector` consumes only `RuleAwareTaintResult`; it does not inspect Tree-sitter nodes or rediscover API names. `SinkMatch` carries the stable `SQL_TEXT` category, and the detector examines each declared sensitive argument. A finding is produced only when that argument is `TAINTED`. `CLEAN` and `UNKNOWN` arguments do not produce confirmed findings.

Each finding uses rule ID `SQL_INJECTION`, vulnerability type `SQL Injection`, CWE `CWE-89`, and detector metadata severity `HIGH`. `HIGH` is not a calculated CVSS score. The primary location is the SQL argument. Source evidence retains the source rule, source kind, seed, location, and parameter or expression summary. Sink evidence separately retains the environment sink rule, method, argument index, category, and location. Flows reuse the finite STEP 5 provenance graph and contain ordered source, definition, use, expression, and sink steps. Both variable arguments and direct composite expressions are traceable; no second taint engine is used.

Findings are deduplicated by the physical sink call location and sensitive argument index, while every taint origin at that argument is retained in the finding. Prepared-statement/JPA parameter binding and `JdbcTemplate` placeholder data are not treated as sanitizers: they are safe in the currently modeled cases because the SQL-text argument itself is a clean literal and binding arguments are not `SQL_TEXT` positions.

This detector covers only sources, sinks, expressions, and lightweight receiver types currently recognized by the rule and taint layers. An unmodeled method return remains `UNKNOWN`, so flows such as `customBuilder(input)` can be false negatives. The implementation does not claim complete Java/Spring SQL Injection coverage. It does not implement additional flow vulnerability categories beyond the explicitly documented SQL, command, and path detectors, interprocedural Controller-to-Service-to-Repository flow, call graphs, full overload/type resolution, dynamic dispatch, alias/points-to analysis, whole-program analysis, or JSON output.

## OS Command Injection findings

`JavaRuntimeCommandSinkRule` adds the stable `COMMAND_EXECUTION` sink category for supported `java.lang.Runtime.exec` calls. Matching requires the receiver's lightweight qualified type to be exactly `java.lang.Runtime`, the method name to be `exec`, and argument zero to resolve to `java.lang.String`. The supported overload shapes are `exec(String)`, `exec(String, String[])`, and `exec(String, String[], java.io.File)`; argument zero is the only sensitive command position. The `String[]` command overloads are intentionally excluded because array-element taint is not modeled precisely enough.

Declared field, local, and parameter receivers are supported. The common `Runtime.getRuntime().exec(command)` form is also supported through one narrow known-return rule: the factory call must be the zero-argument `getRuntime()` invoked on a type reference that resolves exactly to `java.lang.Runtime`. Arbitrary method return inference and name-only `getRuntime` inference are not performed. Custom `Runtime` types and other classes with an `exec` method do not match.

`CommandInjectionDetector` consumes only `RuleAwareTaintResult` and `COMMAND_EXECUTION` matches; it does not rediscover API names. A finding is produced only when the sensitive command argument is `TAINTED`. `CLEAN` and `UNKNOWN` arguments are not confirmed findings. It reuses the same source, sink, and finite provenance evidence model as SQL Injection. Findings use rule ID `OS_COMMAND_INJECTION`, vulnerability type `OS Command Injection`, CWE `CWE-78`, and detector metadata severity `HIGH`; this is not a calculated CVSS score. Evidence states only that tainted external input reaches a supported operating-system command execution argument. It does not claim guaranteed exploitation, shell metacharacter interpretation, or that `Runtime.exec(String)` always invokes a shell.

String operations covered by the existing propagation model, including `trim`, retain taint; they are not command sanitizers. No production command sanitizer is currently registered. Findings are deduplicated by physical sink location and sensitive argument index while retaining all source origins and their provenance flows.

`ProcessBuilder` is not a STEP 9 sink. Correctly connecting constructor or `command(...)` configuration to a later `start()` requires receiver identity and mutable object-state tracking that the current intraprocedural value analysis does not provide. ProcessBuilder state/start flows, shell-specific syntax analysis, OS-specific command parsing, interprocedural flow, call graphs, alias/points-to analysis, heap-sensitive analysis, whole-program analysis, and JSON serialization remain unsupported. SSRF, XSS, and LDAP Injection detectors are not implemented.

## Path Traversal findings

`JavaNioFilesPathSinkRule` adds the stable `FILESYSTEM_PATH` category for selected static `java.nio.file.Files` APIs. It supports `readString`, `readAllBytes`, `newInputStream`, `newBufferedReader`, `writeString`, `newOutputStream`, `delete`, and `deleteIfExists` when the method's actual arity is supported and argument zero resolves to `java.nio.file.Path`. Argument zero is the only sensitive filesystem-path position. In particular, tainted content at argument one of `writeString(cleanPath, taintedContent)` does not produce a Path Traversal finding. Custom `Files` classes and similarly named methods do not match.

The default Java NIO model propagates taint from all String path components through exact `java.nio.file.Path.of` and `java.nio.file.Paths.get` calls. `Path.resolve(String)` and `Path.resolve(Path)` combine receiver and argument taint. `Path.normalize()` and `Path.toAbsolutePath()` propagate receiver taint and are not sanitizers: neither proves that the result remains inside an allowed base directory. Return-type inference is restricted to these exact qualified APIs and signatures, so custom `Path.of`, arbitrary `get`/`resolve` methods, and unmodeled path builders remain `UNKNOWN`.

`PathTraversalDetector` consumes only `RuleAwareTaintResult` and `FILESYSTEM_PATH` matches. A finding is produced only when argument zero is `TAINTED`; `CLEAN` and `UNKNOWN` do not produce confirmed findings. Findings use rule ID `PATH_TRAVERSAL`, vulnerability type `Path Traversal`, CWE `CWE-22`, and detector metadata severity `HIGH`, which is not a calculated CVSS score. Existing source evidence and finite provenance are retained through Path construction, definitions, uses, and the Files sink. Physical sink location plus sensitive argument index provides deduplication while all source origins remain represented.

STEP 10 intentionally covers only supported external-input taint reaching the documented `java.nio.file.Files` Path arguments. It does not model `java.io.File`, `FileInputStream`, or `FileReader` constructor sinks, because constructor occurrences need a general sink abstraction and `new File` alone is path construction rather than file access. `Files.copy` and `Files.move` are also excluded because they have multiple path positions requiring separate precise modeling. Full base-directory validation reasoning, path canonicalization policies, interprocedural flow, Controller-to-Service-to-Repository flow, alias/points-to analysis, object/heap state, general constructor sinks, full overload/type resolution, whole-program analysis, and JSON serialization remain unsupported. SSRF, XSS, LDAP Injection, XXE, and Open Redirect detectors are not implemented.

## Pattern analysis and hardcoded credentials

Pattern Analysis is a separate analysis path from CFG, reaching definitions, taint, and source/sink rules. `PatternAnalysis` runs `PatternDetector` implementations directly over the Tree-sitter-independent `JavaFileInfo` IR. The default registry currently contains only `HardcodedCredentialDetector`; callers can supply additional detectors without coupling them to flow analysis.

The STEP 8 detector combines a supported sensitive identifier with a direct, non-empty Java string literal initializer or assignment. Fields, local variables, and assignments with a stable variable or field target are supported. Identifier normalization splits camelCase, acronym-style camelCase, snake_case, and other non-alphanumeric separators into lower-case words, then compares the complete normalized identifier against a bounded credential vocabulary. It does not use broad substring matching, so names such as `tokenCount` and `passwordEnabled` are not findings.

Only structural `string_literal` IR values containing non-whitespace content are confirmed. Empty and whitespace-only strings, `null`, character/numeric/boolean literals, method-call returns, environment/config/request values, and arbitrary expressions are not treated as hardcoded credentials. Source text is not searched with regular expressions to reconstruct declarations or assignments.

Pattern findings use rule ID `HARDCODED_CREDENTIAL`, vulnerability type `Hardcoded Credential`, CWE `CWE-798`, and detector metadata severity `HIGH`; this severity is not a calculated CVSS score. The primary location points to the literal. Evidence retains the identifier, declaration/assignment kind, literal kind, location, and a redacted reason, but never copies the literal value. Pattern findings intentionally have no fabricated source, sink, or flow. Flow findings and pattern findings share `FindingResult` metadata while retaining evidence models suited to their different analysis methods. Findings are deduplicated by rule ID and literal source location, so distinct assignments remain distinct findings.

This structural detector does not claim to find every secret. AWS access-key formats, GitHub token formats, JWTs, private-key PEM blocks, entropy-based detection, raw source regex scanning, and configuration/YAML/properties scanning remain unsupported. These are future Pattern Analysis extensions rather than taint rules.

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
