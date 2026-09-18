# Total Security 경량 Java/Spring SAST

이 디렉터리는 Java 25와 Spring Boot 백엔드를 초기 대상으로 하는 경량 SAST 엔진이다. 분석 파이프라인은 다음 계층을 명시적으로 분리한다.

```text
Java source
→ Tree-sitter Java parsing
→ Tree-sitter-independent Java IR
→ method-level CFG
→ DataFlow
→ Taint
→ environment-specific Source/Sink/Sanitizer rules
→ Finding
```

Tree-sitter는 parsing과 concrete syntax tree 생성에만 사용한다. Java 의미 추출기는 syntax tree에서 class, method, parameter, variable, assignment, method invocation, return, annotation 및 statement 구조를 추출해 자체 IR로 변환한다. CFG, DataFlow, Taint, rule 및 Finding 계층은 `TSNode`, `TSTree`, `org.treesitter` 타입이나 Tree-sitter node type 문자열에 직접 의존하지 않는다.

현재 구현은 STEP 1~22의 범위다.

- STEP 1: Tree-sitter Java parsing 및 syntax tree 순회
- STEP 2/2B: Java 의미 추출, Expression IR, lexical/structural 순서를 보존하는 ordered Statement IR
- STEP 3: 메서드 단위 CFG
- STEP 4: 동일 메서드 내부 DataFlow와 reaching definitions
- STEP 5/6/6B: 동일 메서드 내부 Taint, Java/Spring Source/Sink/Sanitizer rule, 명시적 MethodTaintModel 우선순위와 rule-aware orchestration
- STEP 7~17: 지원 취약점 Finding 및 Pattern Analysis
- STEP 18: same-class interprocedural pure-taint 분석
- STEP 19: project-local cross-class interprocedural pure-taint 분석
- STEP 20: 외부 Java/Spring 프로젝트를 읽기 전용으로 분석하는 Project Runner와 CLI
- STEP 21: 실제 개발 중 snapshot을 이용한 unsupported coverage engineering audit. resolver 기능 자체를 추가한 단계는 아니다.
- STEP 22/22B/22C: 보수적인 Java type qualification, assignability 및 overload resolution 정교화
- STEP 23: top-level record/enum extraction과 source declaration으로 증명된 exact accessor/enum constant semantics
- STEP 24: source hierarchy로 증명된 unique project interface 구현체에 한정한 보수적 dispatch

이 엔진은 finding이 0개라는 사실을 대상이 안전하다는 증명으로 해석하지 않는다. parse/semantic failure와 지원하지 않는 호출 또는 구문은 별도로 보존하며, 지원 범위 밖의 의미를 추측해 성공한 분석으로 표시하지 않는다.

## Java parsing과 의미 IR

`JavaSourceParser`는 UTF-8 Java source를 Tree-sitter Java로 parsing하며 root node, syntax error 여부와 syntax tree 순회를 제공한다. `JavaSemanticExtractor`는 syntax tree를 분석 계층에서 사용할 Java IR로 변환한다.

IR은 다음 정보를 포함한다.

- class, interface, enum, record와 package/import 정보
- method, constructor, parameter, return type, annotation 및 method type parameter
- member/local variable와 lexical scope
- assignment, method call, object creation, return 및 주요 expression
- 실제 lexical 순서와 중첩 구조를 보존하는 `BlockStatement` 기반 ordered statement hierarchy
- 모든 주요 node의 `SourceLocation`

지원하는 statement IR에는 `BlockStatement`, `VariableDeclarationStatement`, `ExpressionStatement`, `ReturnStatement`, `IfStatement`, `WhileStatement`, `DoWhileStatement`, `ForStatement`, `EnhancedForStatement`, `SwitchStatement`, `BreakStatement`, `ContinueStatement`, `ThrowStatement`, `UnknownStatement`가 포함된다. 지원하지 않는 syntax는 완전하게 이해한 것으로 처리하지 않고 unknown/unsupported 정보로 남긴다.

## 메서드 단위 CFG

`ControlFlowGraphBuilder`는 `MethodInfo.body`의 ordered Statement IR만 입력으로 사용한다. CFG 계층은 Tree-sitter node를 다시 참조하지 않는다.

현재 CFG는 다음을 모델링한다.

- entry와 exit
- ordered statements를 담는 basic block
- sequential, TRUE/FALSE branch, loop-back, break, continue, return, throw edge
- `if`/`else`, `while`, `do-while`, classic/enhanced `for`
- `switch` fall-through와 가장 가까운 loop/switch target
- early return/throw 이후 unreachable control flow
- successors, predecessors와 reachable blocks 조회

`UnknownStatement` 및 완전하게 지원하지 않는 제어 흐름은 `UnsupportedControlFlow`에 기록한다. exception CFG는 제한적이며 Java의 모든 예외 전파 의미를 모델링하지 않는다.

## 동일 메서드 내부 DataFlow

`IntraproceduralDataFlowAnalysis`는 reachable CFG block을 대상으로 worklist/fixpoint reaching-definitions 분석을 수행한다.

- parameter, declaration initializer와 assignment를 안정적인 `Definition`으로 모델링한다.
- RHS use는 이전 IN 상태에서 해석한 뒤 기존 definition을 kill하고 새 definition을 generate한다.
- branch merge는 predecessor OUT state의 union이다.
- loop back-edge는 상태가 바뀔 때 successor를 다시 등록해 fixpoint에 도달한다.
- 각 정적 definition과 use occurrence는 분석 반복 동안 안정적인 identity를 유지한다.
- lexical scope가 다른 동일 이름의 local variable은 서로 다른 `VariableSymbol`이다.
- unresolved reference를 임의의 symbol에 연결하지 않는다.
- `UnknownExpression.source()`를 regex나 문자열 검색으로 재해석하지 않는다.
- unreachable statement는 Definition, UseSite 및 IN/OUT 결과에 포함하지 않는다.

`DataFlowResult`는 block별 IN/OUT state, Definition, UseSite, symbol resolution과 각 use에 도달하는 definitions를 제공한다. 이를 이용해 assignment chain을 변수 이름 추측이 아니라 실제 use-definition 관계로 역추적할 수 있다. 지원하지 않는 분석은 `UnsupportedDataFlow`에 남는다.

## 동일 메서드 내부 Taint

`IntraproceduralTaintAnalysis`는 DataFlow 결과를 입력으로 사용하며 `CLEAN < UNKNOWN < TAINTED`의 보수적인 may-taint 의미를 사용한다.

- `DefinitionTaintSeed`와 `ExpressionTaintSeed`를 지원한다.
- definition seed는 assigned expression 평가 결과보다 우선해 `TAINTED`로 유지된다.
- 직접 assignment chain은 UseSite와 reaching Definition을 통해 전파된다.
- overwrite 후 이전 tainted definition이 더는 도달하지 않으면 새 clean definition만 반영된다.
- branch/loop merge 중 하나라도 tainted이면 결과는 tainted다.
- unresolved reference, unknown expression, 모델이 없는 field value/object creation/arbitrary method return은 `UNKNOWN`이다.
- arbitrary method argument의 taint를 해당 method return으로 자동 전파하지 않는다.
- reachable DataFlow 결과만 사용하므로 unreachable call과 expression은 taint/provenance에 포함하지 않는다.

`TaintValue.join`은 다음과 같다.

```text
CLEAN   + CLEAN   = CLEAN
CLEAN   + UNKNOWN = UNKNOWN
UNKNOWN + UNKNOWN = UNKNOWN
TAINTED + CLEAN   = TAINTED
TAINTED + UNKNOWN = TAINTED
TAINTED + TAINTED = TAINTED
```

정적 Definition, UseSite 및 Expression 기반 identity와 유한한 seed-origin set을 사용하므로 loop 재평가가 무한한 provenance node를 만들지 않는다. trace 생성은 cycle-safe이며 복수 seed가 merge될 때 한 origin이 다른 origin을 덮어쓰지 않는다. 지원하지 않는 의미는 `UnsupportedTaint`에 기록한다.

## Java/Spring rule과 call-taint semantics

`RuleRegistry`는 환경별 `SourceRule`, `SinkRule`, `SanitizerRule`과 `MethodTaintModel`을 제공한다. API 이름만으로 match하지 않고 현재 IR에서 확인 가능한 annotation FQN/import, receiver type, method name, arity와 argument 위치를 함께 사용한다.

`RuleAwareTaintAnalyzer`가 권장 진입점이다.

```text
JavaFileInfo / MethodInfo + DataFlowResult + RuleRegistry
→ source match
→ source seed 생성
→ registry의 method semantics provider를 사용한 Taint Analysis
→ sink match
```

결과에서 source matches, taint seeds, `TaintAnalysisResult`와 sink matches를 조회할 수 있다. low-level `IntraproceduralTaintAnalysis.analyze(dataFlow, seeds)`는 독립적인 분석과 테스트를 위해 유지하지만 framework rule을 사용하는 경로에서는 rule-aware API가 권장된다.

`MethodTaintModelRegistry`의 의미 우선순위는 등록 순서가 아니라 명시적 priority로 결정한다.

```text
Sanitizer semantics
> framework/specific propagation
> generic propagation
```

동일한 최고 priority에서 서로 충돌하는 model이 하나의 call에 match하면 임의의 첫 model을 고르지 않고 ambiguity를 unsupported/unknown 의미로 보존한다. Java `String`의 `trim`, `replace`, `substring` 등은 receiver가 실제 `java.lang.String`으로 해석될 때만 propagation model이 적용되며 sanitizer로 분류하지 않는다.

## 지원 Finding

현재 구현은 다음 vulnerability 및 Pattern Analysis finding을 지원한다.

| Category | CWE | 주요 범위 |
| --- | ---: | --- |
| SQL Injection | CWE-89 | JDBC, Spring JDBC, JPA native SQL의 tainted SQL text |
| OS Command Injection | CWE-78 | `Runtime.exec`, `ProcessBuilder`의 tainted command |
| Path Traversal | CWE-22 | 지원 file/path API의 tainted filesystem path |
| Cross-Site Scripting (XSS) | CWE-79 | 지원 Spring MVC response context의 unencoded tainted output |
| Server-Side Request Forgery (SSRF) | CWE-918 | 지원 network API의 tainted request target |
| LDAP Injection | CWE-90 | 지원 LDAP API의 tainted filter |
| XML External Entity (XXE) | CWE-611 | 명시적으로 관찰된 unsafe JAXP DOM configuration과 parse |
| Open Redirect | CWE-601 | 지원 Spring redirect API/context의 tainted target |
| Insecure Deserialization | CWE-502 | 지원 Java native deserialization sink |
| Unrestricted File Upload | CWE-434 | 지원 upload flow와 검증 상태 |
| Hardcoded Credential Pattern | CWE-798 | 별도 Pattern Analysis |

각 Finding은 해당 분석에서 이용 가능한 범위로 rule id, vulnerability type, CWE, severity, location, source, sink, flow와 evidence를 보존한다. Pattern Finding에는 source-to-sink flow가 없을 수 있다.

### SQL Injection — CWE-89

지원 rule은 receiver FQN/type, method signature와 SQL argument 위치를 확인한다.

- `java.sql.Statement.execute(...)`, `executeQuery(...)`, `executeUpdate(...)`
- `java.sql.Connection.prepareStatement(...)`
- 지원하는 Spring `JdbcTemplate` SQL-first overload
- `jakarta.persistence.EntityManager.createNativeQuery(...)`

SQL text는 지원 signature의 argument 0이어야 한다. `PreparedStatement.setString`/`setInt` 및 `Query.setParameter`는 SQL text sink가 아니다. callback/creator overload처럼 argument 0이 SQL임을 입증하지 못하는 형태는 확정적으로 match하지 않는다.

### OS Command Injection — CWE-78

`java.lang.Runtime.exec` 및 `java.lang.ProcessBuilder`의 지원 signature에서 command argument의 taint를 검사한다. method name만 같은 사용자 정의 API는 match하지 않는다. shell 해석 여부나 운영체제별 quoting을 완전하게 모델링하지 않는다.

### Path Traversal — CWE-22

지원하는 `java.io`, `java.nio.file` 및 Spring resource/file API에서 filesystem path argument를 검사한다. path normalization 또는 canonicalization을 이름만으로 sanitizer라고 간주하지 않으며, alias와 실제 filesystem 상태를 추론하지 않는다.

### Server-Side Request Forgery — CWE-918

지원하는 URL/URI 및 Spring HTTP client 호출에서 network request target의 taint를 검사한다. DNS resolution, redirect chain, allowlist의 runtime 내용이나 네트워크 상태는 분석하지 않는다.

### LDAP Injection — CWE-90

지원 LDAP API에서 filter expression argument의 taint를 검사한다. receiver와 signature가 확인되지 않은 유사 이름 API는 match하지 않는다.

### XML External Entity — CWE-611

`DomXxeConfigurationAnalyzer`는 JAXP DOM factory/builder의 명시적으로 관찰된 configuration state와 parse를 연결한다. 관찰하지 않은 provider/JDK default는 추론하지 않으며 `UNKNOWN` 상태만으로 confirmed finding을 만들지 않는다.

confirmed XXE Finding은 external entity resolution 가능성을 충분히 입증하는 보수적인 조합에서만 생성한다. 다음 설정 하나만으로는 다른 관련 설정이 `UNKNOWN`인 상황에서 confirmed CWE-611을 만들지 않는다.

- `disallow-doctype-decl = false`
- `external-general-entities = true`
- `external-parameter-entities = true`
- `load-external-dtd = true`
- `setXIncludeAware(true)`
- `setExpandEntityReferences(true)`

`setXIncludeAware(true)`는 전통적인 external entity resolution과 동일한 단독 증거로 취급하지 않는다. `setExpandEntityReferences(true)`도 external entity loading이 실제 허용됨을 단독으로 증명하지 않는다. unsupported 또는 불완전한 configuration은 분석 제한으로 남긴다.

### Open Redirect — CWE-601

지원 Spring MVC redirect context에서 외부 입력이 redirect target에 도달하는지를 검사한다. 단순 문자열 `redirect:` 검색만으로 Finding을 만들지 않으며, route/view 의미를 확인할 수 없는 경우 확정하지 않는다.

### Insecure Deserialization — CWE-502

지원 Java native deserialization API와 tainted input flow를 검사한다. classpath gadget 존재, custom `readObject` 동작 또는 runtime type을 추론하지 않는다.

### Cross-Site Scripting — CWE-79

지원 Spring MVC response context의 tainted output을 검사한다. HTML/attribute/JavaScript 등 모든 출력 문맥과 모든 encoding library를 완전하게 모델링하지 않는다. 이름이 비슷한 method만으로 sink나 sanitizer를 단정하지 않는다.

### Unrestricted File Upload — CWE-434

지원 Spring multipart upload flow와 관찰 가능한 검증/저장 context를 분석한다. 실제 storage ACL, malware scanning, content sniffing 또는 runtime file policy는 추론하지 않는다.

## Same-class interprocedural taint

STEP 18 분석은 같은 class의 직접 호출만 제한적으로 해석한다.

- `helper(arg)`와 `this.helper(arg)`를 대상으로 한다.
- caller argument → callee parameter와 callee return → caller expression 경계를 보존한다.
- acyclic `A → B → C` summary chain을 지원한다.
- self recursion과 mutual recursion은 propagation에서 제외하고 unsupported로 기록한다.
- synthetic callee-parameter seed는 사용자-facing `FindingSource`로 노출하지 않는다.
- 원래 caller의 `@RequestParam` 등 실제 source는 Finding source로 유지한다.
- physical sink location은 실제 callee sink 위치다.
- method call, parameter binding과 return boundary가 provenance에 보존된다.

Overload resolution은 method name만 보지 않는다. name, arity, argument/parameter type compatibility를 확인하며 다음 정책을 사용한다.

- exact candidate가 있으면 compatible/unknown 후보보다 우선한다.
- exact candidate가 없고 `COMPATIBLE` 후보가 정확히 하나이며 competing `UNKNOWN` 후보가 없을 때만 그 후보를 선택한다.
- `COMPATIBLE` 후보가 둘 이상이면 `AMBIGUOUS_OVERLOAD`다. `UNKNOWN` 후보가 함께 있어도 ambiguity가 우선한다.
- `COMPATIBLE` 하나와 `UNKNOWN` 하나 이상이 경쟁하면 `UNKNOWN_ARGUMENT_TYPE`으로 해석을 중단한다.
- compatible 후보 없이 unknown 후보가 있으면 `UNKNOWN_ARGUMENT_TYPE`이다.
- 단, name/arity가 맞는 후보가 하나뿐이고 알려진 incompatibility가 없는 singleton `UNKNOWN` 사례는 기존의 보수적인 singleton 정책에 따라 resolve될 수 있다.
- incompatible 후보만 남으면 지원하지 않는 type mismatch로 기록한다.
- 모호한 overload에서 첫 candidate를 임의 선택하지 않는다.

## Project-local cross-class interprocedural taint

STEP 19 분석은 project 내에서 선언된 concrete class 간의 고신뢰 직접 호출만 해석한다.

- declared receiver type을 project class FQN으로 해석할 수 있어야 한다.
- duplicate FQN class는 임의 선택하지 않는다.
- interface receiver는 STEP 24의 엄격한 unique source implementation 조건을 만족할 때만 지원한다. 일반 runtime implementation 선택, runtime override dispatch 및 external class 내부 호출은 지원하지 않는다.
- target method name, arity와 보수적인 type compatibility를 확인한다.
- 한 파일의 실패가 다른 file/class 분석을 중단시키지 않으며 unsupported call을 기록한다.

Same-class 및 cross-class generic interprocedural Finding은 다음 다섯 pure-taint category로만 제한한다.

- `SQL_TEXT`
- `COMMAND_EXECUTION`
- `FILESYSTEM_PATH`
- `NETWORK_REQUEST_TARGET`
- `LDAP_FILTER`

XSS, XXE, Open Redirect, Insecure Deserialization 및 Unrestricted File Upload는 이 generic interprocedural summary로 확장하지 않는다. 이들은 각 detector의 context-sensitive intraprocedural 의미를 유지한다. 기존 intraprocedural Finding과 동일한 physical sink Finding은 안정적인 identity로 중복 제거한다.

## STEP 22 보수적 Java type qualification과 assignability

`LightweightTypeContext`, `ConservativeTypeCompatibility`와 project hierarchy index는 compiler-complete type checker가 아니라, source에서 증명할 수 있는 경우에만 call resolution 범위를 넓히는 경량 모델이다.

Type qualification 정책은 다음과 같다.

- explicit import/FQN을 우선하며, 단순 이름을 임의의 FQN으로 만들지 않는다.
- 알려진 implicit `java.lang` type을 지원하되, explicit import에 의해 합법적으로 shadow될 수 있는 Java 이름 해석을 존중한다.
- same-package type은 해당 project type의 존재가 확인될 때만 사용한다.
- wildcard import는 실제 project type 또는 알려진 type 존재를 확인할 수 있을 때만 후보를 만든다.
- wildcard 후보가 복수이면 unknown/ambiguous로 남긴다.
- duplicate FQN은 하나를 임의 선택하지 않는다.

지원하는 보수적 compatibility는 다음과 같다.

- exact type
- reference type에 대한 `Object` parameter
- method-level type variable과 표현 가능한 단일 upper bound
- 안전하게 비교 가능한 generic raw/erasure shape
- exact boxing/unboxing
- 방향이 올바른 primitive widening
- source로 증명된 project-local class/interface subtype

제한은 다음과 같다.

- `Object` 규칙을 primitive argument에 직접 적용하지 않는다.
- bounded type variable은 bound와 무관한 type을 허용하지 않는다.
- unrelated generic raw type을 compatible로 만들지 않는다.
- primitive narrowing이나 wrapper 간 임의 numeric conversion을 허용하지 않는다.
- unresolved/external parent hierarchy를 추측하지 않는다.
- hierarchy traversal은 cycle-safe이며 duplicate subtype, target supertype 또는 intermediate parent가 있으면 해당 proof를 중단한다.
- hierarchy는 argument assignability와 STEP 24의 제한적인 unique project interface implementation 증명에만 사용한다. 일반 runtime dispatch에는 사용하지 않는다.

Generic type-variable array shape도 보존한다.

- scalar `T`의 기존 method type-variable 의미는 유지한다.
- `T[]`는 scalar argument와 compatible하지 않다.
- 배열 차원이 같을 때만 component type compatibility를 검사한다.
- `T[][]` 같은 multidimensional dimension을 보존한다.
- `T[]` 또는 bounded `T[]`에 `int[]`, `long[]`, `boolean[]` 등 primitive-component array를 허용하지 않는다.
- `int[] → T[]`에 element-wise boxing을 적용하지 않는다.
- `String[] → T[]`, `String[][] → T[][]`처럼 reference component와 동일 dimension인 경우에만 현재 type-variable 의미 안에서 판단한다.
- `T...`를 scalar `T`로 취급하지 않으며 varargs invocation conversion은 지원하지 않는다.

Method-level type parameter는 해당 method declaration에만 연결한다. class-level generic parameter를 method-level parameter로 가장하지 않으며, 현재 IR 표현 범위를 벗어나는 복수/intersection bound는 추측하지 않는다.

## STEP 23 record/enum semantics

Top-level `record`와 `enum`을 class/interface와 구분된 project type으로 추출한다. record component의 name, declared type, annotation과 location, enum constant의 name, location 및 constant-specific class body 존재 여부를 Tree-sitter-independent IR에 보존한다.

- 유일한 exact project record의 instance-value receiver, 실제 component name, argument 0개가 모두 증명되고 동일 signature의 explicit method가 없을 때만 compiler-provided accessor return type을 component declared type으로 제공한다.
- analyzable explicit accessor가 있으면 normal project method resolution과 body summary가 synthetic component semantics보다 우선한다.
- exact synthetic record accessor에만 receiver-derived taint를 적용하며 arbitrary getter, Lombok getter 또는 다른 zero-argument method로 일반화하지 않는다.
- source-declared enum constant field access는 해당 enum의 exact type을 유지한다. constant-specific class body가 있는 호출은 runtime override target을 선택하지 않고 unsupported dynamic dispatch로 남긴다.
- duplicate FQN은 record accessor나 enum constant declaration을 임의 선택하지 않는다.

Nested record/enum, compiler-generated `values()`/`valueOf()` 및 runtime override dispatch는 STEP 23 지원 범위가 아니다. Interface dispatch는 아래 STEP 24 조건을 별도로 만족할 때만 지원한다.

## STEP 24 unique project interface implementation dispatch

Receiver가 duplicate가 아닌 exact unique project interface type에 bound된 instance value이고, 실제 source의 `extends`/`implements` hierarchy로 unique analyzable concrete class implementation이 정확히 하나임을 증명할 수 있을 때만 해당 implementation method를 target으로 사용한다. Abstract class는 concrete candidate에서 제외하며, target method에는 기존의 보수적 name/arity/type/overload 판정과 analyzable body 조건을 그대로 적용한다.

- `@Service`, `@Repository`, `@Component`, `@Controller`, `@RestController` 같은 Spring annotation 자체는 dispatch 근거가 아니다.
- Interface type-name/static-style receiver에는 unique implementation dispatch를 적용하지 않는다.
- Spring Data/JPA repository marker hierarchy의 runtime proxy interface는 계속 unsupported다.
- concrete implementation이 여러 개이거나 FQN/hierarchy가 duplicate 또는 ambiguous이면 임의 선택하지 않는다.
- `@Primary`, `@Qualifier`, bean name 및 Spring container injection resolution은 지원하지 않는다.
- interface default method, external superclass inherited method, runtime override 및 record/enum implementation dispatch는 추측하지 않는다.
- resolve된 call은 기존 STEP 19 project summary와 5개 pure-taint category만 재사용하며, interface와 선택된 implementation 정보를 call provenance에 보존한다.

## 외부 경로 Project Runner

`ProjectScanner`는 전달받은 `projectRoot`를 기준으로 외부 Java/Spring project를 읽기 전용으로 분석한다. current working directory나 이 저장소 경로를 대상 project로 암묵적으로 사용하지 않는다.

- multi-module의 `src/main/java` source를 중복 없이 발견한다.
- `.git`, `build`, `target`, `out`, generated/cache 경로를 제외한다.
- symlink 또는 canonical path가 project root 밖으로 벗어나면 분석하지 않는다.
- 각 Java source는 기본적으로 한 번 parsing하고 한 번 semantic extraction한다.
- READ, PARSE 또는 SEMANTIC_EXTRACTION 실패와 diagnostics는 파일별로 남기고 다른 파일 분석을 계속한다.
- project-level interprocedural 분석과 각 method에 적용 가능한 context-sensitive intraprocedural detector를 실행한다.
- `PatternAnalysis.javaDefaults()`를 추출에 성공한 모든 `JavaFileInfo`에 적용한다.
- 동일 detector를 runner에서 중복 실행하지 않는다.

`ProjectScanResult`는 discovered/analyzed files, Finding, unsupported 및 failure를 제공한다. fatal failure는 유효한 project scan 자체를 시작하거나 유지할 수 없는 경우이며, 일부 파일 실패/unsupported는 `PARTIAL`로 표현할 수 있다. unsupported가 존재하거나 Finding이 0개여도 이를 안전 판정으로 바꾸지 않는다.

최종 Finding 정렬은 location과 rule을 포함한 안정적인 key를 사용하며 Finding의 source/evidence/flow를 변경하지 않는다. 중복 제거는 detector/interprocedural 계층의 occurrence identity를 보존하도록 physical occurrence와 category/rule 정보를 사용한다. Hardcoded Credential의 실제 secret literal은 CLI summary 또는 `ProjectScanResult.toString()`에 출력하지 않는다.

CLI exit code 정책은 다음과 같다.

- 정상 또는 partial scan: `0`
- invalid input 또는 fatal scan failure: non-zero
- Finding 존재 자체는 process failure가 아니다.

현재 CLI는 사람이 읽을 수 있는 summary를 제공한다. JSON 또는 SARIF output을 구현한 것으로 주장하지 않는다.

## Pattern Analysis와 Hardcoded Credential

Pattern Analysis는 DataFlow/Taint vulnerability detector와 분리되어 있다. `PatternAnalysis.javaDefaults()`는 Java literal 및 assignment/declaration context를 이용해 Hardcoded Credential(CWE-798) 후보를 찾는다.

- 실제 secret value는 Finding evidence와 일반 문자열 표현에서 redaction한다.
- placeholder, 명백한 test/example value 및 지원하지 않는 동적 표현은 보수적으로 처리한다.
- regex나 literal pattern 결과를 source-to-sink taint finding으로 가장하지 않는다.
- Pattern Finding에는 DataFlow source/sink flow가 없을 수 있다.

## 명시적 제한

현재 구현은 다음을 지원하지 않거나 완전하게 분석하지 않는다.

- compiler-complete Java type checking과 generic type inference
- Java overload specificity 전체
- varargs invocation conversion
- source hierarchy로 유일성을 증명할 수 없는 runtime interface implementation 선택
- runtime override/virtual dispatch
- external library hierarchy 추론
- Reflection
- 완전한 points-to/alias analysis
- 완전한 field/heap taint
- path-sensitive analysis
- 모든 exception path와 resource lifecycle
- async/reactive flow
- whole-program call graph 및 상용 SAST 수준 whole-program analysis
- 모든 Java/Spring/JPA/Hibernate/JDBC overload와 framework behavior

분석은 보수적인 may-taint 모델이다. source에서 증명할 수 없는 target, type, hierarchy 또는 runtime behavior는 추측하지 않고 unsupported/unknown으로 남긴다. duplicate FQN, ambiguous overload 및 동적 dispatch 대상도 임의 선택하지 않는다.

## 요구 사항

- JDK 25
- Gradle Wrapper
- Windows에서는 native Tree-sitter binding을 위한 `--enable-native-access=ALL-UNNAMED`

Tree-sitter Java grammar와 Java binding 버전은 `build.gradle.kts`에 고정되어 있다. Tree-sitter는 parsing에만 사용하며 별도의 Java parser로 대체하지 않는다.

## Build와 test

저장소의 `sast` 디렉터리에서 실행한다.

```powershell
.\gradlew.bat -g C:\project\total-security\sast\.gradle-user-home clean build --no-daemon
```

Gradle 내부 cache와 build output은 `sast/.gitignore`에서 제외한다.

## Java syntax tree 출력

하나의 `.java` 파일을 parsing하고 node type, start/end position 및 선택적인 source text를 출력할 수 있다.

```powershell
.\gradlew.bat -g C:\project\total-security\sast\.gradle-user-home run --args="src/test/resources/fixtures/SampleController.java"
```

이 출력은 parsing/진단용이다. syntax tree dump 자체가 semantic IR, CFG, DataFlow, Taint 또는 vulnerability Finding을 의미하지 않는다.
