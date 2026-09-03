# AGENTS.md

## 적용 범위

이 파일은 저장소 전체에 적용된다. 더 하위 경로에 별도의 `AGENTS.md`가 있다면 해당 경로에서는 더 구체적인 하위 지침을 함께 따르며, 충돌하는 경우 하위 지침을 우선한다.

이 저장소에서 구현하는 SAST 기능의 초기 대상은 **Java 25 + Spring Boot 백엔드**다. 프론트엔드는 현재 구현 범위에서 제외하되, 이후 언어 및 프레임워크 분석기를 추가할 수 있도록 Java/Spring 전용 로직과 공통 분석 모델의 경계를 명확히 유지한다.

## 핵심 원칙

- Java 소스 파싱에는 **Tree-sitter Java**를 사용한다.
- Tree-sitter의 책임은 소스 파싱과 concrete syntax tree 생성까지로 제한한다.
- Tree-sitter 자체 Parser 또는 Java 문법 Parser를 재구현하지 않는다.
- Tree-sitter 노드를 순회하여 다음 의미 정보를 추출하고 내부 분석 모델로 변환하는 로직은 직접 구현한다.
  - Class, interface, enum, record
  - Method와 constructor
  - Parameter와 local/member variable
  - Assignment와 expression
  - Method invocation과 object creation
  - Return
  - Annotation
- syntax tree의 노드 타입 문자열에 분석 전반이 직접 결합되지 않도록, AST 의미 추출 계층과 이후 분석 계층을 분리한다.
- CFG(Control Flow Graph), DataFlow, Taint Analysis는 저장소 내부에서 직접 구현한다.
- 취약점 탐지를 단순 정규식 검색이나 API 이름 검색만으로 대체하지 않는다. 탐지 결과는 가능한 범위에서 구문 구조, 심볼/의미 정보, 제어 흐름, 데이터 흐름 또는 taint 전파 근거를 가져야 한다.
- 정규식 및 리터럴 기반 검사는 별도의 **Pattern Analysis**로 제공한다. Pattern Analysis에는 민감정보 하드코딩 탐지 패턴을 포함한다.
- 구현하지 않은 분석 기능이나 정확도를 구현한 것처럼 문서, 코드, 테스트, 로그 또는 결과에 표현하지 않는다.

## 분석 파이프라인과 책임 분리

구현은 다음 책임을 구분할 수 있도록 설계한다.

1. 소스 수집 및 파일 식별
2. Tree-sitter Java 기반 parsing 및 syntax tree 생성
3. syntax tree에서 Java 의미 요소를 추출하는 semantic model/IR 구성
4. 메서드 단위 CFG 생성
5. 동일 메서드 내부 DataFlow 및 Taint Analysis
6. 환경별 Source/Sink/Sanitizer rule 적용
7. 별도 Pattern Analysis 실행
8. Finding 생성, 근거 연결 및 결과 출력

각 계층의 입력과 출력을 명시적으로 모델링한다. Tree-sitter 노드를 Finding 생성이나 프레임워크 rule이 무분별하게 직접 참조하지 않도록 하며, 공통 분석 모델과 Java/Spring/JPA/JDBC 전용 rule을 분리한다.

## CFG 및 DataFlow 범위

- 기본 구현 단위는 **메서드 단위 CFG**다.
- 최소한 순차 실행, 조건 분기, 반복, 조기 `return`, 예외 흐름 등 현재 지원하는 Java 구문의 제어 흐름을 명시적으로 다룬다.
- 지원하지 않는 구문이나 흐름은 조용히 완전 분석으로 간주하지 말고, 보수적 처리 또는 명시적인 제한으로 남긴다.
- DataFlow의 첫 단계는 동일 메서드 내부(intraprocedural) 분석이다.
- 이후 다음 순서로 제한적인 interprocedural 분석을 확장한다.
  1. 동일 클래스 내부의 메서드 호출
  2. Spring의 Controller -> Service -> Repository 간 단순 호출 및 값 전달
- interprocedural 분석은 실제로 해석 가능한 호출 연결과 인자/반환값 전달만 보고해야 한다. 동적 디스패치나 호출 대상을 확정할 수 없는 경우 그 한계를 명시한다.
- taint 전파에서는 값의 생성, 대입, 인자 전달, 반환, 병합 및 sanitizer 적용을 추적 가능한 형태로 모델링한다.

## Rule 설계

- Source, Sink, Sanitizer는 분석 엔진에 하드코딩된 단일 목록이 아니라 **환경별 Rule**로 정의한다.
- 초기 rule은 다음 환경을 고려한다.
  - Java 표준 API
  - Spring Boot / Spring MVC
  - Spring Data JPA
  - JPA / Hibernate
  - JDBC
  - PostgreSQL
  - MySQL
- rule에는 가능한 경우 적용 환경, 호출/annotation/signature 조건, taint 종류, 인자 또는 반환값 위치, sanitizer 효과와 탐지 근거를 표현한다.
- 이름이 같은 API라는 이유만으로 Source/Sink/Sanitizer로 단정하지 않는다. 선언 타입, 메서드 signature, annotation, 호출 문맥 등 현재 분석기가 확보할 수 있는 근거를 함께 사용한다.
- 대표적인 Java/Spring 백엔드 취약점 약 10종을 초기 목표로 하되, rule별 지원 수준과 알려진 한계를 테스트와 문서에서 사실대로 구분한다.

## Finding 모델

Finding은 최소한 다음 정보를 포함할 수 있도록 설계한다.

- rule id
- 취약점 유형
- CWE
- severity
- file
- line
- source
- sink
- flow
- 탐지 근거

모든 항목이 모든 분석 유형에 항상 존재한다고 가정하지 않는다. 예를 들어 Pattern Analysis finding은 source-to-sink flow가 없을 수 있으므로 필드의 필수 여부와 부재 의미를 명확히 모델링한다. 위치 정보는 가능하면 파일과 시작/종료 위치를 보존하고, flow는 사용자가 소스에서 sink까지의 전파 단계를 재현할 수 있는 순서로 제공한다.

## 명시적 비범위

현재 단계에서는 다음을 완전하게 지원하지 않는다.

- Reflection을 통한 동적 호출 해석
- 완전한 alias analysis 또는 points-to analysis
- 상용 SAST 수준의 whole-program analysis
- 모든 Java/Spring/JPA/Hibernate 동작의 정확한 의미 해석
- 프론트엔드 언어 및 프레임워크 분석

비범위 기능에 의존해야 하는 경우 추측으로 확정적인 finding을 만들지 않는다. 제한된 heuristic을 도입한다면 해당 rule과 결과에 heuristic임을 드러내고, false positive/false negative 가능성을 테스트 및 문서에 기록한다.

## 구현 및 변경 규칙

- 새 기능은 파싱, 의미 추출, CFG, DataFlow/Taint, Rule, Pattern Analysis 중 어느 계층에 속하는지 먼저 정하고 계층 경계를 지킨다.
- 분석 결과의 근거와 추적 가능성을 탐지 개수보다 우선한다.
- 외부 라이브러리는 목적과 책임 범위를 확인한 뒤 도입한다. Java parsing은 Tree-sitter Java를 우회하거나 중복 구현하는 라이브러리로 대체하지 않는다.
- 지원 범위를 넓힐 때 기존 지원 수준과 새로 추가된 수준을 구분한다.
- 오류 복구된 syntax tree나 불완전한 소스를 처리할 때 분석 성공으로 과장하지 않고, 실패/부분 분석 상태를 표현할 수 있게 한다.
- 공개 모델과 rule 식별자는 가능한 한 안정적으로 유지하고, 변경 시 호환성 영향을 검토한다.

## 테스트 및 검증

- 의미 추출기는 Java 25 문법과 Spring 백엔드에서 자주 쓰이는 구조를 포함한 작은 fixture로 검증한다.
- CFG는 분기, 반복, 조기 종료 및 예외 흐름에 대해 노드와 edge를 검증한다.
- DataFlow/Taint rule마다 최소한 true positive, true negative, sanitizer 적용, 유사 이름 API 오탐 방지 사례를 둔다.
- Pattern Analysis 테스트는 taint/data-flow 테스트와 분리한다.
- JPA/Hibernate/JDBC/PostgreSQL/MySQL 관련 rule은 가능한 경우 실제 API signature와 호출 문맥을 반영한 fixture로 검증한다.
- 테스트가 증명하는 범위를 넘어 지원을 주장하지 않는다. 미지원 구문, 불확실한 호출 해석 및 알려진 우회 사례를 명시적으로 기록한다.

