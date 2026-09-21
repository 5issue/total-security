# STEP 28 Ground-Truth Vulnerability Benchmark

이 benchmark는 SAST 기능 개발용 fixture와 분리된 작은 통제 프로젝트를 `ProjectScanner.javaDefaults()`로 분석해, 현재 공식 지원 범위의 탐지 결과를 ground truth와 대조하는 회귀 기준이다.

이 결과는 저장소 안에서 의도적으로 구성한 23개 case에만 해당한다. 실제 애플리케이션, 개발 중 backend snapshot 또는 일반 Java/Spring 프로젝트 전체의 precision/recall을 대표하지 않으며, finding 0개를 안전 판정으로 해석하지 않는다.

## 구성

- fixture project: `src/test/resources/benchmark/project`
- machine-readable manifest: `src/test/resources/benchmark/ground-truth.tsv`
- runner: `GroundTruthBenchmarkTest`

Manifest는 case ID, rule ID, vulnerability type, CWE, 기대 label, source file, 기대 finding 수, complexity level과 근거를 기록한다. Runner는 production `ProjectScanner`의 실제 `FindingResult`를 source file + rule ID + CWE로 매칭하고 vulnerability type과 CWE도 검증한다. 불일치가 있으면 전체 지표를 먼저 출력한 뒤 회귀 테스트를 실패시킨다. Expected label을 scanner 출력에 맞추어 자동 변경하지 않는다.

## Ground truth

| 취약점 | Rule ID | CWE | Positive | Negative | 주요 의미 |
|---|---|---|---:|---:|---|
| SQL Injection | `SQL_INJECTION` | CWE-89 | 2 | 1 | JDBC SQL text taint, exact cross-class flow, prepared binding safe |
| OS Command Injection | `OS_COMMAND_INJECTION` | CWE-78 | 1 | 1 | same-class helper를 통한 `Runtime.exec`, constant command safe |
| Path Traversal | `PATH_TRAVERSAL` | CWE-22 | 1 | 1 | request-body record accessor에서 filesystem path sink까지의 flow |
| SSRF | `SSRF` | CWE-918 | 1 | 1 | request target taint와 constant target 구분 |
| LDAP Injection | `LDAP_INJECTION` | CWE-90 | 1 | 1 | JNDI filter argument taint와 constant filter 구분 |
| XSS | `XSS` | CWE-79 | 1 | 1 | 명시적 HTML servlet response context의 raw output과 exact sanitizer 구분 |
| XXE | `XXE` | CWE-611 | 1 | 1 | 관찰된 unsafe/safe JAXP configuration 구분 |
| Open Redirect | `OPEN_REDIRECT` | CWE-601 | 1 | 1 | tainted complete redirect target과 fixed local target 구분 |
| Insecure Deserialization | `INSECURE_DESERIALIZATION` | CWE-502 | 1 | 1 | external request bytes 기반 `readObject`와 internal bytes 구분 |
| Unrestricted File Upload | `UNRESTRICTED_FILE_UPLOAD` | CWE-434 | 1 | 1 | attacker-controlled original filename과 fixed filename 구분 |
| Hardcoded Credential | `HARDCODED_CREDENTIAL` | CWE-798 | 1 | 1 | sensitive identifier의 literal과 runtime environment value 구분 |

Positive 12개, negative 11개다. Complexity 분포는 L1 20개, L2 1개, L3 1개, L4 1개이며 의미는 다음과 같다.

- L1: intraprocedural direct flow 또는 direct pattern
- L2: same-class helper flow
- L3: project-local cross-class flow
- L4: record/Lombok/accessor를 포함한 synthetic semantics flow

## 판정과 지표

판정 단위는 manifest case다.

- TP: vulnerable case에 기대한 finding이 존재
- FN: vulnerable case에 기대한 finding이 없음
- TN: safe case에 finding이 없음
- FP: safe case에 finding이 존재하거나 manifest에 없는 finding이 생성됨

Precision은 `TP / (TP + FP)`, recall은 `TP / (TP + FN)`, F1은 두 값의 조화 평균이다. 분모가 0이면 `N/A`로 출력한다.

현재 STEP 28 결과:

| Rule ID | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `SQL_INJECTION` | 2 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| `OS_COMMAND_INJECTION` | 1 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| `PATH_TRAVERSAL` | 1 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| `SSRF` | 1 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| `LDAP_INJECTION` | 1 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| `XSS` | 1 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| `XXE` | 1 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| `OPEN_REDIRECT` | 1 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| `INSECURE_DESERIALIZATION` | 1 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| `UNRESTRICTED_FILE_UPLOAD` | 1 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| `HARDCODED_CREDENTIAL` | 1 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| **전체** | **12** | **0** | **0** | **11** | **1.0000** | **1.0000** | **1.0000** |

현재 controlled fixture에는 알려진 FP/FN이 없다. 이는 구현의 일반적 정확도나 지원 범위 밖 의미의 처리를 증명하지 않는다. 새로운 case가 실제 miss를 드러내면 expected label을 바꾸지 않고 FP/FN과 원인을 이 문서에 기록한다.

## 실행

```powershell
.\gradlew.bat -g C:\project\total-security\sast\.gradle-user-home test --tests com.totalsecurity.sast.benchmark.GroundTruthBenchmarkTest --no-daemon --info
```

전체 회귀 검증은 `clean build`로 실행한다. Benchmark는 실제 backend를 읽거나 수정하지 않으며 production analyzer에 benchmark 전용 예외를 추가하지 않는다.
