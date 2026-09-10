# total-security

## 인프라 점검 자동화 (infra-check)

주요정보통신기반시설 기술적 취약점 분석·평가 기준(서버 67 / DBMS 26 항목)과
클라우드 보안가이드(AWS, 41항목)를 기준으로, 서버·DBMS는 **Ansible**, 클라우드는
**AWS CLI(boto3)**로 자동 점검하고 결과를 xlsx 한 파일로 병합해 산출하는 파이프라인.

### 구조

```
ansible/           서버(U-XX)·DBMS(D-XX) 점검 — 상세: ansible/README.md
cloud/             클라우드(1.x~4.x) 점검(boto3) — 상세: cloud/README.md
test/              로컬 검증 환경(Vagrant VM 3대 + 테스트 AWS 계정 + kind) — 상세: test/README.md
merge_report.py    서버·DBMS 결과 + 클라우드 결과 -> 최종 infra_check_*.xlsx 병합
run_check.sh       전체 파이프라인 한 번에 실행(mgmt 서버 crontab 등록용)
```

### 실행 흐름

```
[Ansible] 서버·DBMS 점검 -> server_dbms_result.xlsx (중간 산출물)
[boto3]   클라우드 점검   -> cloud_result.xlsx        (중간 산출물)
                              |
                    [merge_report.py]
                              |
        infra_check_{YYYYMMDD}_{회차}.xlsx (최종 산출물, 시트: 요약/서버/DBMS/클라우드)
                              |
                    SHA-256 해시 생성 후 결과물과 함께 전달
```

```bash
./run_check.sh 1차 20260914
```

### 기준값 관리 원칙

로직(무엇을 조회하고 어떻게 비교할지)과 기준값(구체적인 수치·목록)을 분리한다.
`ansible/group_vars/all.yml`, `cloud/config.py`에 기준값을 모아두고, 값이 없는(TODO)
항목은 로직은 이미 작성된 채로 자동 SKIP 처리된다 — 값만 채우면 코드 수정 없이 바로 동작.
로컬 검증 전용 임의값은 각각 `group_vars/test_values.yml`, `config_test.py`에 분리되어
있어 실제 운영값과 섞이지 않는다.

### 판정 값

`PASS` / `FAIL` / `N/A`(원문상 해당없음 확정) / `SKIP`(기준값 미확정) / `REVIEW`(화이트리스트
등 추가 수동 검토 필요) 5종. 기준값이 확정된 항목은 위반 시 예외 없이 `FAIL`로 판정하고,
기준값 자체가 협의 중이라는 사실로 판정을 흐리지 않는 것을 원칙으로 한다.

자세한 항목 커버리지, 미착수/보류 항목, 실행 방법은 `ansible/README.md`, `cloud/README.md`,
`test/README.md` 각각을 참고.
