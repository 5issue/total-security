# 인프라 점검 Ansible

`claude_code_handoff_spec.md`(script/ 상위) 기준으로 서버·DBMS 자동 점검 코드를 구성했다.
전체 파이프라인(클라우드 boto3 + 병합 스크립트 포함)은 `script/run_check.sh` 참고.

## 구성

| Role | 대상 항목 | 비고 |
|---|---|---|
| `roles/account_auth` | U-01~13, U-63 (+U-08 SKIP) | 계정·인증 |
| `roles/file_permission` | U-14~30 계열(U-23,26 포함) | 파일·디렉터리 권한 |
| `roles/network_service` | U-34~61 계열(U-37,42 포함) | 서비스 활성화 여부 |
| `roles/dbms_common` | D-01~26 중 코드화 대상 17개 | mysql.yml/postgresql.yml(SQL) + k8s_pod_checks.yml(D-07,14 파드레벨) |

판정유형이 "제외"로 확정된 항목(U-62,64,66 / D-12,13,15,16,19,22,23,24,26)은 role에
코드로 작성하지 않고, `scripts/build_server_dbms_xlsx.py`가 N/A 고정 행으로 삽입한다.

## 기준값 관리

- `group_vars/all.yml` — 실제 운영용. TODO(null) 항목은 값이 채워지기 전까지 해당 항목이
  자동으로 SKIP 처리된다(로직은 이미 작성되어 있음 — 값만 채우면 됨).
- `group_vars/test_values.yml` — **테스트 전용**, 로컬 VM 검증 시에만 `-e @group_vars/test_values.yml`
  로 얹어서 사용. all.yml은 건드리지 않는다.

## 설치

```bash
ansible-galaxy collection install -r requirements.yml
```

## 실행

```bash
cp inventory/hosts.ini.example inventory/hosts.ini
# hosts.ini 에 실제 인스턴스 ID(SSM) 채운 뒤:
ansible-playbook -i inventory/hosts.ini site_check.yml -e check_round="1차"
```

`check_round` 미지정 시 `"정기점검"`으로 고정(매주 crontab 자동실행용).

## 결과 출력

각 호스트/DBMS 실행마다 `results/` 아래 JSON 파일 생성:

```json
{
  "host": "worker-node-1",
  "checked_at": "2026-09-14T10:00:00+09:00",
  "round": "1차",
  "results": [
    {"id": "U-01", "item": "root 계정 원격 접속 차단", "status": "PASS", "detail": "..."}
  ]
}
```

DBMS 결과 항목에는 `target`(서비스명) 필드가 추가로 포함된다.

이 JSON들을 `scripts/build_server_dbms_xlsx.py`가 읽어 `server_dbms_result.xlsx`(중간
산출물)로 변환한다. 최종 산출물은 `merge_report.py`가 클라우드 결과와 합쳐서 만든다 —
전체 흐름은 `script/run_check.sh` 하나로 실행 가능.

## 아직 미착수 / 보류 (실제 인프라 연동 후 확인 필요)

| 항목 | 이유 |
|---|---|
| U-08,23,26,28,31,33,40,45,47,49,50,51,56,61,65 / D-02,03,04,05,06,10,17,20 | 기준값 TODO — `group_vars/all.yml`에 표시. 값 확정 시 해당 파일만 수정 |
| D-07, D-14 | `dbms_connections`에 host/namespace/pod_label_selector 확정 필요(DB 구축 진행 중) |
| 로컬 VM 파일럿 테스트 | 스펙 6절 참고 — 사용자 환경에서 진행 |
