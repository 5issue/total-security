# 인프라 점검 Ansible

서버·DBMS 자동 점검 코드. 전체 파이프라인(클라우드 boto3 + 병합 스크립트 포함)은
`../run_check.sh` 참고, 저장소 전체 개요는 `../README.md` 참고.

## 구성

| Role | 대상 항목 | 비고 |
|---|---|---|
| `roles/account_auth` | U-01~13, U-63 | 계정·인증 |
| `roles/file_permission` | U-14~30 계열(U-23,26 포함, U-26은 아직 TODO — 아래 표 참고) | 파일·디렉터리 권한 |
| `roles/network_service` | U-34~61 계열(U-37,42 포함) | 서비스 활성화 여부 |
| `roles/log_patch_check` | U-64(패치), U-66(로깅) | mgmt 서버 AWS CLI 조회(SSM/CloudWatch) — 2026-09-10 재분류(제외→자동판정가능(부분)) |
| `roles/dbms_common` | D-01~26 중 코드화 대상 18개 | mysql.yml/postgresql.yml(SQL) + k8s_pod_checks.yml(D-07,10,14,25 파드/K8s) + log_patch_check 재사용(D-26) |

판정유형이 "제외"로 확정된 항목(U-62 / D-12,13,15,16,19,22,23,24)은 role에
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
산출물)로 변환한다. 최종 산출물은 `../merge_report.py`가 클라우드 결과와 합쳐서 만든다 —
전체 흐름은 `../run_check.sh` 하나로 실행 가능.

## 아직 미착수 / 보류 (실제 인프라 연동 후 확인 필요)

2026-09-13/14 인프라팀 대량 회신으로 U-08·U-31,33,39~41,45,47,49~51,54,56~61,65·
D-02,03,04,05,06,10,20,21 등은 전부 확정·자동판정가능으로 전환 완료됐다(해결된 항목은
이 표에서 제외). 아래는 2026-09-14 기준 여전히 열려있는 항목만 남긴다.

| 항목 | 이유 |
|---|---|
| U-26 | `u26_dev_baseline_snapshot` 아직 빈 값(TODO) — 1차 점검 시 EKS 워커노드에서 직접 `ls /dev` 추출해 baseline으로 저장하기로 결정(인프라팀에 별도 요청 안 함) |
| U-28 | 처음부터 2차 점검행으로 설계됨(1차 대상 아님) — `u28_allowed_ips` TODO는 2차 점검 착수 시 채울 것 |
| D-17 | MySQL은 1차 스코프 제외 확정(SKIP). PostgreSQL은 관리자 화이트리스트(`postgres`)까지 확정됐지만, 실제 "Audit Table"의 위치/존재 여부가 아직 회신 없음 — D-26과 함께 별도 확인 필요, 확인 전까지는 pgAudit 로드 여부로만 판정 |
| U-64 | AMI 비교 방식·SSM 파라미터 경로 확정 완료 — `u64_nat_latest_ami_ssm_param`(NAT용, arm64 계열)은 kernel-default/minimal 확정이 100%는 아니라 1차 점검 시 `aws ssm get-parameter`로 실제 AMI ID와 대조 검증 권장 |
| U-23 | SUID/SGID 화이트리스트 확정값 있음 — 단, 파일럿 실측 결과 AL2023 표준 바이너리(`at`,`chage`,`write`,`screen` 등) 일부 누락 발견돼 보정 검토 중 |
| D-26 | `d26_audit_log_group_name` TODO — D-17 Audit Table 위치와 함께 별도 확인 필요, 값 확정 전까지 SKIP |
| D-07, D-10, D-14, D-25 | `dbms_connections`에 host/namespace/pod_label_selector 확정 필요(실제 MOCO/CNPG DB 파드 구축 진행 중) |
