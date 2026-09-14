# 인프라 점검 클라우드(AWS boto3)

AWS CLI/boto3 read-only API로 클라우드 시트(1.x~4.x, 41개 항목)를 점검한다.
진입점은 `cloud_check.py`. 서버·DBMS(Ansible) 결과와의 병합은 `../merge_report.py` 참고.

## 구성

| 모듈 | 대상 항목 | 비고 |
|---|---|---|
| `checks/iam_checks.py` | 1.1~1.10, 2.3 | IAM 사용자·그룹·Access Key·MFA·패스워드 정책, 기타 서비스(KMS/S3/SecretManager) IAM 정책 |
| `checks/network_checks.py` | 3.1~3.6 | 보안그룹·NACL·라우팅테이블·IGW·NAT |
| `checks/storage_checks.py` | 3.7~3.8, 4.1~4.3, 4.9~4.10 | S3/EBS/RDS 접근·암호화 |
| `checks/logging_checks.py` | 4.4~4.8, 4.11~4.12 | 통신구간·CloudTrail·CloudWatch·VPC 플로우로그, 보관기간 |
| `checks/elb_checks.py` | 3.10 | ALB 제어정책(리스너/SSL Policy/액세스로그/Deletion Protection/헬스체크/보안그룹/Cross-Zone) |
| `checks/eks_checks.py` | 1.11~1.13, 2.1~2.2, 3.9, 4.14~4.15 | boto3 + kubernetes 파이썬 클라이언트(kubeconfig 필요). 인스턴스/네트워크 서비스 IAM 최소권한(2.1/2.2)이 EKS 노드그룹·ALB IRSA 대조라 이 파일로 옮겨와 있음 — 2.2는 VPC CNI IRSA 미분리가 구조적으로 확정된 사실이라 항상 REVIEW 이상(PASS 없음) |

판정유형이 "제외"로 확정된 항목(4.13 백업)은 코드로 작성하지 않고 `cloud_check.py`가
N/A 고정 행으로 삽입한다.

## 기준값 관리

- `config.py` — 실제 운영용. TODO(None) 항목은 값이 채워지기 전까지 해당 항목이 자동으로
  SKIP 처리된다(로직은 이미 작성되어 있음 — 값만 채우면 됨).
- `config_test.py` — **테스트 전용**, 로컬 검증 시에만 `--test-config` 플래그로 적용.
  `config.py`는 건드리지 않는다.

## 설치

```bash
pip install -r requirements.txt
```

## 실행

```bash
python3 cloud_check.py --round "1차"
python3 cloud_check.py --round "1차" --eks-clusters my-cluster-1,my-cluster-2
```

인증은 boto3 기본 자격증명 체인(환경변수/공유 credentials/인스턴스 프로파일)을 그대로
사용 — mgmt 서버에 이미 구성된 AWS CLI 프로파일이면 별도 설정 불필요. `--round` 미지정
시 `"정기점검"`으로 고정(매주 crontab 자동실행용).

## 결과 출력

`cloud_result.xlsx`(시트: 클라우드)를 생성한다. 컬럼: 항목ID/항목명/판정/상세/대상/점검일시/회차.
이 파일을 `../merge_report.py`가 서버·DBMS 결과와 합쳐 최종 `infra_check_*.xlsx`를 만든다 —
전체 흐름은 `../run_check.sh` 하나로 실행 가능.

## 아직 미착수 / 보류 (실제 계정 연동 후 확인 필요)

2026-09-13 인프라팀 대량 회신으로 1.1,1.2,1.4,1.6,1.11 / 2.1,2.2 / 3.2,3.6 / 3.10(Idle
Timeout) 는 전부 확정·자동판정 전환 완료됐다(해결된 항목은 이 표에서 제외). 아래는
2026-09-14 기준 여전히 열려있는 항목만 남긴다.

| 항목 | 이유 |
|---|---|
| 2.3(KMS/S3/SecretManager) | `config.SERVICE_IAM_POLICY_MAP` 아직 TODO(None) — 서비스 역할별 필요권한 정의서 확정 시 값만 채우면 됨(로직은 이미 작성됨, 값 없으면 자동 SKIP) |
| 1.8 | AWS Config Rule(`access-keys-rotated`)이 대상 계정에 배포돼 있어야 정상 판정 |
