# 인프라 점검 스크립트 — 실행 가이드

서버·DBMS는 Ansible, 클라우드는 AWS CLI(boto3)로 자동 점검하고 결과를 xlsx 한 파일로
병합하는 스크립트입니다. **지금은 mgmt 서버에서 수동으로 실행**해주시면 됩니다(1차/2차
점검을 거치며 스크립트가 계속 수정될 가능성이 있어, cron 자동화는 이후 안정화되면 별도로
진행하겠습니다).

## 0. 준비

```bash
# Ansible 컬렉션 설치 (kubernetes.core, amazon.aws)
cd ansible
ansible-galaxy collection install -r requirements.yml

# ⚠ kubernetes.core는 파이썬 kubernetes 클라이언트 라이브러리가 별도로 있어야 동작합니다
# (컬렉션 설치와는 별개). 이게 없으면 DBMS 점검(DB 파드 조회·실행, Secret 조회)이 전부
# "조회 실패"로 나옵니다.
pip install kubernetes

# 클라우드 점검용 파이썬 패키지 설치
cd ../cloud
pip install -r requirements.txt
```

DB 조회 방식이 바뀌어 `community.mysql`, `community.postgresql` 컬렉션은 더 이상 필요 없습니다
(이전에 설치하셨다면 그대로 두셔도 됩니다).

인벤토리 설정:
```bash
cd ../ansible
cp inventory/hosts.ini.example inventory/hosts.ini
# hosts.ini 에 실제 EKS 워커노드/NAT 인스턴스 ID를 채우고,
# [eks_worker_nodes]·[nat_instances] 그룹에도 각 서버를 배정해주세요(U-64 기준 AMI 구분용).
```

인벤토리를 채운 뒤 아래 명령으로 **서버마다 서로 다른 인스턴스 ID가 나오는지** 확인해주세요.
같은 ID가 나오면 여러 대가 실제로는 한 대만 점검됩니다.
```bash
ansible server_targets -i inventory/hosts.ini -m command -a "cat /var/lib/cloud/data/instance-id"
```

AWS 인증은 mgmt 서버에 이미 구성된 AWS CLI 프로파일을 그대로 사용합니다(boto3 기본
자격증명 체인) — 별도 설정 불필요.

### 필요 권한

기존 점검에 쓰던 권한 외에 이번 전달분부터 아래 권한이 필요합니다.

| 구분 | 권한 | 용도 |
|---|---|---|
| K8s (`backend` 네임스페이스) | `pods` get/list, `pods/exec` create | DBMS 점검 쿼리를 DB 파드 안에서 실행 |
| K8s (`backend` 네임스페이스) | `secrets` get — `shared-mysql-dba-admin`, `shared-pg-dba-admin-credentials` | MySQL `dba_admin` 접속, D-03 비밀번호 자동 교체 이력 확인 |
| AWS | `config:DescribeDeliveryChannels` | 4.10 로그 저장 버킷(AWS Config) 자동 탐지 |
| AWS | `backup:ListBackupPlans`, `dlm:GetLifecyclePolicies` | 4.13 백업 정책 존재 여부 |
| AWS | `s3:GetBucketPublicAccessBlock`, `s3:GetBucketAcl` | 3.7 버킷 단위 공개 설정 확인(계정 단위 차단이 없을 때) |
| AWS | `ec2:DescribeNatGateways`, `ec2:DescribeVolumes` | 3.5 NAT 게이트웨이, 4.1 기존 EBS 볼륨 암호화 |
| AWS | `iam:SimulatePrincipalPolicy` | SVC-08 MFA 없이 SSM 접속이 허용되는 IAM 사용자 확인 |
| AWS | `iam:ListAttachedGroupPolicies`, `iam:ListRoles`, `iam:ListAttachedRolePolicies` | 1.1 관리자 그룹·Role 경유 관리자 권한 확인 |
| AWS | `s3:GetLifecycleConfiguration` | 4.12 S3 로그 버킷 보관기간(수명주기 삭제 규칙) |
| AWS | `logs:DescribeLogStreams` | 4.8 인스턴스별 CloudWatch 로그 스트림 보관 여부 |

### 실행 직전 확인

DBMS 점검은 DB 파드 안에서 조회하므로, 플레이북 실행 전에 아래 명령이 모두 성공하는지 먼저
확인해주세요. 하나라도 실패하면 DBMS 항목이 "조회 실패"로 나옵니다.
```bash
# 1) DB 파드 exec 권한 (yes가 나와야 정상)
kubectl auth can-i create pods/exec -n backend

# 2) MySQL 파드 안에서 dba_admin 접속
MYSQL_POD=$(kubectl get pods -n backend -l app.kubernetes.io/instance=shared-mysql -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n backend $MYSQL_POD -c mysqld -- mysql -u dba_admin -p"$(kubectl get secret shared-mysql-dba-admin -n backend -o jsonpath='{.data.password}' | base64 -d)" -e "SELECT 1"

# 3) PostgreSQL 파드 안에서 로컬 접속
PG_POD=$(kubectl get pods -n backend -l cnpg.io/cluster=shared-pg -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n backend $PG_POD -c postgres -- psql -c "SELECT 1"
```

## 1. 실행

프로젝트 최상위 폴더에서 아래 한 줄이면 서버·DBMS·클라우드 점검부터 최종 xlsx
병합까지 전부 실행됩니다.

```bash
./run_check.sh 1차 20260914
```

- 첫 번째 인자(`1차`)는 회차, 두 번째 인자(날짜, `YYYYMMDD`)는 생략하면 오늘 날짜가
  자동으로 들어갑니다.
- 완료되면 `results/{날짜}/infra_check_{날짜}_{회차}.xlsx` 파일과 그 파일의 SHA-256
  해시 파일(`.sha256`)이 함께 생성됩니다. 이 두 파일을 그대로 전달하시면 됩니다.
- U-33(숨김 파일) 전체 검색 목록이 서버별로 `ansible/results/{서버}_u33_hidden_{날짜}.log`에 남습니다.
  U-33이 FAIL이면 엑셀 상세의 "확인 필요" 파일을 보시고, 이 로그 파일도 같이 전달해주세요.
- U-15(무소유자 파일)가 있으면 전체 목록이 서버별로 `ansible/results/{서버}_u15_unowned_{날짜}.log`에 남습니다.
  엑셀 상세의 "그 외" 파일이 조치 대상이며, 이 로그 파일도 같이 전달해주세요.

## 2. 단계별로 나눠서 실행하고 싶다면

```bash
cd ansible
ansible-playbook -i inventory/hosts.ini site_check.yml -e check_round="1차"
python3 scripts/build_server_dbms_xlsx.py --round "1차" --date 20260914

cd ../cloud
python3 cloud_check.py --round "1차" --date 20260914
# EKS 클러스터 이름을 직접 지정하고 싶다면:
# python3 cloud_check.py --round "1차" --date 20260914 --eks-clusters my-cluster-1,my-cluster-2

cd ..
python3 merge_report.py --round "1차" --date 20260914
cd results/20260914
sha256sum infra_check_20260914_1차.xlsx > infra_check_20260914_1차.xlsx.sha256
```

`--date`를 생략하면 각 스크립트가 실행 시점의 오늘 날짜를 기본값으로 쓰므로, 날짜를
지정할 거라면 세 스크립트(`build_server_dbms_xlsx.py`/`cloud_check.py`/`merge_report.py`)
모두 같은 `--date` 값을 넘겨야 결과 파일을 서로 찾을 수 있습니다.

## 3. 결과 확인 시 참고

- 판정은 `PASS`/`FAIL`/`N/A`(해당없음)/`SKIP`(기준값 미확정)/`REVIEW`(수동 검토 필요) 5종입니다.
- 최종 xlsx의 **요약 시트**에 전체 개수와 SKIP 건수가 표시됩니다. SKIP이 나온 항목은
  `ansible/group_vars/all.yml` 또는 `cloud/config.py`에 해당 기준값이 아직 비어있다는
  뜻입니다 — 코드 수정 없이 값만 채우면 다음 실행부터 정상 판정됩니다.
- **DBMS는 DB 파드 안에서 조회합니다.** mgmt 서버에서 DB로 네트워크 접속하지 않고, DB 파드에
  DB 클라이언트 명령을 한 번씩 실행하는 방식입니다(대화형 쉘 접속 아님). MySQL은 `mysqld`
  컨테이너에서 `dba_admin` 계정으로, PostgreSQL은 `postgres` 컨테이너에서 로컬 접속으로
  조회합니다(PostgreSQL은 별도 Secret 불필요).
- 조회가 실패하면 해당 행의 상세에 **"조회 실패 — 원인: …"**으로 실제 에러가 표시됩니다.
  이 경우 그 내용을 그대로 알려주시면 원인 확인 후 다시 전달하겠습니다.
- **⚠ 실행 전에 CloudTrail과 VPC Flow Logs를 켜주세요.** 4.5/4.7/4.11 항목은 점검 스크립트가
  도는 동안 두 로그가 켜져 있어야 정상 PASS로 잡힙니다. 상시로 켜두실 필요는 없고, 점검
  실행 직전에 켜서 실행 완료될 때까지만 유지하시면 됩니다(끝나면 다시 꺼두셔도 됩니다).
- **다음 항목들은 스크립트 오류가 아니라 의도된 FAIL입니다** — 해당 기능이 아직 구현되지
  않았거나 구조상 기준을 충족할 수 없는 게 확인된 상태라 SKIP 대신 FAIL로 정직하게
  잡아두었습니다.
  - **D-26**: DB 감사 기록(pgAudit·감사 플러그인 등) 미설정
  - **D-03**: 서비스 계정에 비밀번호 만료·복잡도 정책 미적용(`dba_admin`은 자동 교체 이력으로 판정)
  - **D-01(PostgreSQL)**: CNPG 구성상 `postgres` 계정 비밀번호가 비어 있고 잠금도 불가 —
    상세에 구조적 사유가 함께 표시됩니다.
- **AUTHZ-09는 SKIP으로 표시됩니다.** RabbitMQ Management API 상시 접근 경로가 구조적으로
  구성 불가하다고 확인해주신 내용을 반영해, 자동 판정 대신 저희가 임시 계정 +
  `kubectl port-forward`로 수동 확인합니다(리포트에는 SKIP과 사유만 표시).

## 4. 문제가 있을 때

- 실행 중 오류가 나거나 판정이 이상하게 나온다고 판단되면, 어떤 명령을 실행했고
  어떤 결과/오류가 나왔는지와 함께 알려주세요.
