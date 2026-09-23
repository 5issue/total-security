# 인프라 점검 스크립트 — 실행 가이드

서버·DBMS는 Ansible, 클라우드는 AWS CLI(boto3)로 자동 점검하고 결과를 xlsx 한 파일로
병합하는 스크립트입니다. **지금은 mgmt 서버에서 수동으로 실행**해주시면 됩니다(1차/2차
점검을 거치며 스크립트가 계속 수정될 가능성이 있어, cron 자동화는 이후 안정화되면 별도로
진행하겠습니다).

## 0. 준비

```bash
# Ansible 컬렉션 설치
cd ansible
ansible-galaxy collection install -r requirements.yml

# ⚠ 위 컬렉션 중 kubernetes.core는 별도로 파이썬 kubernetes 클라이언트 라이브러리가
# 있어야 동작합니다(컬렉션 설치와는 별개). 이게 없으면 DBMS 점검의 K8s Secret 조회
# 태스크가 전부 "No module named 'kubernetes'"로 실패하고 무시(ignoring)된 채
# 넘어가서, 이후 DB 쿼리들이 빈 자격증명으로 전부 "조회 실패"가 됩니다.
pip install kubernetes

# 클라우드 점검용 파이썬 패키지 설치
cd ../cloud
pip install -r requirements.txt
```

인벤토리 설정:
```bash
cd ../ansible
cp inventory/hosts.ini.example inventory/hosts.ini
# hosts.ini 에 실제 EKS 워커노드/NAT 인스턴스 ID를 채워주세요.
```

AWS 인증은 mgmt 서버에 이미 구성된 AWS CLI 프로파일을 그대로 사용합니다(boto3 기본
자격증명 체인) — 별도 설정 불필요.

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
- **DBMS 접속 정보(`dbms_connections`, `dbms_admin_connections`)는 인프라팀이 준 서비스/관리자
  계정 기준으로 채워져 있습니다.** oms 서비스(PostgreSQL)만 Secret 미확정으로 제외돼 있어
  SKIP으로 나옵니다. D-01/02/04/06/08/11/18/20/21은 관리자 계정(`dbms_admin_connections`)으로
  조회하도록 전환되어 있습니다.
- DB 연결 자체가 안 되거나(host 오타 등) 인프라팀 서비스어카운트/관리자 계정에 Secret 읽기
  권한이 아직 없으면, 관련 DBMS 항목들이 FAIL이나 에러로 표시됩니다 — 이 경우 저희에게
  알려주시면 값만 다시 맞춰서 전달하겠습니다.
- **⚠ 실행 전에 CloudTrail과 VPC Flow Logs를 켜주세요.** 4.5/4.7/4.11 항목은 점검 스크립트가
  도는 동안 두 로그가 켜져 있어야 정상 PASS로 잡힙니다. 상시로 켜두실 필요는 없고, 점검
  실행 직전에 켜서 실행 완료될 때까지만 유지하시면 됩니다(끝나면 다시 꺼두셔도 됩니다).
- **다음 항목들은 스크립트 오류가 아니라 의도된 FAIL입니다** — 해당 기능이 아직 구현되지
  않은 게 확인된 상태라 SKIP 대신 FAIL로 정직하게 잡아두었습니다. 구현되면 저희가 값만
  바꿔서 다시 전달드립니다: **D-26**(DB 감사로그 CloudWatch 미연동), **AUTHZ-09**(WMS/OMS
  RabbitMQ 계정 미분리), **D-03**(서비스 계정에 비밀번호 만료·복잡도 정책 미적용 —
  전용 유저 계정 생성 전까지는 함께 FAIL로 표시됩니다), **D-17**(MySQL 감사 플러그인
  미도입 — 오픈소스 후보는 있으나 보안·버전 지원 검토 중이라 도입 전까지 FAIL로
  표시됩니다).
- **AUTHZ-09는 계정 분리가 완료되면 FAIL이 아니라 SKIP으로 바뀝니다.** RabbitMQ
  Management API 상시 접근 경로가 구조적으로 구성 불가하다고 확인해주신 내용을 반영해,
  계정 분리 이후에는 자동 판정 대신 저희가 임시 관리자 계정 + `kubectl port-forward`로
  수동 확인하는 방식으로 전환됩니다(리포트에는 SKIP과 사유만 표시).
- **이번 전달분에서 `U-37`(crontab/at 권한), `D-01`(PostgreSQL 기본 계정 잠금),
  `3.10`(WAF가 ALB에 연결됐는지) 판정 로직을 보완했습니다** — 기존엔 U-37이
  `/etc/crontab` 파일 권한만 보고 at 서비스 관련(명령어 SUID, at 작업 파일 등)은
  누락돼 있었고, D-01은 PostgreSQL 쪽이 판정 없이 SKIP 고정이었고, 3.10은 WAF 연결
  여부 자체를 안 보고 있었습니다. 이번에 원문 기준대로 완전히 채워서 실측하도록
  고쳤습니다 — **의도된 FAIL이 아니라 실제 값을 그대로 판정에 반영하는 항목들**이라,
  WAF를 켜놓고 실행하시면 3.10은 정상적으로 PASS가 나올 겁니다. 이전 회차에 안 보이던
  FAIL이 새로 나오더라도 스크립트 오류가 아니라 실제 서버 설정을 반영한 결과이니
  참고 부탁드립니다.

## 4. 문제가 있을 때

- 실행 중 오류가 나거나 판정이 이상하게 나온다고 판단되면, 어떤 명령을 실행했고
  어떤 결과/오류가 나왔는지와 함께 알려주세요.
