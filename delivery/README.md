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
- **DBMS 접속 정보(`dbms_connections`)는 인프라팀이 준 서비스 계정 기준으로 채워져
  있습니다.** oms 서비스(PostgreSQL)만 Secret 미확정으로 제외돼 있어 SKIP으로 나옵니다.
- **⚠ MySQL D-04/D-11/D-21은 결과를 곧이곧대로 믿지 마세요.** 지금 쓰는 계정이 서비스별
  애플리케이션 계정이라, 이 세 항목은 다른 계정의 권한 정보를 볼 수 없어 실제로는 위반이
  있어도 PASS로 잘못 나올 수 있습니다(에러 없이 조용히 빈 결과만 나오는 경우). 관리자/감사
  계정을 받으면 이 부분만 다시 반영해서 전달하겠습니다.
- DB 연결 자체가 안 되거나(host 오타 등) 인프라팀 서비스어카운트에 Secret 읽기 권한이
  아직 없으면, 관련 DBMS 항목들이 FAIL이나 에러로 표시됩니다 — 이 경우 저희에게 알려주시면
  값만 다시 맞춰서 전달하겠습니다.

## 4. 문제가 있을 때

- 실행 중 오류가 나거나 판정이 이상하게 나온다고 판단되면, 어떤 명령을 실행했고
  어떤 결과/오류가 나왔는지와 함께 알려주세요.
