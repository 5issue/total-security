# 로컬 테스트 환경 (spec 6절)

어제 작성한 `../ansible`, `../cloud` 코드를 실제로 돌려보기 위한 VM 3대(Vagrant) + 테스트 AWS 계정(Terraform) 구성.
`ansible/`, `cloud/` 코드 자체는 건드리지 않고, 테스트에 필요한 값만 `ansible/group_vars/test_values.yml`(테스트 전용 파일)에 추가해뒀다.

## 구성

```
[VM control  192.168.56.10] Ansible 컨트롤 노드 — ../ansible, ../cloud 를 /infra-check 로 마운트
   │                         kind 클러스터(infracheck, Docker 위) — D-10 NetworkPolicy 검증 전용
   ├─(SSH)→ [VM server 192.168.56.11] 서버 role 대상 — U-01/U-07 의도적 FAIL
   └─(TCP)→ [VM dbms   192.168.56.12] DBMS role 대상 — MySQL+PostgreSQL, D-01/D-18 의도적 FAIL

[테스트 AWS 계정 893961164525 (default 프로파일)] — terraform/ 로 1.9/3.1/3.7 의도적 FAIL 리소스 생성
```

**D-10(원격 DB 서버 접속 제한)** 은 2026-09-09 인프라팀 확인으로 IP 허용목록이 아니라
K8s NetworkPolicy(라벨 기반 Pod 접근 제한) 방식으로 바뀌었다(spec 2.3절). VM3(DBMS) 설계는
그대로 두고(D-01/08/09/11/18/21은 계속 VM3의 MySQL/PostgreSQL로 검증), D-10만 control VM
안의 kind 클러스터로 검증한다(spec 6.6절). 라벨 값이 아직 미확정(`d10_allowed_np_label: null`)
이라 운영 판정은 REVIEW로 나가고, 로컬 테스트에서는 `test_values.yml`의 임의 라벨로
PASS/FAIL 분기까지 확인한다.

## 0. 공유 SSH 키 생성 (최초 1회, `.ssh/`는 gitignore 대상이라 저장소에 없음)

```bash
cd test
ssh-keygen -t ed25519 -f .ssh/id_ed25519_infracheck -N ""
```

## 1. VM 3대 띄우기

```bash
cd test
vagrant up          # 최초 실행 시 box 다운로드 포함 5~15분 정도 소요
```

- `control`: Ansible, ansible-galaxy 컬렉션(`requirements.yml`), boto3/openpyxl/kubernetes, PyMySQL/psycopg2 설치
- `server`: `/etc/ssh/sshd_config`에 `PermitRootLogin yes` 강제 설정(U-01 FAIL), `games` 계정을 로그인 가능한 shell로 생성(U-07 FAIL)
- `dbms`: MySQL 8.0 + PostgreSQL 15 설치. MySQL `root@localhost`는 기본값(잠금 해제 상태) 그대로 둬서 D-01 FAIL, PostgreSQL `testdb.accounts` 테이블에 `GRANT ... TO PUBLIC` 실행해서 D-18 FAIL
- `control` 추가 프로비저닝(`kind_setup.sh`): Docker + kubectl + kind 설치, `infracheck` 클러스터 생성,
  `k8s/namespace.yaml`·`pods.yaml`·`networkpolicies.yaml` 적용 — `mock-db-pass`(PASS 케이스, role=db-client
  라벨에서만 ingress 허용) / `mock-db-fail`(FAIL 케이스, NetworkPolicy 자체 미존재 = 무제한 허용)

## 2. 서버·DBMS 점검 실행

```bash
vagrant ssh control
cd /infra-check/ansible
ansible-playbook -i /infra-check/test/inventory/hosts.ini site_check.yml \
  -e check_round="테스트" -e @group_vars/test_values.yml
```

결과: `/infra-check/ansible/results/*.json` (호스트에서는 `../ansible/results/`로 그대로 보임 — synced folder).

확인 포인트:
- `vm2-server_*.json` 안에서 U-01, U-07이 `FAIL`인지
- `dbms_*.json` 안에서 vm3-mysql의 D-01, vm3-postgresql의 D-18이 `FAIL`인지
- `dbms_*.json` 안에서 kind-d10-pass-case의 D-10이 `PASS`, kind-d10-fail-case의 D-10이 `FAIL`인지
  (`test_values.yml`의 `d10_allowed_np_label` 덕분에 REVIEW가 아니라 실제 PASS/FAIL로 나와야 함 — 라벨이
  `all.yml`처럼 `null`이면 두 케이스 모두 REVIEW로 나오는 게 정상)
- 나머지 값 채워진 항목(U-08, D-02~06 등)이 REVIEW로 흐려지지 않고 PASS/FAIL로 정확히 나오는지

xlsx로 변환하려면 이어서:
```bash
python3 scripts/build_server_dbms_xlsx.py --round "테스트"
```

## 3. 클라우드(AWS) 점검용 테스트 리소스 (Terraform)

**계정: 893961164525 (AWS CLI `default` 프로파일 그대로 사용, 사용자 확인됨)**
**주의: 3.7 검증을 위해 계정 전체 S3 Public Access Block을 끈다.** 버킷별 자체 차단이 없는
다른 버킷도 이 기간 동안 노출될 수 있으니 **테스트 끝나면 바로 destroy**할 것.

```bash
cd test/terraform
terraform init
terraform apply
```

생성되는 것 (전부 `infracheck-test-` 접두어, 기존 fintech-platform 리소스와 무관한 신규 생성):
- IAM 사용자 1개(콘솔 로그인 프로필 O, MFA 디바이스 미등록) → 1.9 FAIL
- 보안그룹 1개(0.0.0.0/0:22 인바운드, 인스턴스 미연결) → 3.1 FAIL
- 계정 S3 Public Access Block 해제 + 퍼블릭 버킷 1개 → 3.7 FAIL

```bash
cd ../../cloud
python3 cloud_check.py --round "테스트" --test-config
```

확인 후 정리:
```bash
cd ../test/terraform
terraform destroy
```

EKS 관련 항목(1.11~1.13, 3.9, 4.14~4.15)은 spec 6.5절에 따라 로컬 재현 생략(인프라팀 사전테스트 단계에서 검증).
시간 경과형 항목(1.8 Access Key 60일 등)은 실측 대신 코드 로직 리뷰로 대체.

## 4. 전체 파이프라인(merge_report.py까지)

```bash
cd ../..   # script/
python3 merge_report.py --round "테스트" --date $(date +%Y%m%d)
```
최종 `infra_check_*.xlsx`의 시트 구성·판정(FAIL이 REVIEW로 흐려지지 않는지)을 spec 4.2~4.5절과 대조.

## 5. 정리

```bash
cd test
vagrant destroy -f
cd terraform && terraform destroy
```

## 파일 구성

```
test/
  Vagrantfile
  provision/
    control.sh        # VM1: ansible/boto3/collections 설치
    kind_setup.sh      # VM1: Docker+kind+kubectl 설치, infracheck 클러스터 생성, D-10 테스트 매니페스트 적용
    server_target.sh  # VM2: U-01/U-07 의도적 FAIL 세팅
    dbms_target.sh     # VM3: MySQL+PostgreSQL 설치, D-01/D-18 의도적 FAIL 세팅
  inventory/hosts.ini  # 로컬 테스트 전용 인벤토리 (ansible_connection=ssh)
  k8s/                 # D-10 검증용 kind 클러스터 매니페스트 (namespace/pods/networkpolicies)
  terraform/           # 테스트 AWS 계정 의도적 FAIL 리소스 (1.9/3.1/3.7)
  .ssh/                # 공유 SSH 키(gen 완료, gitignore 처리)
```

`ansible/group_vars/test_values.yml`에 이 VM 3대 테스트용 `dbms_connections`, `mysql_login_*`,
`pg_login_*`, `d10_allowed_np_label`을 추가해뒀다(실제 값 아님, all.yml에는 반영 금지 — 파일 상단 경고 참고).
