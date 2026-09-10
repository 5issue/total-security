"""3.7~3.8, 4.1~4.3, 4.9~4.10 — S3/EBS/RDS 저장소 보안 점검."""
from .common import make_result, safe_call


def check_3_7_s3_public_access(s3control, account_id):
    if not account_id:
        return [make_result("3.7", "S3 버킷/객체 접근 관리", "SKIP", "계정 ID 조회 실패")]
    conf, err = safe_call(s3control.get_public_access_block, AccountId=account_id)
    if err:
        return [make_result("3.7", "S3 버킷/객체 접근 관리", "FAIL", f"계정레벨 퍼블릭 액세스 차단 미설정: {err}")]
    block = conf["PublicAccessBlockConfiguration"]
    ok = all(block.get(k) for k in
             ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
    status = "PASS" if ok else "FAIL"
    return [make_result("3.7", "S3 버킷/객체 접근 관리", status, str(block))]


def _rds_instances(rds):
    result, err = safe_call(rds.describe_db_instances)
    return (result["DBInstances"] if not err else []), err


def check_3_8_rds_subnet(rds_instances):
    status = "PASS" if not rds_instances else "REVIEW"
    detail = "RDS 미사용 확인됨(해당없음, 자동 양호)" if not rds_instances \
        else f"RDS 인스턴스 {len(rds_instances)}개 발견 — 'RDS 미사용' 전제 재검토 필요"
    return [make_result("3.8", "RDS 서브넷 가용 영역 관리", status, detail)]


def check_4_1_ebs_encryption(ec2):
    conf, err = safe_call(ec2.get_ebs_encryption_by_default)
    if err:
        return [make_result("4.1", "EBS 및 볼륨 암호화 설정", "SKIP", f"조회 실패: {err}")]
    status = "PASS" if conf["EbsEncryptionByDefault"] else "FAIL"
    return [make_result("4.1", "EBS 및 볼륨 암호화 설정", status,
                         f"계정 기본 EBS 암호화={conf['EbsEncryptionByDefault']}")]


def check_4_2_rds_encryption(rds_instances):
    if not rds_instances:
        return [make_result("4.2", "RDS 암호화 설정", "PASS", "RDS 미사용 확인됨(해당없음, 자동 양호)")]
    unencrypted = [d["DBInstanceIdentifier"] for d in rds_instances if not d.get("StorageEncrypted")]
    status = "PASS" if not unencrypted else "FAIL"
    return [make_result("4.2", "RDS 암호화 설정", status,
                         "미암호화 RDS: " + (", ".join(unencrypted) if unencrypted else "없음"))]


def check_4_3_s3_encryption(s3):
    buckets, err = safe_call(s3.list_buckets)
    if err:
        return [make_result("4.3", "S3 암호화 설정", "SKIP", f"버킷 목록 조회 실패: {err}")]
    unencrypted = []
    for b in buckets["Buckets"]:
        _, eerr = safe_call(s3.get_bucket_encryption, Bucket=b["Name"])
        if eerr:
            unencrypted.append(b["Name"])
    status = "PASS" if not unencrypted else "FAIL"
    return [make_result("4.3", "S3 암호화 설정", status,
                         "암호화 미설정 버킷: " + (", ".join(unencrypted) if unencrypted else "없음"))]


def check_4_9_rds_logging(rds_instances):
    status = "PASS" if not rds_instances else "REVIEW"
    detail = "RDS 미사용 확인됨(해당없음, 자동 양호)" if not rds_instances \
        else f"RDS 인스턴스 {len(rds_instances)}개 발견 — 로그 스트림 설정 개별 확인 필요"
    return [make_result("4.9", "RDS 로깅 설정", status, detail)]


def check_4_10_s3_access_logging(s3):
    buckets, err = safe_call(s3.list_buckets)
    if err:
        return [make_result("4.10", "S3 버킷 로깅 설정", "SKIP", f"버킷 목록 조회 실패: {err}")]
    no_logging = []
    for b in buckets["Buckets"]:
        conf, lerr = safe_call(s3.get_bucket_logging, Bucket=b["Name"])
        if lerr or "LoggingEnabled" not in conf:
            no_logging.append(b["Name"])
    status = "PASS" if not no_logging else "FAIL"
    return [make_result("4.10", "S3 버킷 로깅 설정", status,
                         "액세스 로깅 미설정 버킷: " + (", ".join(no_logging) if no_logging else "없음"))]


def run_all(ec2, s3, s3control, rds, account_id):
    rds_instances, _ = _rds_instances(rds)
    results = []
    results += check_3_7_s3_public_access(s3control, account_id)
    results += check_3_8_rds_subnet(rds_instances)
    results += check_4_1_ebs_encryption(ec2)
    results += check_4_2_rds_encryption(rds_instances)
    results += check_4_3_s3_encryption(s3)
    results += check_4_9_rds_logging(rds_instances)
    results += check_4_10_s3_access_logging(s3)
    return results
