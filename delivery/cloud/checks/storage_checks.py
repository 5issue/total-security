"""3.7~3.8, 4.1~4.3, 4.9~4.10 — S3/EBS/RDS 저장소 보안 점검."""
import json

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


def _log_storage_buckets(cloudtrail, elbv2, ec2, ssm, awsconfig):
    """CloudTrail·ALB 액세스로그·VPC 플로우로그(S3)·SSM 세션로그·AWS Config가 로그를 쌓는
    버킷을 자동 탐지한다. 반환: ({버킷명: {출처,...}}, [탐지 실패 출처])"""
    found, errors = {}, []

    def add(bucket, source):
        if bucket:
            found.setdefault(bucket, set()).add(source)

    trails, err = safe_call(cloudtrail.describe_trails)
    if err:
        errors.append(f"CloudTrail({err})")
    else:
        for t in trails["trailList"]:
            add(t.get("S3BucketName"), "CloudTrail")

    lbs, err = safe_call(elbv2.describe_load_balancers)
    if err:
        errors.append(f"ALB({err})")
    else:
        for lb in lbs["LoadBalancers"]:
            attrs, aerr = safe_call(elbv2.describe_load_balancer_attributes, LoadBalancerArn=lb["LoadBalancerArn"])
            if aerr:
                errors.append(f"ALB {lb['LoadBalancerName']}({aerr})")
                continue
            a = {x["Key"]: x["Value"] for x in attrs["Attributes"]}
            if a.get("access_logs.s3.enabled") == "true":
                add(a.get("access_logs.s3.bucket"), "ALB 액세스로그")

    flow_logs, err = safe_call(ec2.describe_flow_logs)
    if err:
        errors.append(f"VPC 플로우로그({err})")
    else:
        for fl in flow_logs["FlowLogs"]:
            dest = fl.get("LogDestination", "")
            if fl.get("LogDestinationType") == "s3" and dest.startswith("arn:aws:s3:::"):
                add(dest[len("arn:aws:s3:::"):].split("/", 1)[0], "VPC 플로우로그")

    doc, err = safe_call(ssm.get_document, Name="SSM-SessionManagerRunShell")
    if err:
        errors.append(f"SSM 세션로그({err})")
    else:
        try:
            add(json.loads(doc["Content"]).get("inputs", {}).get("s3BucketName"), "SSM 세션로그")
        except (TypeError, ValueError, KeyError) as e:
            errors.append(f"SSM 세션로그(문서 파싱 실패: {e})")

    channels, err = safe_call(awsconfig.describe_delivery_channels)
    if err:
        errors.append(f"AWS Config({err})")
    else:
        for ch in channels["DeliveryChannels"]:
            add(ch.get("s3BucketName"), "AWS Config")

    return found, errors


def check_4_10_s3_access_logging(s3, log_buckets, detect_errors):
    # 로그 보관 버킷(자동 탐지)만 판정 — 액세스 로그 수신 전용 버킷은 대상 아님, 탐지 일부 실패 시 REVIEW
    item = "S3 버킷 로깅 설정"
    err_note = f" / 탐지 실패 출처(권한 확인 필요): {', '.join(detect_errors)}" if detect_errors else ""
    if not log_buckets:
        status = "SKIP" if detect_errors else "N/A"
        return [make_result("4.10", item, status, "로그 보관 버킷 탐지 결과 없음" + err_note)]
    no_logging, logging_ok = [], []
    for bucket in sorted(log_buckets):
        label = f"{bucket}[{', '.join(sorted(log_buckets[bucket]))}]"
        conf, lerr = safe_call(s3.get_bucket_logging, Bucket=bucket)
        if lerr:
            no_logging.append(f"{label}(조회 실패: {lerr})")
        elif "LoggingEnabled" not in conf:
            no_logging.append(label)
        else:
            logging_ok.append(f"{label}→{conf['LoggingEnabled'].get('TargetBucket', '?')}")
    status = "FAIL" if no_logging else ("REVIEW" if detect_errors else "PASS")
    detail = ("로그 보관 버킷(자동 탐지) 중 서버 액세스 로깅 미설정: " + (", ".join(no_logging) if no_logging else "없음")
              + " / 설정됨(→수신 버킷): " + (", ".join(logging_ok) if logging_ok else "없음")
              + err_note)
    return [make_result("4.10", item, status, detail)]


def run_all(ec2, s3, s3control, rds, account_id, cloudtrail, elbv2, ssm, awsconfig):
    rds_instances, _ = _rds_instances(rds)
    results = []
    results += check_3_7_s3_public_access(s3control, account_id)
    results += check_3_8_rds_subnet(rds_instances)
    results += check_4_1_ebs_encryption(ec2)
    results += check_4_2_rds_encryption(rds_instances)
    results += check_4_3_s3_encryption(s3)
    results += check_4_9_rds_logging(rds_instances)
    log_buckets, detect_errors = _log_storage_buckets(cloudtrail, elbv2, ec2, ssm, awsconfig)
    results += check_4_10_s3_access_logging(s3, log_buckets, detect_errors)
    return results
