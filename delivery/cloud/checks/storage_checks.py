"""3.7~3.8, 4.1~4.3, 4.9~4.10, 4.13 — S3/EBS/RDS 저장소 보안·백업 점검."""
import json

import config
from .common import make_result, safe_call


PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GRANTEE_URIS = ("http://acs.amazonaws.com/groups/global/AllUsers",
                       "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")


def check_3_7_s3_public_access(s3, s3control, account_id):
    if not account_id:
        return [make_result("3.7", "S3 버킷/객체 접근 관리", "SKIP", "계정 ID 조회 실패")]
    conf, err = safe_call(s3control.get_public_access_block, AccountId=account_id)
    account_block = {} if err else conf["PublicAccessBlockConfiguration"]
    if all(account_block.get(k) for k in PAB_KEYS):
        return [make_result("3.7", "S3 버킷/객체 접근 관리", "PASS", f"계정 단위 퍼블릭 액세스 차단 설정: {account_block}")]

    buckets, berr = safe_call(s3.list_buckets)
    if berr:
        return [make_result("3.7", "S3 버킷/객체 접근 관리", "SKIP",
                             f"계정 단위 차단 미설정, 버킷 목록 조회 실패: {berr}")]
    owner_id = buckets.get("Owner", {}).get("ID")
    offenders, unknown = [], []
    for b in buckets["Buckets"]:
        name = b["Name"]
        pab, perr = safe_call(s3.get_public_access_block, Bucket=name)
        if not perr and all(pab["PublicAccessBlockConfiguration"].get(k) for k in PAB_KEYS):
            continue
        acl, aerr = safe_call(s3.get_bucket_acl, Bucket=name)
        if aerr:
            unknown.append(f"{name}(ACL 조회 실패)")
            continue
        exposed = [g["Grantee"].get("URI") or g["Grantee"].get("ID") for g in acl["Grants"]
                   if g["Grantee"].get("URI") in PUBLIC_GRANTEE_URIS
                   or (g["Grantee"].get("Type") == "CanonicalUser" and g["Grantee"].get("ID") != owner_id)]
        if exposed:
            offenders.append(f"{name}(차단 미설정 + ACL 공개/외부 계정 부여)")
    status = "FAIL" if offenders else ("REVIEW" if unknown else "PASS")
    detail = ("계정 단위 퍼블릭 액세스 차단 미설정 — 버킷별 확인: 차단 미설정이면서 ACL이 모든 사람·외부 계정에 부여된 버킷: "
              + (", ".join(offenders) if offenders else "없음")
              + (f" / 확인 불가: {', '.join(unknown)}" if unknown else ""))
    return [make_result("3.7", "S3 버킷/객체 접근 관리", status, detail)]


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
    unencrypted, verr = [], None
    paginator = ec2.get_paginator("describe_volumes")
    pages, verr = safe_call(lambda: list(paginator.paginate(Filters=[{"Name": "encrypted", "Values": ["false"]}])))
    if not verr:
        unencrypted = [v["VolumeId"] for page in pages for v in page["Volumes"]]
    default_on = conf["EbsEncryptionByDefault"]
    status = "PASS" if default_on and not unencrypted and not verr else "FAIL"
    detail = (f"계정 기본 EBS 암호화={default_on} / 미암호화 볼륨: "
              + (f"조회 실패({verr})" if verr else (", ".join(unencrypted[:10]) + (f" 외 {len(unencrypted) - 10}개" if len(unencrypted) > 10 else "")
                                                   if unencrypted else "없음")))
    return [make_result("4.1", "EBS 및 볼륨 암호화 설정", status, detail)]


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


def check_4_12_log_retention(logs, s3, log_buckets, detect_errors):
    item = "로그 보관 기간 설정"
    short, notes = [], []
    paginator = logs.get_paginator("describe_log_groups")
    groups, gerr = safe_call(lambda: [g for page in paginator.paginate() for g in page["logGroups"]])
    if gerr:
        notes.append(f"CloudWatch 로그그룹 조회 실패: {gerr}")
    else:
        short += [f"{g['logGroupName']}({g['retentionInDays']}일)" for g in groups
                  if g.get("retentionInDays") and g["retentionInDays"] < config.LOG_RETENTION_MIN_DAYS]
    for bucket, sources in sorted(log_buckets.items()):
        lc, lerr = safe_call(s3.get_bucket_lifecycle_configuration, Bucket=bucket)
        if lerr:
            if "NoSuchLifecycleConfiguration" not in lerr:
                notes.append(f"s3://{bucket} 수명주기 조회 실패: {lerr}")
            continue
        days = [r["Expiration"]["Days"] for r in lc.get("Rules", [])
                if r.get("Status") == "Enabled" and r.get("Expiration", {}).get("Days")]
        if days and min(days) < config.LOG_RETENTION_MIN_DAYS:
            short.append(f"s3://{bucket}({'/'.join(sorted(sources))}, {min(days)}일 후 삭제)")
    notes += [f"로그 버킷 탐지 실패 출처: {', '.join(detect_errors)}"] if detect_errors else []
    status = "FAIL" if short else ("REVIEW" if notes else "PASS")
    detail = (f"기준({config.LOG_RETENTION_MIN_DAYS}일) 미만 보관 — CloudWatch 로그그룹·S3 로그 버킷: "
              + (", ".join(short[:10]) + (f" 외 {len(short) - 10}건" if len(short) > 10 else "") if short else "없음")
              + f" (확인한 S3 로그 버킷 {len(log_buckets)}개)"
              + (" / " + " / ".join(notes) if notes else ""))
    return [make_result("4.12", item, status, detail)]


def check_4_13_backup_policy(backup, dlm):
    plans, perr = safe_call(backup.list_backup_plans)
    policies, derr = safe_call(dlm.get_lifecycle_policies, State="ENABLED")
    if perr and derr:
        return [make_result("4.13", "백업 사용 여부", "SKIP", f"AWS Backup 조회 실패: {perr} / DLM 조회 실패: {derr}")]
    plan_names = [] if perr else [p["BackupPlanName"] for p in plans.get("BackupPlansList", [])]
    policy_ids = [] if derr else [p["PolicyId"] for p in policies.get("Policies", [])]
    status = "PASS" if (plan_names or policy_ids) else ("REVIEW" if (perr or derr) else "FAIL")
    detail = ("AWS Backup 백업 계획: " + (f"조회 실패({perr})" if perr else (", ".join(plan_names) or "없음"))
              + " / 활성 DLM(EBS 스냅샷) 정책: " + (f"조회 실패({derr})" if derr else (", ".join(policy_ids) or "없음"))
              + " — 참고: DB는 MOCO·CNPG 오퍼레이터가 S3로 백업(이 조회 대상 아님)")
    return [make_result("4.13", "백업 사용 여부", status, detail)]


def run_all(ec2, s3, s3control, rds, account_id, cloudtrail, elbv2, ssm, awsconfig, backup, dlm, logs):
    rds_instances, _ = _rds_instances(rds)
    results = []
    results += check_3_7_s3_public_access(s3, s3control, account_id)
    results += check_3_8_rds_subnet(rds_instances)
    results += check_4_1_ebs_encryption(ec2)
    results += check_4_2_rds_encryption(rds_instances)
    results += check_4_3_s3_encryption(s3)
    results += check_4_9_rds_logging(rds_instances)
    log_buckets, detect_errors = _log_storage_buckets(cloudtrail, elbv2, ec2, ssm, awsconfig)
    results += check_4_10_s3_access_logging(s3, log_buckets, detect_errors)
    results += check_4_12_log_retention(logs, s3, log_buckets, detect_errors)
    results += check_4_13_backup_policy(backup, dlm)
    return results
