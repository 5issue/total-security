# alb_iam_policy.json 출처

- 원본: https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/main/docs/install/iam_policy.json
- 고정(pin) 시점: 2026-09-13
- 용도: 클라우드 점검 2.2(네트워크 서비스 정책 관리) — aws-load-balancer-controller IRSA
  역할의 실제 부여 권한이 이 공식 정책의 부분집합인지 대조(초과 권한만 FAIL).
- ⚠ 런타임에 이 URL을 매번 fetch하지 않는다(spec 3.1절 근거 — mgmt 서버 온프레미스
  외부망 제한, 외부 의존성이 점검 결과에 영향 주면 안 됨). 버전이 크게 바뀌면
  (v2.7~v2.11 범위 밖으로 이동 등) 이 파일을 수동으로 다시 받아 교체할 것.
