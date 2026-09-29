"""인증_인가(AUTHZ-08, SVC-01) 판정용 필터 — K8s Ingress/NetworkPolicy 구조 분석.

[2026-09-28 축소실행본 v1.0 판정 기준 재대조]
- AUTHZ-08: 기존엔 Ingress 경로가 /internal로 "시작"할 때만 노출로 봐서, "/"·"/*"처럼 모든 경로를
  백엔드로 넘기는 규칙(→ 외부에서 /internal/* 도달 가능)을 놓쳤음.
- SVC-01: 기존엔 출발지를 podSelector의 app 라벨로만 세서 namespaceSelector(네임스페이스 전체 허용)·
  from 없음(전체 허용)을 무시했음 — 실제 차트(backend-service)가 backend 네임스페이스 전체를 허용하는
  구조인데도 PASS로 나왔던 원인.
"""


def _selector_empty(sel):
    return not (sel or {}).get("matchLabels") and not (sel or {}).get("matchExpressions")


def authz08_exposed_paths(ingresses, prefix="/internal"):
    """Ingress 규칙 중 외부에서 prefix(/internal) 경로까지 전달되는 것 목록.
    "ingress명: 경로(pathType)→서비스" 문자열 리스트."""
    exposed = []
    for ing in ingresses or []:
        name = ing.get("metadata", {}).get("name", "?")
        spec = ing.get("spec", {})
        if spec.get("defaultBackend") and not spec.get("rules"):
            exposed.append(f"{name}: defaultBackend(모든 경로)")
        for rule in spec.get("rules") or []:
            for p in (rule.get("http") or {}).get("paths") or []:
                path = p.get("path") or "/"
                ptype = p.get("pathType", "ImplementationSpecific")
                svc = (((p.get("backend") or {}).get("service") or {}).get("name")) or "?"
                wildcard = path.endswith("*")
                norm = path.rstrip("*").rstrip("/")
                if norm.startswith(prefix):
                    hit = True                                   # /internal 경로를 직접 노출
                elif ptype == "Exact":
                    hit = False
                elif wildcard:
                    hit = prefix.startswith(norm)                # ALB 와일드카드: /*, /int* 등
                else:
                    hit = norm == "" or prefix.startswith(norm + "/")  # Prefix: 경로 요소 단위 매칭
                if hit:
                    exposed.append(f"{name}: {path}({ptype})→{svc}")
    return exposed


def svc01_eval(netpols, service, namespace):
    """service(app 라벨)에 적용되는 NetworkPolicy의 ingress 출발지 분석.
    반환: protected(Ingress 정책 적용 여부), callers(허용된 같은 네임스페이스 서비스 app 라벨),
          wide(사실상 전체 허용 규칙), other_ns(다른 네임스페이스 허용 — 참고), policies(적용 정책명)."""
    applying = []
    for np in netpols or []:
        spec = np.get("spec", {})
        pod_sel = spec.get("podSelector") or {}
        if _selector_empty(pod_sel) or (pod_sel.get("matchLabels") or {}).get("app") == service:
            applying.append(np)

    protected, callers, wide, other_ns = False, set(), [], set()
    for np in applying:
        name = np.get("metadata", {}).get("name", "?")
        spec = np.get("spec", {})
        if "Ingress" in (spec.get("policyTypes") or []) or "ingress" in spec:
            protected = True
        for rule in spec.get("ingress") or []:
            peers = rule.get("from")
            if not peers:
                wide.append(f"{name}: 출발지 제한 없음(from 없음 — 모든 출발지 허용)")
                continue
            for peer in peers:
                if "ipBlock" in peer:
                    continue                                     # 엣지(ALB) 대역 — AUTHZ-08 소관
                ns_sel, pod_sel = peer.get("namespaceSelector"), peer.get("podSelector")
                if ns_sel is not None:
                    labels = ns_sel.get("matchLabels") or {}
                    target_ns = "*" if _selector_empty(ns_sel) else (
                        labels.get("kubernetes.io/metadata.name") or labels.get("name") or str(labels))
                    if target_ns not in ("*", namespace):
                        other_ns.add(target_ns if _selector_empty(pod_sel) else f"{target_ns}/{(pod_sel.get('matchLabels') or {}).get('app', '?')}")
                        continue
                    if _selector_empty(pod_sel):
                        wide.append(f"{name}: {'모든 네임스페이스' if target_ns == '*' else namespace + ' 네임스페이스'} 전체 허용")
                        continue
                if pod_sel is not None:
                    if _selector_empty(pod_sel):
                        wide.append(f"{name}: 네임스페이스 내 모든 파드 허용")
                        continue
                    ml = pod_sel.get("matchLabels") or {}
                    callers.add(ml.get("app") or str(ml))
    return {"protected": protected, "callers": sorted(callers), "wide": wide,
            "other_ns": sorted(other_ns), "policies": [np.get("metadata", {}).get("name", "?") for np in applying]}


class FilterModule(object):
    def filters(self):
        return {"authz08_exposed_paths": authz08_exposed_paths, "svc01_eval": svc01_eval}
