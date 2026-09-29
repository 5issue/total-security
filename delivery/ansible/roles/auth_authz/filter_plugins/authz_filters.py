"""AUTHZ-08, SVC-01 : Ingress/NetworkPolicy 판정 필터."""


def _selector_empty(sel):
    return not (sel or {}).get("matchLabels") and not (sel or {}).get("matchExpressions")


def authz08_exposed_paths(ingresses, prefix="/internal"):
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
                    hit = True
                elif ptype == "Exact":
                    hit = False
                elif wildcard:
                    hit = prefix.startswith(norm)
                else:
                    hit = norm == "" or prefix.startswith(norm + "/")
                if hit:
                    exposed.append(f"{name}: {path}({ptype})→{svc}")
    return exposed


def svc01_eval(netpols, service, namespace):
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
                    continue
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
