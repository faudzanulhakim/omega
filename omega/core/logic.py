"""omega/core/logic — business-logic test templates.

Expert pentesters test the SHAPE of business flows, not just payloads:
negative prices, quantity overflow, double redemption, IDOR swaps,
step skipping. Each template is a deterministic checklist; the runner
sends the operator-supplied requests (or benign variants) and reports
candidate signals only.

Templates are declarative dicts so they can be audited and extended:
    {"name", "signal_regex", "steps": [{"desc", "method", "path",
     "body", "expect"}], "why"}
"""
import re

TEMPLATES = [
    {"name": "idor-swap",
     "signal_regex": r"user_id|account|profile|/api/(me|user)",
     "why": "sequential object IDs without per-object authz",
     "steps": [
         {"desc": "swap the object id to an adjacent value",
          "method": "GET", "path": "/api/user/2", "body": None,
          "expect": "should be 401/403 when the caller is not user 2"},
         {"desc": "swap again one higher",
          "method": "GET", "path": "/api/user/3", "body": None,
          "expect": "same authorization check applies"},
     ]},
    {"name": "price-tamper",
     "signal_regex": r"price|amount|total|cart|checkout|order",
     "why": "server trusts client-side price/amount fields",
     "steps": [
         {"desc": "submit a negative price",
          "method": "POST", "path": "/api/cart",
          "body": '{"price":-1,"qty":1}',
          "expect": "server rejects or normalizes to >= 0"},
         {"desc": "submit a huge quantity",
          "method": "POST", "path": "/api/cart",
          "body": '{"price":1,"qty":999999999}',
          "expect": "server caps the quantity"},
     ]},
    {"name": "redeem-twice",
     "signal_regex": r"redeem|voucher|coupon|promo|invite|code",
     "why": "one-time codes are not atomically consumed",
     "steps": [
         {"desc": "replay the same redeem request twice",
          "method": "POST", "path": "/api/redeem",
          "body": '{"code":"OMEGA-TEST"}',
          "expect": "second request must be refused"},
     ]},
    {"name": "step-skip",
     "signal_regex": r"step|checkout|verify|confirm|kyc|onboard",
     "why": "multi-step flows trust the client's step marker",
     "steps": [
         {"desc": "jump straight to the final step",
          "method": "POST", "path": "/api/checkout/final",
          "body": '{"step":3}', "expect": "server refuses skipped "
          "prerequisites"},
     ]},
    {"name": "role-escalation",
     "signal_regex": r"role|admin|permission|privilege",
     "why": "role/privilege fields accepted from the client",
     "steps": [
         {"desc": "send role=admin in a profile update",
          "method": "POST", "path": "/api/profile",
          "body": '{"role":"admin"}',
          "expect": "field ignored or rejected for non-admins"},
     ]},
]


def applicable_templates(surface_text):
    """Templates whose signal appears in the observed surface text."""
    low = str(surface_text or "").lower()
    out = []
    for t in TEMPLATES:
        if re.search(t["signal_regex"], low):
            out.append(t)
    return out


def run_logic_templates(target, surface_text=None, fetch=None,
                        dry_run=False, log=None):
    """Run applicable business-logic templates.

    In dry_run mode (the default when no fetch is given) it returns
    the checklist WITHOUT sending anything — the operator can review
    exactly what would be sent. Real sends are candidate-grade only.
    """
    templates = applicable_templates(surface_text)
    results = []
    for t in templates:
        result = {"name": t["name"], "why": t["why"], "steps": []}
        for step in t["steps"]:
            url = str(target).rstrip("/") + step["path"]
            if dry_run or fetch is None:
                result["steps"].append({
                    "desc": step["desc"], "request":
                    "%s %s" % (step["method"], url),
                    "body": step["body"], "expect": step["expect"],
                    "sent": False})
                continue
            try:
                st, headers, body = fetch(step["method"], url,
                                          body=step["body"])
                text = (body or b"").decode("latin-1", "replace")
                buggy = st is not None and st < 400 and t["name"] in (
                    "price-tamper", "redeem-twice", "role-escalation",
                    "idor-swap", "step-skip")
                result["steps"].append({
                    "desc": step["desc"], "request":
                    "%s %s" % (step["method"], url),
                    "status": st, "expect": step["expect"],
                    "sent": True,
                    "signal": ("accepted (%s) — verify business "
                               "impact manually" % st) if buggy else
                              "rejected (%s)" % st})
            except Exception as exc:
                result["steps"].append({"desc": step["desc"],
                                        "error": str(exc)})
        results.append(result)
    if log:
        log("logic: %d template(s) applicable, dry_run=%s"
            % (len(results), bool(dry_run or fetch is None)))
    return {"target": target, "templates": results,
            "dry_run": bool(dry_run or fetch is None)}


def findings_from_result(doc):
    """Convert accepted-step signals into candidate findings."""
    findings = []
    for t in doc.get("templates") or []:
        for s in t.get("steps") or []:
            if s.get("sent") and "accepted" in str(s.get("signal")):
                findings.append({
                    "title": "business-logic weakness suspected: %s"
                             % t["name"],
                    "severity": "MEDIUM",
                    "verification": "candidate",
                    "source": "logic/%s" % t["name"],
                    "evidence": "%s -> HTTP %s (%s)"
                                % (s["request"], s.get("status"),
                                   s.get("signal")),
                    "location": s["request"].split(" ", 1)[-1],
                    "manual_check": "replay %s with two different "
                                    "accounts and compare outcomes"
                                    % s["request"],
                })
    return findings
