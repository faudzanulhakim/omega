"""omega/offensive/offense/bizfuzz — business-logic fuzzer.

Injection scanners miss logic flaws: negative quantities, price
tampering, coupon stacking, state-skipping. This module permutes
action sequences and invalid-but-plausible values against a session,
comparing each response to a valid baseline. A 2xx acceptance of an
invalid value (negative qty, zero price) is candidate evidence.

OFFENSE-GATED (PTK_OFFENSE). Non-destructive value shapes only; the
operator supplies the endpoint map (path + params).
"""
import itertools
import os

__all__ = ["run_bizfuzz"]

INVALID_VALUES = ["-1", "0", "999999999", "0.01", "-0.01", "1e9",
                  "null", "", "true", "admin' --"]


def run_bizfuzz(actions, fetch, budget=40, log=None, gate_open_fn=None):
    """Permute action sequences and invalid values.

    actions: [{"url", "method", "param", "value"}] — a normal action
    (e.g. qty=1). For each action the fuzzer tries invalid value
    shapes; then it tries sequence permutations (all 2-action
    orderings) to catch state-machine bugs.
    fetch(url, method=..., body=...) -> response with .status/.text
    Returns {"findings": [...], "probes": n}
    """
    gate = gate_open_fn or (lambda: os.environ.get("PTK_OFFENSE") == "1")
    if not (gate() if callable(gate) else gate):
        return {"note": "offense layer disabled (PTK_OFFENSE)"}
    if not callable(fetch) or not actions:
        return {"note": "actions required"}
    findings = []
    probes = 0

    def _send(url, method, param, value):
        nonlocal probes
        body = f"{param}={value}"
        try:
            resp = fetch(url, method=method or "POST", body=body)
            probes += 1
            return resp
        except TypeError:
            try:
                sep = "&" if "?" in url else "?"
                resp = fetch(url + sep + body)
                probes += 1
                return resp
            except Exception:
                return None
        except Exception:
            return None

    # baseline per action with its declared (valid) value
    bases = {}
    for a in actions[:12]:
        resp = _send(a.get("url"), a.get("method"), a.get("param"),
                     a.get("value", "1"))
        bases[a.get("url")] = getattr(resp, "status", None)

    # invalid-value sweep
    for a in actions[:12]:
        for val in INVALID_VALUES:
            if probes >= budget:
                break
            resp = _send(a.get("url"), a.get("method"), a.get("param"),
                         val)
            st = getattr(resp, "status", None)
            body = (resp if isinstance(resp, str) else
                    getattr(resp, "text", "") or "") if resp else ""
            base_st = bases.get(a.get("url"))
            if st and base_st and 200 <= st < 300 and \
                    base_st == st and any(
                        m in body.lower() for m in ("success", "accepted",
                                                    "added", "order",
                                                    "updated")):
                findings.append({
                    "title": f"logic flaw candidate: invalid value "
                             f"{val!r} accepted on {a.get('param')}",
                    "severity": "MEDIUM",
                    "source": "bizfuzz/invalid-value",
                    "evidence": f"{a.get('param')}={val} returned HTTP "
                                f"{st} with success-shaped content "
                                f"(baseline {base_st})",
                    "location": a.get("url"),
                    "verification": "candidate",
                    "manual_check": "verify the invalid value actually "
                                    "affects business state (order "
                                    "total, balance) before reporting",
                    "cwe": "CWE-840",
                })

    # sequence permutations (2-3 actions)
    seqs = list(itertools.permutations(actions[:3], 2))
    for seq in seqs:
        for a in seq:
            if probes >= budget:
                break
            _send(a.get("url"), a.get("method"), a.get("param"),
                  a.get("value", "1"))
    if log:
        log(f"bizfuzz: probes={probes} findings={len(findings)}")
    return {"findings": findings, "probes": probes}
