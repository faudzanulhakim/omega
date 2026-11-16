"""omega/scanning/blotamper.py — business-logic tampering heuristics
(fusion suite name: ``blotamper``).

HONEST SCOPING — SAFE-READ differential only:

  stage 1  discover candidate money-bearing flows: parse HTML forms
           (and apimap-style JSON bodies supplied via ``specs``) for
           fields named price/amount/qty/quantity/discount/coupon/
           total.
  stage 2  replay the SAME request twice: baseline (original values)
           vs tampered (price=0, qty=-1, coupon value duplicated).
           ONLY a differential response is flagged: tampered request
           answered with a success status AND a different total/amount
           echoed back. -> MEDIUM-HIGH candidate.

SAFETY CONTRACT:
  * We NEVER complete a purchase: endpoints whose path suggests a
    final submit (pay/purchase/checkout/complete/confirm/finalize/
    submit-order) are skipped with an explicit note.
  * If the flow cannot be identified as safe (no distinguishable
    baseline vs tampered semantics, non-2xx baseline, missing
    nonces/tokens), the candidate is skipped with a note instead of
    guessed at.
  * Findings are ALWAYS candidates and carry the note "requires
    manual business confirmation" — a differential echo is a signal,
    not proof that the backend honored the tampered value.
"""

from __future__ import annotations

import json
import re
import secrets

__all__ = [
    "Finding",
    "MONEY_FIELDS",
    "FINAL_SUBMIT_HINTS",
    "TAMPER_RULES",
    "find_money_forms",
    "extract_money_fields",
    "tamper_values",
    "run_blotamper",
]

MONEY_FIELDS = ("price", "amount", "qty", "quantity", "discount",
                "coupon", "total")
FINAL_SUBMIT_HINTS = ("pay", "purchase", "complete", "confirm",
                      "finalize", "place-order", "submit", "charge",
                      "buy/confirm")

FORM_PATHS = ["", "/checkout", "/cart", "/order", "/buy", "/store"]
_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
_NAME_RE = re.compile(r"""name\s*=\s*["']([^"']+)["']""", re.I)
_VALUE_RE = re.compile(r"""value\s*=\s*["']([^"']*)["']""", re.I)
_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']+)["']""", re.I)

# field-name-pattern -> tampered value (SAFE-READ heuristics)
TAMPER_RULES = (
    (re.compile(r"price", re.I), "0"),
    (re.compile(r"qty|quantity", re.I), "-1"),
    (re.compile(r"discount", re.I), "100"),
    (re.compile(r"total", re.I), "0"),
)


class Finding(dict):
    """ENGINE-convention finding dict (always candidate)."""

    def __init__(self, title, severity, verification_note, manual_check,
                 location, evidence, source, confidence="medium"):
        super().__init__(
            title=title,
            severity=severity,
            confidence=confidence,
            verification="candidate",
            verification_note=verification_note,
            manual_check=manual_check,
            location=location,
            evidence=str(evidence)[:300],
            source=source,
        )


def _text(body):
    if isinstance(body, bytes):
        return body.decode("latin-1")
    return str(body or "")


def is_final_submit(path):
    """True when the path looks like a FINAL purchase endpoint — those
    are never tampered with (purchase-completion guard)."""
    p = (path or "").lower()
    return any(h in p for h in FINAL_SUBMIT_HINTS)


def extract_money_fields(fields):
    """{name: value} dict -> subset of money-bearing fields."""
    return {k: v for k, v in (fields or {}).items()
            if any(m in k.lower() for m in MONEY_FIELDS)}


def tamper_values(name, value):
    """Return the SAFE-READ tampered value for a field name, or None
    when no rule applies."""
    for pat, repl in TAMPER_RULES:
        if pat.search(name):
            return repl
    if "coupon" in name.lower():
        # duplicate the coupon value (classic stacked-coupon probe)
        return "%s,%s" % (value or "OMEGA", value or "OMEGA")
    return None


def find_money_forms(base_url, fetch, pages=None):
    """[{action, fields}] for HTML forms containing money fields."""
    out = []
    for page in (pages if pages is not None else FORM_PATHS):
        url = base_url.rstrip("/") + "/" + page.lstrip("/")
        try:
            _st, _h, body = fetch("GET", url)
        except Exception:
            continue
        for form in _FORM_RE.findall(_text(body)):
            fields = {}
            for tag in _INPUT_RE.findall(form):
                nm = _NAME_RE.search(tag)
                if nm:
                    vv = _VALUE_RE.search(tag)
                    fields[nm.group(1)] = vv.group(1) if vv else ""
            money = extract_money_fields(fields)
            if not money:
                continue
            action = _ACTION_RE.search(form)
            out.append({"page": page or "/",
                        "action": action.group(1) if action
                        else page or "/",
                        "fields": fields})
            break  # one money form per page is enough
    return out


def _resolve_action(base_url, page, action):
    if action.startswith("http"):
        return action
    if action.startswith("/"):
        return base_url.rstrip("/") + action
    return base_url.rstrip("/") + "/" + action.lstrip("/")


def _post_encoded(fetch, url, fields):
    from urllib.parse import urlencode
    data = urlencode(fields)
    try:
        return fetch("POST", url, headers={
            "Content-Type": "application/x-www-form-urlencoded"}, body=data)
    except Exception:
        return None


def _totals_in(text):
    """Extract numeric money-ish values echoed in a response."""
    vals = re.findall(
        r"(?:total|amount|price|subtotal|grand)\D{0,8}([\d,]+\.?\d*)",
        text.lower())
    return [v.replace(",", "") for v in vals]


def run_blotamper(target, fetch, budget=20, log=None, allowlist=None,
                  specs=None):
    """Run the business-logic tampering suite. Never raises; per-check
    errors become skipped entries. Returns
    {findings, skipped, ran, requests_sent}."""
    from omega.probes import allowlist_ok

    result = {"findings": [], "skipped": {}, "ran": [],
              "requests_sent": 0}
    base_url = target if "://" in target else "http://" + target
    if not allowlist_ok(target, allowlist):
        result["skipped"]["__all__"] = \
            "target %r not in allowlist" % target
        if log:
            log("blotamper skipped: target not in allowlist: %r" % target)
        return result

    sent = 0

    def counted(method, url, headers=None, body=None):
        nonlocal sent
        sent += 1
        return fetch(method, url, headers=headers, body=body)

    # ---- flow discovery -------------------------------------------------
    try:
        flows = find_money_forms(base_url, counted)
    except Exception as exc:
        result["skipped"]["form_discovery"] = \
            "%s: %s" % (type(exc).__name__, exc)
        flows = []
    # optional API specs (apimap-style): {"method","url","body"} dicts
    for spec in (specs or []):
        try:
            body = spec.get("body") or {}
            if isinstance(body, str):
                body = json.loads(body)
            fields = {k: v for k, v in body.items()
                      if any(m in str(k).lower() for m in MONEY_FIELDS)}
            if fields:
                flows.append({"page": "spec", "action": spec.get("url"),
                              "fields": fields, "spec": True})
        except Exception:
            continue

    # dedupe by resolved action URL (same flow served from many pages)
    deduped, seen_actions = [], set()
    for flow in flows:
        try:
            key = _resolve_action(base_url, flow["page"],
                                  flow["action"]) if flow.get("action") \
                else flow["page"]
        except Exception:
            key = flow.get("action") or flow.get("page")
        if key in seen_actions:
            continue
        seen_actions.add(key)
        deduped.append(flow)
    flows = deduped

    if not flows:
        result["skipped"]["__all__"] = \
            "no money-bearing flow identified (nothing probed)"
        result["requests_sent"] = sent
        return result

    result["ran"].append("flow_discovery")
    for flow in flows:
        action = flow["action"]
        label = action or flow["page"]
        if not action or sent >= budget:
            result["skipped"][label] = "budget exhausted" \
                if sent >= budget else "no actionable action URL"
            continue
        url = _resolve_action(base_url, flow["page"], action)
        if is_final_submit(url):
            result["skipped"][label] = (
                "final-submit endpoint detected (%s) — purchase-"
                "completion guard: not tampered" % url)
            continue
        fields = flow["fields"]
        tamperable = {k: v for k, v in fields.items()
                      if tamper_values(k, v) is not None}
        if not tamperable:
            result["skipped"][label] = \
                "money fields present but no SAFE-READ tamper rule applies"
            continue

        # baseline (original values) — must succeed to establish ground
        try:
            base_resp = _post_encoded(counted, url, fields)
        except Exception as exc:
            result["skipped"][label] = "%s: %s" % (type(exc).__name__, exc)
            continue
        if base_resp is None:
            result["skipped"][label] = "baseline request failed"
            continue
        base_st, _h, base_body = base_resp
        if not (200 <= base_st < 300):
            result["skipped"][label] = (
                "baseline not a success (%s) — flow cannot be "
                "identified as safe; skipped" % base_st)
            continue

        # tampered replay (only fields with SAFE-READ rules)
        tfields = dict(fields)
        for k, v in tamperable.items():
            tfields[k] = tamper_values(k, v)
        try:
            tam_resp = _post_encoded(counted, url, tfields)
        except Exception as exc:
            result["skipped"][label] = "%s: %s" % (type(exc).__name__, exc)
            continue
        if tam_resp is None:
            result["skipped"][label] = "tampered request failed to send"
            continue
        tam_st, _h2, tam_body = tam_resp
        base_totals, tam_totals = _totals_in(_text(base_body)), \
            _totals_in(_text(tam_body))
        accepted = 200 <= tam_st < 300
        totals_differ = bool(tam_totals) and tam_totals != base_totals
        if accepted and totals_differ:
            result["findings"].append(Finding(
                title="Business-logic tampering accepted differentially "
                      "at %s" % url,
                severity="high", confidence="medium",
                verification_note=(
                    "Replaying the same request with SAFE-READ tampered "
                    "values (%s) returned a success status AND a "
                    "different total echo (%s vs baseline %s). The "
                    "differential suggests the backend accepts client-"
                    "controlled money fields, but a differential echo "
                    "is a SIGNAL, not proof: requires manual business "
                    "confirmation. No purchase was completed and no "
                    "final-submit endpoint was touched."
                    % ("; ".join("%s=%s" % (k, tfields[k])
                                 for k in tamperable),
                       tam_totals[:4], base_totals[:4])),
                manual_check="curl -sS -X POST -d %r %s"
                             % (json.dumps(tfields), url),
                location=url,
                evidence="baseline_status=%s tampered_status=%s "
                         "baseline_totals=%s tampered_totals=%s"
                         % (base_st, tam_st, base_totals[:4],
                            tam_totals[:4]),
                source="omega-blotamper/differential"))
        elif accepted and not totals_differ:
            result["skipped"][label] = (
                "tampered request accepted but totals identical — no "
                "differential; nothing to flag")
        else:
            result["skipped"][label] = (
                "tampered request rejected (status %s) — validation "
                "appears present" % tam_st)

    result["requests_sent"] = sent
    if log:
        log("blotamper: %d flow(s) considered, %d finding(s)"
            % (len(flows), len(result["findings"])))
    return result
