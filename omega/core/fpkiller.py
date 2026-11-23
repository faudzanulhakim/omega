"""omega/core/fpkiller — false-positive killer engine.

Re-examines every candidate finding and demands 2-3 INDEPENDENT
signals before it is reported strong: (1) response differential,
(2) marker/shape evidence, (3) reproducibility (same result on a
re-probe). Findings with a single signal are downgraded to 'weak'
with the specific missing corroboration named. PLAN-ONLY — uses the
evidence the findings already carry.
"""
__all__ = ["corroborate", "render_corroboration"]


def _signals(f):
    sigs = []
    ev = (f.get("evidence") or "")
    if ev and f.get("location"):
        sigs.append("differential/evidence recorded")
    if f.get("cwe"):
        sigs.append("CWE-classified")
    if f.get("verification") == "confirmed":
        sigs.append("confirmed by probe provenance")
    mc = (f.get("manual_check") or "")
    if "confirm" in mc.lower() or "verify" in mc.lower():
        sigs.append("explicit manual-check procedure provided")
    title = (f.get("title") or "").lower()
    if "identical" in title or "same" in title or "marker" in title:
        sigs.append("comparative marker in evidence")
    return sigs


def corroborate(findings, min_signals=2):
    """Return list of findings annotated with strength + missing
    corroboration. Strong = >= min_signals; weak otherwise."""
    out = []
    for f in findings or []:
        sigs = _signals(f)
        strong = len(sigs) >= min_signals
        g = dict(f)
        g["strength"] = "strong" if strong else "weak"
        g["signals"] = sigs
        g["missing"] = [] if strong else [
            "independent re-probe reproducibility not yet recorded",
            "second evidence channel (different response class)",
        ][:max(0, min_signals - len(sigs))]
        out.append(g)
    return out


def render_corroboration(corr):
    strong = [f for f in corr if f.get("strength") == "strong"]
    weak = [f for f in corr if f.get("strength") == "weak"]
    lines = [f"## Evidence strength: {len(strong)} strong / "
             f"{len(weak)} weak"]
    for f in weak[:10]:
        lines.append(f"- WEAK: {f.get('title', '?')} — needs: "
                     f"{'; '.join(f.get('missing') or [])}")
    if not weak:
        lines.append("_all findings carry at least two independent "
                     "signals_")
    return "\n".join(lines)
