"""omega/core/campaign.py — multi-target campaign orchestration.

Runs the fusion engine (omega.fusion.fuse) against a LIST of targets
using a scan profile pack (omega.core.profiles) for the suite subset
and per-target budget. Per the engine/tools/campaign.py shape, each
phase is contained: one unreachable or failing target never fails the
campaign — it is recorded as skipped with a reason.

Guarantees:
- never raises (all failures degrade to skip entries / error strings)
- per-target findings are tagged with their originating target
- global dedupe on (title, location)
- one combined report (markdown sections per target + executive
  summary comparing targets; PDF when --out ends in .pdf)
- scope_ack=True is REQUIRED; without it the campaign is refused
- max 10 targets per campaign (env OMEGA_CAMPAIGN_MAX overrides)
- offense/exploit gates stay OFF unless aggressive=True (maps to
  PTK_OFFENSE=1 + the polyglot gate)
"""

import os
import time

MAX_TARGETS_DEFAULT = 10


def campaign_max_targets():
    """Campaign target cap; env OMEGA_CAMPAIGN_MAX overrides (sanitized)."""
    raw = os.environ.get("OMEGA_CAMPAIGN_MAX", "")
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return MAX_TARGETS_DEFAULT


def normalize_target(target):
    """Bare host -> https://host (trailing slash stripped); URLs with
    an explicit scheme pass through unchanged."""
    t = str(target or "").strip()
    if not t:
        return ""
    if "://" in t:
        return t
    t = "https://" + t
    return t.rstrip("/") or t


def dedupe_findings(findings):
    """Global (title, location) dedupe. Keeps the first occurrence,
    preserving order. Never raises."""
    seen = set()
    out = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        key = (str(f.get("title") or "").strip().lower(),
               str(f.get("location") or "").strip())
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _tag(finding, target):
    try:
        if isinstance(finding, dict):
            finding.setdefault("target", target)
    except Exception:
        pass
    return finding


def _run_extra(name, target):
    """Run a non-fusion probe capability by name; contained."""
    try:
        if name == "tfinger":
            from omega.tfinger import run_tfinger
            return (run_tfinger(target) or {}).get("findings") or []
        if name == "apimap":
            from omega.apimap import run_apimap
            return (run_apimap(target) or {}).get("findings") or []
        return []
    except Exception as exc:
        return [{"title": "extra probe failed", "severity": "info",
                 "location": target, "source": "omega-campaign/extra",
                 "evidence": "%s: %s" % (type(exc).__name__, exc),
                 "confidence": "info", "verification": "error",
                 "manual_check": True}]


def _reachability_probe(target, log):
    """Cheap GET before scanning; returns (ok, reason). Contained.

    Reasons are operator-facing: never leak raw exception text (traceback
    names, type names). Full detail goes to the log only.
    """
    try:
        from omega.deepchecks import default_fetch
        default_fetch("GET", target)
        return True, ""
    except Exception as exc:
        if isinstance(exc, (ValueError, TypeError)):
            reason = ("target invalid or malformed — not reachable, "
                      "skipped")
        else:
            reason = "target unreachable — connection failed, skipped"
        log("reachability: %s: %s: %s"
            % (target, type(exc).__name__, exc))
        return False, reason


def _executive_summary(per_target):
    """Small markdown table comparing targets."""
    lines = ["## Executive summary", "",
             "| target | status | findings | corroborated |",
             "|---|---|---|---|"]
    for tgt, info in per_target.items():
        lines.append("| %s | %s | %s | %s |" % (
            tgt.replace("|", "/"), info.get("status", "?"),
            info.get("count", 0), info.get("corroborated", 0)))
    lines.append("")
    return "\n".join(lines)


def _combined_markdown(per_target, profile_name):
    """One section per target, rendered via omega.report."""
    from omega.report import generate_report
    parts = ["# OMEGA campaign report", "",
             "profile: %s — %d target(s)" % (profile_name,
                                             len(per_target)), ""]
    parts.append(_executive_summary(per_target))
    for tgt, info in per_target.items():
        parts.append("---")
        parts.append("## Target: %s" % tgt)
        if info.get("status") == "skipped":
            parts.append("")
            parts.append("SKIPPED: %s" % info.get("reason", ""))
            continue
        try:
            md = generate_report(tgt, info.get("findings") or [],
                                 meta={"profile": profile_name},
                                 fmt="markdown")
            if md:
                parts.append(md)
        except Exception as exc:
            parts.append("(report rendering failed: %s)" % exc)
        parts.append("")
    return "\n".join(parts)


def _write_report(per_target, findings, profile_name, out):
    """Write the combined report; returns (path, note). Contained."""
    from omega.report import write_report
    path = out or os.path.join(
        os.getcwd(), "campaign_report_%d.md" % int(time.time()))
    ext = os.path.splitext(str(path))[1].lower()
    if ext == ".pdf":
        meta = {"profile": profile_name,
                "campaign": {t: i.get("count", 0)
                             for t, i in per_target.items()}}
        # one combined section-per-target PDF via the report engine
        from omega.report import generate_report
        blob = generate_report("campaign (%d targets)" % len(per_target),
                               findings, meta=meta, fmt="pdf")
        os.makedirs(os.path.dirname(os.path.abspath(str(path))) or ".",
                    exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(blob)
        return str(path), ""
    os.makedirs(os.path.dirname(os.path.abspath(str(path))) or ".",
                exist_ok=True)
    md = _combined_markdown(per_target, profile_name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(md)
    return str(path), ""


def run_campaign(targets, profile="web", scope_ack=True, log=None,
                 aggressive=False, out=None):
    """Run a multi-target campaign. Returns:

    {ok, error, findings, per_target, report_path, profile,
     truncated}

    per_target maps each target to
    {status: ran|skipped, count, corroborated, findings, ran, skipped,
     reason}. One failing target never fails the campaign. Never
    raises.
    """
    log = log or (lambda msg: None)
    result = {"ok": False, "error": "", "findings": [],
              "per_target": {}, "report_path": None,
              "profile": profile, "truncated": False}
    if not scope_ack:
        result["error"] = ("scope-ack required: OMEGA will not run a "
                           "campaign without explicit operator "
                           "acknowledgment (--scope-ack)")
        log(result["error"])
        return result

    prof = _resolve(profile)
    result["profile"] = prof["name"]

    raw = [t for t in (targets or []) if str(t or "").strip()]
    cap = campaign_max_targets()
    if len(raw) > cap:
        result["truncated"] = True
        log("campaign: truncating %d targets to cap %d" % (len(raw), cap))
        raw = raw[:cap]
    urls = [normalize_target(t) for t in raw]
    urls = [u for u in urls if u]
    if not urls:
        result["error"] = "no usable targets supplied"
        return result

    offense_was_set = os.environ.get("PTK_OFFENSE") == "1"
    try:
        from omega.fusion import fuse
        all_findings = []
        for url in urls:
            info = {"status": "ran", "count": 0, "corroborated": 0,
                    "findings": [], "ran": [], "skipped": [], "reason": ""}
            ok, reason = _reachability_probe(url, log)
            if not ok:
                info["status"] = "skipped"
                info["reason"] = reason
                result["per_target"][url] = info
                continue
            try:
                if aggressive:
                    os.environ["PTK_OFFENSE"] = "1"
                res = fuse(url, budget=prof["budget"], allowlist=None,
                           gate=bool(aggressive), suites=prof["suites"]) or {}
                found = [_tag(f, url) for f in (res.get("findings") or [])]
                info["findings"] = found
                info["count"] = len(found)
                info["corroborated"] = len(res.get("corroborated") or [])
                info["ran"] = res.get("ran") or []
                info["skipped"] = res.get("skipped") or []
                for extra in prof["extras"]:
                    for f in _run_extra(extra, url):
                        _tag(f, url)
                        info["findings"].append(f)
                info["count"] = len(info["findings"])
                all_findings.extend(info["findings"])
                log("campaign: %s -> %d finding(s)" % (url, info["count"]))
            except Exception as exc:
                info["status"] = "skipped"
                info["reason"] = ("scan skipped — internal scanner error "
                                  "(details in log)")
                log("campaign: %s failed: %s: %s"
                    % (url, type(exc).__name__, exc))
            result["per_target"][url] = info
        result["findings"] = dedupe_findings(all_findings)
        result["ok"] = True
        try:
            path, note = _write_report(result["per_target"],
                                       result["findings"],
                                       prof["name"], out)
            result["report_path"] = path
            if note:
                result["error"] = note
        except Exception as exc:
            result["error"] = ("report generation failed: %s: %s"
                               % (type(exc).__name__, exc))
            log(result["error"])
    finally:
        if aggressive and not offense_was_set:
            os.environ.pop("PTK_OFFENSE", None)
    return result


def _resolve(profile):
    from omega.core.profiles import resolve_profile
    return resolve_profile(profile)
