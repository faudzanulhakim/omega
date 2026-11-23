"""omega/reporting/evidencepack — full audit-trail evidence files.

Persists EVERY finding's raw evidence (request shape, response body,
timestamp, timing, source capability) as a numbered JSON file under
OMEGA_EVIDENCE_HOME, and returns an index. Credentials/secret-shaped
values are REDACTED from stored bodies (shape only). The HTML report
links into these files.
"""
import hashlib
import json
import os
import re
import time

__all__ = ["pack_findings"]

_SECRETISH = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization)\W{0,3}"
    r"[^\s\"']{4,}")


def _redact(body):
    return _SECRETISH.sub(lambda m: m.group(0).split(":")[0]
                          .split("=")[0] + ": [REDACTED]", body)


def _home():
    root = os.environ.get("OMEGA_EVIDENCE_HOME")
    if not root:
        try:
            from omega.core.home import omega_home
            root = os.path.join(omega_home(), "evidence")
        except Exception:
            root = os.path.join(os.path.expanduser("~"), ".omega",
                                "evidence")
    os.makedirs(root, exist_ok=True)
    return root


def pack_findings(findings, target="", run_id=None):
    root = _home()
    run_id = run_id or time.strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() else "_" for c in str(target))[:50]
    index = []
    for i, f in enumerate(findings or [], 1):
        rec = {
            "run_id": run_id,
            "n": i,
            "title": f.get("title"),
            "severity": f.get("severity"),
            "cwe": f.get("cwe"),
            "source": f.get("source"),
            "location": f.get("location"),
            "verification": f.get("verification"),
            "evidence_raw": _redact(str(f.get("evidence", ""))),
            "manual_check": f.get("manual_check"),
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                         time.gmtime()),
            "body_sha256": hashlib.sha256(
                str(f.get("evidence", "")).encode()).hexdigest()[:16],
        }
        path = os.path.join(root, f"{run_id}.{safe[:30]}.{i:03d}.json")
        with open(path, "w") as fh:
            json.dump(rec, fh, indent=1)
        index.append({"n": i, "title": f.get("title"), "file": path})
    idx_path = os.path.join(root, f"{run_id}.{safe[:30]}.index.json")
    with open(idx_path, "w") as fh:
        json.dump({"target": str(target), "run_id": run_id,
                   "count": len(index), "items": index}, fh, indent=1)
    return {"index_file": idx_path, "files": [x["file"] for x in index],
            "count": len(index)}


def render_evidence_index(pack):
    lines = [f"## Evidence pack — {pack['count']} file(s)",
             f"index: {pack['index_file']}"]
    for item in pack["files"][:10]:
        lines.append(f"- {item}")
    if pack["count"] > 10:
        lines.append(f"- ... {pack['count'] - 10} more (see index)")
    return "\n".join(lines)
