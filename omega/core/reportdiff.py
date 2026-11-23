"""omega/core/reportdiff — rescan diff engine.

Compares a fresh findings set against a previous run snapshot (JSON
file): NEW (not seen before), STILL-PRESENT (same title+location),
FIXED (was present, now gone). Snapshots keyed by finding title +
location hash. Lives under OMEGA_SNAPSHOTS_HOME (default:
<omega_home>/snapshots).
"""
import hashlib
import json
import os

__all__ = ["save_snapshot", "diff_snapshots"]


def _key(f):
    base = f"{f.get('title', '')}|{f.get('location', '')}"
    return hashlib.sha256(base.encode()).hexdigest()[:16]


def _home():
    root = os.environ.get("OMEGA_SNAPSHOTS_HOME")
    if not root:
        try:
            from omega.core.home import omega_home
            root = os.path.join(omega_home(), "snapshots")
        except Exception:
            root = os.path.join(os.path.expanduser("~"), ".omega",
                                "snapshots")
    os.makedirs(root, exist_ok=True)
    return root


def save_snapshot(target, findings, label=None):
    """Persist a findings snapshot; returns the file path."""
    root = _home()
    safe = "".join(c if c.isalnum() else "_" for c in str(target))[:60]
    label = label or "run"
    path = os.path.join(root, f"{safe}.{label}.json")
    with open(path, "w") as fh:
        json.dump({"target": str(target), "keys": sorted(
            {_key(f) for f in findings or []}), "findings": [
                {"title": f.get("title"), "severity": f.get("severity"),
                 "location": f.get("location")}
                for f in findings or []]}, fh, indent=1)
    return path


def diff_snapshots(old_path, findings):
    """Diff new findings against a saved snapshot.

    Returns {new: [...], still: [...], fixed_count: int, old_path}.
    """
    with open(old_path) as fh:
        old = json.load(fh)
    old_keys = set(old.get("keys") or [])
    new, still = [], []
    new_keys = set()
    for f in findings or []:
        k = _key(f)
        new_keys.add(k)
        (still if k in old_keys else new).append(f)
    fixed = old_keys - new_keys
    return {"new": new, "still": still,
            "fixed_count": len(fixed),
            "old_path": old_path,
            "old_target": old.get("target")}


def render_diff(d):
    lines = [f"## Rescan diff vs {d.get('old_path', '?')}"]
    lines.append(f"- fixed since last run: {d['fixed_count']}")
    lines.append(f"- new findings: {len(d['new'])}")
    lines.append(f"- still present: {len(d['still'])}")
    for f in d["new"][:10]:
        lines.append(f"  + [{f.get('severity')}] {f.get('title')}")
    if len(lines) == 4 and not d["new"]:
        lines.append("_no new findings — target stable_")
    return "\n".join(lines)
