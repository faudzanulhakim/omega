"""omega/fusion.py — the FUSION engine: combined multi-scanner,
multi-language scanning with cross-corroboration.

fuse() runs every available scanner suite CONCURRENTLY
(ThreadPoolExecutor, max 6 workers):

  python/pytools      omega.pytools_scan.run_py_suite
  python/probes       omega.probes.run_probes
  go+node/native      omega.adapters.native.run_native_suite
                      (skips gracefully when Go/Node are missing)
  system binaries     omega.adapters.system_tools.run_system_suite
                      (skips missing binaries internally)
  perl                omega.adapters.perltools.run_perl_suite
                      (skips when perl is missing)
  jq (hygiene pass)   omega.adapters.jqtools.run_jq_suite
                      (skips when jq is missing)

Every suite is contained: a raise becomes a skipped entry, never an
exception. Per-suite gates (PTK_POLYGLOT) are handled HERE via explicit
allow= overrides, so fusion needs no environment variable: gate=True
enables the gated suites, gate=False keeps them off.

After collection, findings are CORROBORATED across scanners: findings
from >= 2 independent scanners (different source prefixes, e.g.
omega-py/* + omega-probe/*) that agree on (title, location) or on a
semantic signature (location + title class) get corroborated=True,
confidence upgraded to "high" and a verification_note suffix
"corroborated by: <sources>". The verification label itself is NEVER
upgraded to "confirmed" — a signature match between tools is still a
signature, not proof (honesty contract).

Return shape:
  {findings, corroborated, surface, ran, skipped, languages_used}
"""

from __future__ import annotations

import re
import shutil
from concurrent.futures import ThreadPoolExecutor

MAX_WORKERS = 6
DEFAULT_BUDGET = 20  # per-suite request budget; env OMEGA_FUSION_BUDGET overrides


def _fusion_budget():
    raw = os.environ.get("OMEGA_FUSION_BUDGET")
    if raw and raw.isdigit():
        return int(raw)
    return DEFAULT_BUDGET

_SEVERITY_RANK = {
    "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
}
# scores normalized across UPPER and lower severity conventions
_SEV_ALIASES = dict(_SEVERITY_RANK)
_SEV_ALIASES.update({k.upper(): v for k, v in _SEVERITY_RANK.items()})

_NONWORD_RE = re.compile(r"[^a-z0-9]+")


def severity_score(sev):
    """Numeric severity score (higher = more severe; unknown -> 0)."""
    return _SEV_ALIASES.get(str(sev or "").strip().lower(), 0)


def _as_dict(finding):
    """Coerce a finding to a plain dict (probe Findings are dict subclasses)."""
    return dict(finding) if not isinstance(finding, dict) else finding


def source_prefix(finding):
    """First path segment of a finding's source, e.g.
    'omega-py/http_fingerprint' -> 'omega-py'."""
    src = str((finding or {}).get("source") or "")
    return src.split("/", 1)[0] if src else ""


def title_class(finding):
    """Semantic class of a finding title: first two normalized words,
    e.g. 'Missing security response headers' -> 'missing security'."""
    words = _NONWORD_RE.sub(
        " ", str((finding or {}).get("title") or "").lower()).split()
    return " ".join(words[:2])


# --------------------------------------------------------------------------
# Corroboration
# --------------------------------------------------------------------------

def _groups_for(findings):
    """Yield groups of finding indices that agree semantically.

    Two grouping keys:
      A) exact  : (title.lower(), location)
      B) semantic: (location, title_class)
    """
    by_exact, by_semantic = {}, {}
    for i, f in enumerate(findings):
        d = _as_dict(f)
        loc = str(d.get("location") or "")
        title = str(d.get("title") or "").lower().strip()
        if title or loc:
            by_exact.setdefault((title, loc), []).append(i)
        cls = title_class(d)
        if cls and loc:
            by_semantic.setdefault((loc, cls), []).append(i)
    seen, groups = set(), []
    for groups_map in (by_exact, by_semantic):
        for key, idxs in groups_map.items():
            frozen = tuple(sorted(set(idxs)))
            if len(frozen) >= 2 and frozen not in seen:
                seen.add(frozen)
                groups.append(frozen)
    return groups


def corroborate(findings):
    """Pure corroboration pass. Returns (annotated_findings, corroborated).

    A finding corroborated by >= 2 independent scanners (different source
    prefixes) is copied, marked corroborated=True, confidence='high' and
    its verification_note gains 'corroborated by: <sources>'. The
    verification label is never changed (honesty contract).
    Single-source findings pass through untouched.
    """
    findings = [_as_dict(f) for f in (findings or [])]
    corroborated_ids = set()
    out = [dict(f) for f in findings]

    for idxs in _groups_for(findings):
        prefixes = {source_prefix(findings[i]) for i in idxs} - {""}
        if len(prefixes) < 2:
            continue
        sources = sorted({str(findings[i].get("source") or "?")
                          for i in idxs})
        corroborated_ids.update(idxs)
        for i in idxs:
            note = str(out[i].get("verification_note") or "")
            tag = "corroborated by: " + ", ".join(sources)
            if tag not in note:
                out[i]["verification_note"] = (
                    note + ("; " if note else "") + tag)
            out[i]["corroborated"] = True
            out[i]["confidence"] = "high"
            # HONESTY CONTRACT: out[i]["verification"] is intentionally
            # left untouched — cross-scanner agreement is a stronger
            # signature, not confirmation.

    corroborated = [dict(out[i]) for i in sorted(corroborated_ids)]
    return out, corroborated


def sort_findings(findings):
    """Sort by corroborated desc, then severity desc (stable)."""
    return sorted(
        findings,
        key=lambda f: (
            0 if f.get("corroborated") else 1,
            -severity_score(f.get("severity")),
        ))


# --------------------------------------------------------------------------
# Suite runners
# --------------------------------------------------------------------------

def _suite_pytools(target, ctx):
    from omega.pytools_scan import run_py_suite
    return run_py_suite(target, budget=ctx["budget"], log=ctx["log"])


def _suite_probes(target, ctx):
    from omega.probes import run_probes
    return run_probes(target, fetch=ctx["fetch"], budget=ctx["budget"],
                      log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_native(target, ctx):
    from omega.adapters.native import run_native_suite
    return run_native_suite(
        target, ["portspeed", "htsweep", "jsanalyze"],
        budget=max(1, ctx["budget"] // 2), log=ctx["log"],
        allow=("fusion",) if ctx["gate"] else ())


def _suite_system(target, ctx):
    import os as _os
    from omega.adapters.system_tools import run_system_suite, GATE_ENV
    # fusion handles the per-suite gate itself: temporarily open the
    # environment gate while the suite runs (restored afterwards).
    if ctx["gate"]:
        _os.environ[GATE_ENV] = "1"
    try:
        return run_system_suite(
            target, stages=("recon", "enum", "verify"),
            budget=max(1, ctx["budget"] // 2), log=ctx["log"],
            which_fn=ctx["which_fn"])
    finally:
        if ctx["gate"]:
            if _os.environ.get(GATE_ENV) == "1":
                del _os.environ[GATE_ENV]


def _suite_perl(target, ctx):
    from omega.adapters.perltools import run_perl_suite
    return run_perl_suite(target, fetch=ctx["fetch"],
                          budget=ctx["budget"], log=ctx["log"],
                          which_fn=ctx["which_fn"])


def _suite_deep(target, ctx):
    from omega.deepchecks import run_deepchecks
    return run_deepchecks(target, fetch=ctx["fetch"], budget=ctx["budget"],
                          log=ctx["log"], allowlist=ctx["allowlist"],
                          path_info=ctx.get("path_info"))


def _suite_browser(target, ctx):
    from omega.browser import browser_available, run_browser_suite
    if not browser_available():
        # contained skip: fuse() turns any raise into a skipped entry
        raise RuntimeError("playwright chromium not available; "
                           "browser suite skipped")
    return run_browser_suite(target, budget=ctx["budget"], log=ctx["log"],
                             allowlist=ctx["allowlist"])


def _suite_chaos(target, ctx):
    from omega.chaos import run_chaos
    return run_chaos(target, fetch=ctx["fetch"], budget=ctx["budget"],
                     log=ctx["log"], allowlist=ctx["allowlist"],
                     path_info=ctx.get("path_info"))


def _suite_api(target, ctx):
    from omega.apiintel import run_apiintel
    return run_apiintel(target, fetch=ctx["fetch"],
                        log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_graphql_deep(target, ctx):
    from omega.graphqldeep import run_graphqldeep
    return run_graphqldeep(target, fetch=ctx["fetch"],
                           log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_offense(target, ctx):
    """Gated offense layer (injection suite). The gate is checked
    INSIDE this fn: gate closed -> contained skip entry, never an
    exception. PTK_OFFENSE=1 (--offense) is the separate offense
    gate — deliberately NOT PTK_POLYGLOT."""
    import os as _os
    from omega.offense.injection import run_offense_suite
    if _os.environ.get("PTK_OFFENSE") != "1":
        return {"findings": [], "ran": [],
                "skipped": [{"tool": "offense",
                             "reason": "offense layer disabled "
                                       "(--offense)"}]}
    return run_offense_suite(target, fetch=ctx["fetch"],
                             budget=max(1, ctx["budget"] // 2),
                             log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_hyper(target, ctx):
    from omega.hyper import run_hyper
    return run_hyper(target, fetch=ctx["fetch"], budget=ctx["budget"],
                     log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_headerscan(target, ctx):
    from omega.headerscan import run_headerscan
    return run_headerscan(target, fetch=ctx["fetch"], budget=ctx["budget"],
                          log=ctx["log"])


def _suite_redirects(target, ctx):
    from omega.redirects import run_redirects
    return run_redirects(target, fetch=ctx["fetch"], budget=ctx["budget"],
                         log=ctx["log"])


def _suite_oobscan(target, ctx):
    from omega.oobscan import run_oobscan
    return run_oobscan(target, fetch=ctx["fetch"], budget=ctx["budget"],
                       log=ctx["log"])


def _suite_jsrender(target, ctx):
    from omega.jsrender import run_jsrender
    return run_jsrender(target, budget=max(1, min(3, ctx["budget"])),
                        log=ctx["log"])


def _suite_subperm(target, ctx):
    from omega.subperm import run_subperm
    host = target.split("://")[-1].split("/")[0].split(":")[0]
    return run_subperm(host, log=ctx["log"])


def _suite_go_dirscan(target, ctx):
    from omega.adapters.gotools import run_dirscan
    paths = ["/admin", "/backup.sql", "/backup.zip", "/.env", "/.git/HEAD",
             "/phpinfo.php", "/wp-admin/", "/api", "/config.php.bak",
             "/dump.sql", "/.DS_Store", "/server-status"]
    return run_dirscan(target, paths[:max(1, ctx["budget"])],
                       log=ctx["log"])


def _suite_node_hdr(target, ctx):
    from omega.adapters.node_hdr import run_hdrscore
    return run_hdrscore(target, ctx["fetch"], log=ctx["log"])


def _suite_jq_diff(target, ctx):
    from omega.adapters.jqdiff import run_jqdiff
    return run_jqdiff(target, ctx["fetch"], log=ctx["log"])


def _suite_sentinel(target, ctx):
    from omega.sentinel import run_sentinel
    return run_sentinel(target, fetch=ctx["fetch"], budget=ctx["budget"],
                        log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_c_urlinfo(target, ctx):
    from omega.adapters.ctools import run_c_suite
    return run_c_suite(target, fetch=ctx["fetch"], log=ctx["log"])


def _suite_ruby_urlaudit(target, ctx):
    from omega.adapters.rubytools import run_ruby_suite
    return run_ruby_suite(target, fetch=ctx["fetch"], log=ctx["log"])


def _suite_cpp_hdrstruct(target, ctx):
    from omega.adapters.cpptools import run_cpp_suite
    return run_cpp_suite(target, fetch=ctx["fetch"], log=ctx["log"])


def _suite_awk_urlmine(target, ctx):
    from omega.adapters.awktools import run_awk_suite
    return run_awk_suite(target, fetch=ctx["fetch"], log=ctx["log"])


def _suite_sh_methodcheck(target, ctx):
    from omega.adapters.shtools import run_sh_suite
    return run_sh_suite(target, log=ctx["log"])


def _suite_rust_pathscope(target, ctx):
    from omega.adapters.rusttools import run_rust_suite
    return run_rust_suite(target, log=ctx["log"])


def _suite_php_seriscan(target, ctx):
    from omega.adapters.phptools import run_php_suite
    return run_php_suite(target, fetch=ctx["fetch"], log=ctx["log"])


def _suite_smuggle(target, ctx):
    from omega.smuggle import run_smuggle
    return run_smuggle(target, log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_hhint(target, ctx):
    from omega.hhint import run_hhint
    return run_hhint(target, fetch=ctx["fetch"], budget=ctx["budget"],
                     log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_ssti(target, ctx):
    from omega.ssti import run_ssti
    return run_ssti(target, fetch=ctx["fetch"], budget=ctx["budget"],
                    log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_deser(target, ctx):
    from omega.deser import run_deser
    return run_deser(target, fetch=ctx["fetch"], budget=ctx["budget"],
                     log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_uplprobe(target, ctx):
    from omega.uplprobe import run_uplprobe
    return run_uplprobe(target, fetch=ctx["fetch"], budget=ctx["budget"],
                        log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_authbypass(target, ctx):
    from omega.scanning.authbypass import run_authbypass
    return {"findings": run_authbypass(target, ctx["fetch"],
                                       path_info=ctx.get("path_info"),
                                       gate=ctx.get("gate")) or []}


def _suite_resetpoison(target, ctx):
    from omega.scanning.resetpoison import run_resetpoison
    return {"findings": run_resetpoison(target, ctx["fetch"],
                                        path_info=ctx.get("path_info"),
                                        gate=ctx.get("gate")) or []}


def _suite_userenum(target, ctx):
    from omega.scanning.userenum import run_userenum
    return {"findings": run_userenum(target, ctx["fetch"],
                                     path_info=ctx.get("path_info"),
                                     gate=ctx.get("gate")) or []}


def _suite_libcve(target, ctx):
    from omega.scanning.libcve import run_libcve
    return {"findings": run_libcve(target, ctx["fetch"],
                                   path_info=ctx.get("path_info"),
                                   gate=ctx.get("gate")) or []}


def _suite_backupfiles(target, ctx):
    from omega.scanning.backupfiles import run_backupfiles
    return {"findings": run_backupfiles(target, ctx["fetch"],
                                        path_info=ctx.get("path_info"),
                                        gate=ctx.get("gate")) or []}


def _suite_cmsprobe(target, ctx):
    from omega.scanning.cmsprobe import run_cmsprobe
    return {"findings": run_cmsprobe(target, ctx["fetch"],
                                     path_info=ctx.get("path_info"),
                                     gate=ctx.get("gate")) or []}


def _suite_secretjs(target, ctx):
    from omega.scanning.secretjs import run_secretjs
    return {"findings": run_secretjs(target, ctx["fetch"],
                                     path_info=ctx.get("path_info"),
                                     gate=ctx.get("gate")) or []}


def _suite_cspanalyze(target, ctx):
    from omega.scanning.cspanalyze import run_cspanalyze
    return {"findings": run_cspanalyze(target, ctx["fetch"],
                                       path_info=ctx.get("path_info"),
                                       gate=ctx.get("gate")) or []}



def _suite_secops(target, ctx):
    from omega.secops import run_secops
    return run_secops(target, fetch=ctx["fetch"], budget=ctx["budget"],
                      log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_blotamper(target, ctx):
    from omega.blotamper import run_blotamper
    return run_blotamper(target, fetch=ctx["fetch"], budget=ctx["budget"],
                         log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_mobile_android(target, ctx):
    from omega.scanning.mobandroid import run_android
    return run_android(target)


def _suite_mobile_ios(target, ctx):
    from omega.scanning.mobios import run_ios
    return run_ios(target)


def _suite_mobile_general(target, ctx):
    from omega.scanning.mobgeneral import run_mobile_general
    return run_mobile_general(target)


def _suite_cloudsec(target, ctx):
    from omega.cloudsec import run_cloudsec
    return run_cloudsec(target, fetch=ctx["fetch"], budget=ctx["budget"],
                        log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_k8ssec(target, ctx):
    from omega.k8ssec import run_k8ssec
    return run_k8ssec(target, fetch=ctx["fetch"], budget=ctx["budget"],
                      log=ctx["log"])


def _suite_cicdsec(target, ctx):
    from omega.cicdsec import run_cicdsec
    return run_cicdsec(target, fetch=ctx["fetch"], budget=ctx["budget"],
                       log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_llmsec(target, ctx):
    from omega.llmsec import run_llmsec
    return run_llmsec(target, fetch=ctx["fetch"],
                      log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_dbsec(target, ctx):
    from omega.dbsec import run_dbsec
    return run_dbsec(target, fetch=ctx["fetch"],
                     log=ctx["log"], allowlist=ctx["allowlist"])


def _suite_request_class(name, runner_name):
    """Factory for request-level attack-class suites (wsprobe /
    corscheck / hpp / crlf): each module exposes run_<name>(base_url,
    fetch, path_info, gate) returning a list of Finding dicts."""
    def _suite(target, ctx):
        import importlib
        mod = importlib.import_module("omega.scanning.%s" % name)
        run = getattr(mod, runner_name)
        try:
            findings = run(target, fetch=ctx["fetch"],
                           path_info=ctx.get("path_info"),
                           gate=ctx.get("gate")) or []
        except Exception as exc:
            return {"findings": [], "skipped": [str(exc)]}
        return {"findings": findings}
    _suite.__name__ = "_suite_%s" % name
    return _suite


_suite_wsprobe = _suite_request_class("wsprobe", "run_wsprobe")
_suite_corscheck = _suite_request_class("corscheck", "run_corscheck")
_suite_hpp = _suite_request_class("hpp", "run_hpp")
_suite_crlf = _suite_request_class("crlf", "run_crlf")

_suite_csrf = _suite_request_class("csrf", "run_csrf")
_suite_secondorder = _suite_request_class("secondorder", "run_secondorder")


# name, language, runner (the jq hygiene pass runs post-collection and
# is appended separately)
def _suite_xxe(target, ctx):
    from omega.scanning.xxe import run_xxe
    return {"findings": run_xxe(target, fetch=ctx["fetch"],
                                path_info=ctx.get("path_info"),
                                gate=ctx.get("gate")) or []}


def _suite_ssrf(target, ctx):
    from omega.scanning.ssrf import run_ssrf
    return {"findings": run_ssrf(target, fetch=ctx["fetch"],
                                 path_info=ctx.get("path_info"),
                                 gate=ctx.get("gate")) or []}


def _suite_tlsconf(target, ctx):
    from omega.scanning.tlsconf import run_tlsconf
    return {"findings": run_tlsconf(target, fetch=ctx["fetch"],
                                    path_info=ctx.get("path_info"),
                                    gate=ctx.get("gate")) or []}


def _suite_apidocs(target, ctx):
    from omega.scanning.apidocs import run_apidocs
    return {"findings": run_apidocs(target, fetch=ctx["fetch"],
                                    path_info=ctx.get("path_info"),
                                    gate=ctx.get("gate")) or []}


def _suite_mobdeep(target, ctx):
    from omega.scanning.mobdeep import run_mobdeep
    return {"findings": run_mobdeep(target, fetch=ctx["fetch"],
                                    path_info=ctx.get("path_info"),
                                    gate=ctx.get("gate")) or []}


def _suite_mobapi(target, ctx):
    from omega.scanning.mobapi import run_mobapi
    return {"findings": run_mobapi(target, fetch=ctx["fetch"],
                                   path_info=ctx.get("path_info"),
                                   gate=ctx.get("gate")) or []}


SUITES = (
    ("python-pytools", "python", _suite_pytools),
    ("python-probes", "python", _suite_probes),
    ("python-deep", "python", _suite_deep),
    ("python-browser", "python", _suite_browser),
    ("native", "go+node", _suite_native),
    ("system", "system-binaries", _suite_system),
    ("perl", "perl", _suite_perl),
    ("python-chaos", "python", _suite_chaos),
    ("python-api", "python", _suite_api),
    ("python-graphql-deep", "python", _suite_graphql_deep),
    ("python-offense", "python", _suite_offense),
    ("python-hyper", "python", _suite_hyper),
    ("python-headerscan", "python", _suite_headerscan),
    ("python-redirects", "python", _suite_redirects),
    ("python-oobscan", "python", _suite_oobscan),
    ("python-jsrender", "python", _suite_jsrender),
    ("python-subperm", "python", _suite_subperm),
    ("go-dirscan", "go", _suite_go_dirscan),
    ("node-hdr", "node", _suite_node_hdr),
    ("jq-diff", "jq", _suite_jq_diff),
    ("python-sentinel", "python", _suite_sentinel),
    ("c-urlinfo", "c", _suite_c_urlinfo),
    ("ruby-urlaudit", "ruby", _suite_ruby_urlaudit),
    ("cpp-hdrstruct", "cpp", _suite_cpp_hdrstruct),
    ("awk-urlmine", "awk", _suite_awk_urlmine),
    ("sh-methodcheck", "bash", _suite_sh_methodcheck),
    ("rust-pathscope", "rust", _suite_rust_pathscope),
    ("php-seriscan", "php", _suite_php_seriscan),
    ("smuggle-raw", "go+python", _suite_smuggle),
    ("hh-inject", "python", _suite_hhint),
    ("ssti-engine", "python", _suite_ssti),
    ("deser-safe", "python", _suite_deser),
    ("upl-hygiene", "python", _suite_uplprobe),
    ("secops-hygiene", "python", _suite_secops),
    ("blotamper", "python", _suite_blotamper),
    ("mobile-android", "python", _suite_mobile_android),
    ("mobile-ios", "python", _suite_mobile_ios),
    ("mobile-general", "python", _suite_mobile_general),
    ("cloud-exposure", "python", _suite_cloudsec),
    ("k8s-exposure", "python", _suite_k8ssec),
    ("cicd-chain", "python", _suite_cicdsec),
    ("llm-app", "python", _suite_llmsec),
    ("db-backend", "python", _suite_dbsec),
    ("wsprobe", "python", _suite_wsprobe),
    ("corscheck", "python", _suite_corscheck),
    ("hpp", "python", _suite_hpp),
    ("crlf", "python", _suite_crlf),
    ("authbypass", "python", _suite_authbypass),
    ("resetpoison", "python", _suite_resetpoison),
    ("userenum", "python", _suite_userenum),
    ("libcve", "python", _suite_libcve),
    ("backupfiles", "python", _suite_backupfiles),
    ("cmsprobe", "python", _suite_cmsprobe),
    ("secretjs", "python", _suite_secretjs),
    ("cspanalyze", "python", _suite_cspanalyze),
    ("xxe", "python", _suite_xxe),
    ("ssrf", "python", _suite_ssrf),
    ("tlsconf", "python", _suite_tlsconf),
    ("apidocs", "python", _suite_apidocs),
    ("mobdeep", "python", _suite_mobdeep),
    ("mobapi", "python", _suite_mobapi),
    ("csrf", "python", _suite_csrf),
    ("secondorder", "python", _suite_secondorder),
)


def _merge_surface(agg, res):
    for key in ("hosts", "urls", "ports", "techs"):
        vals = (res.get("surface") or {}).get(key)
        if vals is None and key in (res or {}):
            vals = res.get(key)
        if not vals:
            continue
        cur = agg.setdefault(key, [])
        for v in vals:
            if v and v not in cur:
                cur.append(v)


def fuse(target, fetch=None, budget=None, log=None,
         allowlist=None, which_fn=shutil.which, gate=True, suites=None,
         followup=False):
    """Run the available scanner suites concurrently, corroborate and
    return {findings, corroborated, surface, ran, skipped,
    languages_used}. Never raises.

    `suites` optionally restricts the run to a subset of SUITES by
    suite name (allowlist); None/empty runs every suite.
    `followup=True` additionally runs the adaptive follow-up loop
    (omega.scanning.followup.run_followups) over the collected findings
    and merges the gate-verified second-depth probe claims into the
    result; refuted/skipped probes are reported under result['followup'].
    """
    log = log or (lambda msg: None)
    if budget is None:
        budget = _fusion_budget()
    from omega.deepchecks import default_fetch as _default_fetch
    ctx_fetch = fetch or _default_fetch
    # allowlist must be an iterable scope spec (dict/list); a bare True
    # boolean means "operator authorized" — normalize to None so suites
    # that expect an iterable get a safe default instead of TypeError.
    ctx_allow = allowlist if (allowlist is None or hasattr(allowlist, "__iter__")) else None
    # Light link/param discovery so path-aware checks (XSS reflection,
    # SQLi error diff, ...) probe crawled endpoints, not just '/'.
    path_info = {"paths": [], "params": []}
    try:
        st, _h, body = ctx_fetch("GET", target if "://" in target
                                 else "https://" + target)
        text = (body or b"").decode("latin-1", "replace")
        import re as _re
        import urllib.parse as _up
        base = target.rstrip("/")
        for href in _re.findall(r'href=["\']([^"\'#?]+)[^"\']*', text):
            if href.startswith(("http://", "https://")):
                if not href.startswith(base):
                    continue
                href = href[len(base):] or "/"
            if not href.startswith("/") or href.startswith("//"):
                continue
            clean = _up.urlparse(href).path or "/"
            if clean not in path_info["paths"]:
                path_info["paths"].append(clean)
            for k in _up.parse_qs(_up.urlparse(href).query):
                if k not in path_info["params"]:
                    path_info["params"].append(k)
            if len(path_info["paths"]) >= 30:
                break
    except Exception:
        pass
    ctx = {"fetch": ctx_fetch, "budget": budget, "allowlist": ctx_allow,
           "which_fn": which_fn, "gate": bool(gate), "log": log,
           "path_info": path_info}

    selected = SUITES
    if suites:
        wanted = {str(s) for s in suites}
        selected = tuple(s for s in SUITES if s[0] in wanted)

    all_findings, surface = [], {}
    ran, skipped = [], []
    languages_used = []

    def run_one(name, language, runner):
        try:
            res = runner(target, ctx) or {}
            return name, language, res, None
        except Exception as exc:
            return name, language, {}, f"{type(exc).__name__}: {exc}"

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(run_one, name, lang, runner)
                   for name, lang, runner in selected]
        for fut in futures:
            name, language, res, err = fut.result()
            if err is not None:
                skipped.append({"suite": name, "reason": err})
                log(f"[fusion] suite {name} failed: {err}")
                continue
            ran.append(name)
            languages_used.append(language)
            all_findings.extend(res.get("findings") or [])
            _merge_surface(surface, res)
            res_skips = res.get("skipped") or []
            if isinstance(res_skips, dict):
                res_skips = [{"tool": k, "reason": v}
                             for k, v in res_skips.items()]
            for s in res_skips:
                if isinstance(s, dict) and s.get("tool") is not None:
                    skipped.append({"suite": f"{name}:{s['tool']}",
                                    "reason": str(s.get("reason", ""))})
                elif isinstance(s, dict):
                    skipped.append({"suite": name,
                                    "reason": str(s.get("reason", s))})
                else:
                    skipped.append({"suite": name, "reason": str(s)})
            log(f"[fusion] suite {name}: {len(res.get('findings') or [])} "
                f"finding(s)")

    # ---- jq data-hygiene pass (on collected findings) --------------------
    try:
        from omega.adapters.jqtools import run_jq_suite
        jq_res = run_jq_suite(all_findings, log=log, which_fn=which_fn)
        ran.extend(jq_res.get("ran") or [])
        languages_used.append("jq")
        for s in (jq_res.get("skipped") or []):
            skipped.append({"suite": "jq", "reason": s.get("reason", "")})
        for q in (jq_res.get("quarantined") or []):
            skipped.append({"suite": "jq:quarantine",
                            "reason": q.get("reason", "")})
        all_findings = jq_res.get("findings") or []
    except Exception as exc:  # hygiene layer must never break fusion
        skipped.append({"suite": "jq", "reason": f"{type(exc).__name__}: {exc}"})
        log(f"[fusion] jq hygiene layer failed: {exc}")

    # ---- corroboration ----------------------------------------------------
    annotated, corroborated = corroborate(all_findings)
    annotated = sort_findings(annotated)
    corroborated = sort_findings(corroborated)

    # ---- adaptive follow-up loop (opt-in) ---------------------------------
    followup_info = None
    if followup:
        try:
            from omega.scanning.followup import run_followups
            fu = run_followups(annotated, fetch=ctx_fetch,
                               base_url=target, log=log)
            annotated = fu.get("findings") or annotated
            annotated = sort_findings(annotated)
            followup_info = {"refuted": fu.get("refuted") or [],
                             "skipped": fu.get("skipped") or [],
                             "probes": fu.get("probes") or 0}
            log("[fusion] followup: %d probe(s), %d refuted, %d skipped"
                % (followup_info["probes"],
                   len(followup_info["refuted"]),
                   len(followup_info["skipped"])))
        except Exception as exc:  # followup layer must never break fusion
            skipped.append({"suite": "followup",
                            "reason": f"{type(exc).__name__}: {exc}"})

    if log:
        log(f"[fusion] done: {len(annotated)} finding(s), "
            f"{len(corroborated)} corroborated, "
            f"languages={sorted(set(languages_used))}")

    out = {
        "findings": annotated,
        "corroborated": corroborated,
        "surface": surface,
        "ran": ran,
        "skipped": skipped,
        "languages_used": sorted(set(languages_used)),
    }
    if followup_info is not None:
        out["followup"] = followup_info
    return out
