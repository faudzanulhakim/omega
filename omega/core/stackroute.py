"""omega/core/stackroute — fingerprint-to-module routing.

From recon technologies, decide WHICH attack modules are worth running
and in what order, instead of firing everything blindly. Saves budget
on irrelevant techniques and guarantees relevant ones fire first.
Pure mapping — no network.
"""
__all__ = ["route_stack", "explain_route"]

# tech fragment -> (priority capabilities, notes)
_ROUTES = {
    "grafana": (["offense.authblast", "offense.hackwave"],
                "Grafana: default admin:admin, plugin path traversal, "
                "CVE-2021-43798 style file read"),
    "jenkins": (["offense.authblast", "core.cvesuggest"],
                "Jenkins: default creds, script console RCE once authed, "
                "CVE-2024-23897 file read"),
    "tomcat": (["offense.authblast", "offense.hackwave"],
               "Tomcat: manager default creds, AJP ghostcat, "
               "CVE-2020-1938"),
    "wordpress": (["offense.authblast", "scanning.deepchecks",
                   "core.cvesuggest"],
                  "WordPress: xmlrpc brute, plugin enumeration, "
                  "version CVEs"),
    "php": (["offense.hackwave", "core.cwechain"],
            "PHP: type juggling, LFI/RFI chains, deserialization"),
    "node": (["scanning.spamap", "offense.hackwave"],
             "Node/Express: prototype pollution, SSRF via url params, "
             "JWT weaknesses"),
    "java": (["core.cvesuggest", "offense.hackwave"],
             "Java: deserialization, Spring Actuator, Log4Shell class "
             "of bugs"),
    "spring": (["core.cvesuggest", "offense.hackwave"],
               "Spring: Actuator exposure, Spring4Shell, SpEL"),
    "django": (["core.cvesuggest", "offense.hackwave"],
               "Django: debug page leakage, SQLi via ORM edge cases"),
    "flask": (["offense.hackwave", "core.cwechain"],
              "Flask: SSTI via Jinja, debug console (Werkzeug)"),
    "cloudflare": (["core.wafadapt", "offense.mutafuzz"],
                   "Cloudflare: WAF mutation loop, origin discovery"),
    "aws": (["core.cvesuggest", "core.cwechain"],
            "AWS: metadata SSRF chains, S3 misconfig, IAM pivots"),
    "nginx": (["core.wafadapt", "scanning.deepchecks"],
              "nginx: alias traversal, off-by-slash, misconfig"),
    "apache": (["scanning.deepchecks", "core.cvesuggest"],
               "Apache: traversal aliases, CVE-2021-41773 class"),
    "kubernetes": (["core.cvesuggest", "core.cwechain"],
                   "K8s: API anonymous access, dashboard exposure, "
                   "etcd"),
}


def route_stack(techs, extra_caps=None):
    """Ordered module route for the detected stack."""
    found = []
    hits = []
    for t in techs or []:
        key = str(t).lower()
        for frag, (caps, note) in _ROUTES.items():
            if frag in key:
                hits.append(frag)
                for c in caps:
                    if c not in found:
                        found.append(c)
    if not hits:
        found = ["offense.hackwave", "scanning.deepchecks",
                 "core.cwechain"]
    for c in (extra_caps or []):
        if c not in found:
            found.append(c)
    return {"stack": sorted(set(hits)),
            "route": found,
            "reason": " | ".join(_ROUTES[h][1] for h in
                                 sorted(set(hits))) or
                      "no fingerprint match — generic brutal route"}


def explain_route(techs):
    r = route_stack(techs)
    return (f"stack: {', '.join(r['stack']) or 'unknown'}\n"
            f"route: {' -> '.join(r['route'])}\n"
            f"why: {r['reason']}")
