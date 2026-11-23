"""omega/core/frameworks.py — framework-specific technique kits.

When a fingerprint matches (headers, generator meta, cookies, body
markers), the brain gets a small surgical kit instead of generic
payload spam: framework-native endpoints, check names and hints that
actually apply to that stack.

Kits are DATA (paths + check ids + note). They never execute anything
themselves; the caller decides which suites to run.

Coverage: wordpress, drupal, joomla, jenkins, tomcat, genexus,
grafana, gitlab, spring, laravel, django, rails, nextjs, nginx-unit,
kubernetes-dashboard.
"""

from __future__ import annotations

__all__ = ["KITS", "detect_frameworks", "kit_for", "kit_paths"]

KITS = {
    "wordpress": {
        "signatures": ("wp-content", "wp-includes", "wordpress",
                       "wp-login.php"),
        "cookies": ("wordpress_", "wp-settings"),
        "paths": ("/wp-login.php", "/xmlrpc.php", "/wp-json/wp/v2/users",
                  "/?author=1", "/wp-admin/", "/wp-content/debug.log",
                  "/wp-config.php.bak"),
        "checks": ("userenum", "backupfiles", "secretjs", "attackscan"),
        "note": "xmlrpc pingback SSRF + author enumeration + plugin "
                "enumeration are the highest-signal paths",
    },
    "drupal": {
        "signatures": ("drupal", "sites/default/files", "x-generator: drupal"),
        "cookies": ("sseess", "drupal"),
        "paths": ("/user/login", "/CHANGELOG.txt", "/core/CHANGELOG.txt",
                  "/sites/default/settings.php.bak", "/?q=admin"),
        "checks": ("backupfiles", "userenum", "attackscan"),
        "note": "Drupalgeddon-style form API and CHANGELOG version leaks",
    },
    "joomla": {
        "signatures": ("joomla", "/media/system/js/", "com_content"),
        "cookies": ("joomla",),
        "paths": ("/administrator/", "/configuration.php.bak",
                  "/administrator/manifests/files/joomla.xml"),
        "checks": ("backupfiles", "userenum"),
        "note": "configuration.php backups + version manifest",
    },
    "jenkins": {
        "signatures": ("x-jenkins", "jenkins", "hudson"),
        "cookies": ("jsessionid",),
        "paths": ("/script", "/manage", "/asynchPeople/",
                  "/systemInfo", "/cli", "/jnlpJars/jenkins-cli.jar"),
        "checks": ("authbypass", "backupfiles", "secops-hygiene"),
        "note": "/script console RCE when unauthenticated; check "
                "anonymous read",
    },
    "tomcat": {
        "signatures": ("tomcat", "coyote", "jsessionid"),
        "cookies": ("jsessionid",),
        "paths": ("/manager/html", "/host-manager/html", "/examples/",
                  "/docs/", "/WEB-INF/web.xml"),
        "checks": ("authbypass", "backupfiles", "libcve"),
        "note": "manager app default creds + AJP exposure; version "
                "banner leak validated first",
    },
    "genexus": {
        "signatures": ("gxgral.js", "gxcfg.js", "gxstate", "genexus"),
        "cookies": ("gxsession",),
        "paths": ("/gxmulticall", "/gxwebsession", "/rest/",
                  "/servlet/com.genexus.webpanels.GXWebPanel"),
        "checks": ("attackscan", "authbypass", "hpp", "crlf"),
        "note": "GXState is client-carried state — test tampering; "
                "gxmulticall accepts JSON web-object calls",
    },
    "grafana": {
        "signatures": ("grafana", "grafana_session"),
        "cookies": ("grafana_session",),
        "paths": ("/api/health", "/api/dashboards/home", "/login",
                  "/api/admin/settings", "/public/plugins/"),
        "checks": ("cvefeed", "authbypass", "secretjs"),
        "note": "plugin path traversal + anonymous dashboard access",
    },
    "gitlab": {
        "signatures": ("gitlab", "_gitlab_session"),
        "cookies": ("_gitlab_session",),
        "paths": ("/-/health", "/users/sign_in", "/api/v4/users",
                  "/-/graphql", "/admin/users"),
        "checks": ("authbypass", "userenum", "secretjs"),
        "note": "GraphQL user enumeration + public project leaks",
    },
    "spring": {
        "signatures": ("whitelabel error page", "spring boot",
                       "x-application-context"),
        "cookies": ("jsessionid",),
        "paths": ("/actuator", "/actuator/env", "/actuator/heapdump",
                  "/actuator/mappings", "/v2/api-docs", "/swagger-ui.html"),
        "checks": ("apiintel", "apidocs", "backupfiles", "secops-hygiene"),
        "note": "actuator endpoints leak env/heapdump when exposed",
    },
    "laravel": {
        "signatures": ("laravel_session", "x-powered-by: php"),
        "cookies": ("laravel_session", "xsrf-token"),
        "paths": ("/telescope", "/_ignition/execute-solution", "/.env",
                  "/storage/logs/laravel.log", "/horizon"),
        "checks": ("backupfiles", "secretjs", "cvefeed"),
        "note": ".env + ignition RCE (CVE-2021-3129 family)",
    },
    "django": {
        "signatures": ("csrftoken", "django", "x-frame-options: deny"),
        "cookies": ("csrftoken", "sessionid"),
        "paths": ("/admin/", "/api/", "/static/admin/", "/__debug__/"),
        "checks": ("userenum", "apidocs", "cmsgprobe"),
        "note": "admin exposure + DEBUG traceback pages",
    },
    "rails": {
        "signatures": ("_rails", "action_dispatch", "x-runtime"),
        "cookies": ("_session_id", "_rails"),
        "paths": ("/rails/info/properties", "/rails/info/routes",
                  "/assets/", "/cable"),
        "checks": ("backupfiles", "secretjs"),
        "note": "info/properties leaks DB config in dev mode",
    },
    "nextjs": {
        "signatures": ("__next_data__", "_next/static", "x-nextjs"),
        "cookies": ("__next",),
        "paths": ("/_next/static/", "/api/", "/_next/data/"),
        "checks": ("secretjs", "apiintel"),
        "note": "__NEXT_DATA__ can leak server-side props and env",
    },
    "kubernetes-dashboard": {
        "signatures": ("kubernetes-dashboard", "kubernetes dashboard"),
        "cookies": ("k8s",),
        "paths": ("/api/v1/namespaces", "/api/v1/pods", "/#/login",
                  "/api/v1/secrets"),
        "checks": ("k8s-exposure", "authbypass"),
        "note": "service-account token exposure + anonymous API access",
    },
}

# name, header-name fragments that count as strong signals
HEADER_SIGNATURES = {
    "jenkins": ("x-jenkins",),
    "grafana": ("x-grafana",),
    "nextjs": ("x-nextjs-",),
    "django": (),
}


def detect_frameworks(headers=None, body="", cookies=None):
    """Return kit names matched by response headers/body/cookies.

    Args:
      headers — dict or list of (k, v) pairs (case-insensitive)
      body — response text (first ~200 KB is enough)
      cookies — iterable of cookie names or a raw Cookie header string

    Returns a deterministic list (registry order).
    """
    hdr = {}
    if isinstance(headers, dict):
        hdr = {str(k).lower(): str(v) for k, v in headers.items()}
    elif headers:
        for k, v in headers:
            hdr.setdefault(str(k).lower(), str(v))
    text = (body or "").lower()
    ck = ""
    if isinstance(cookies, str):
        ck = cookies.lower()
    elif cookies:
        ck = ";".join(str(c) for c in cookies).lower()

    found = []
    hdr_join = " ".join("%s=%s" % (k, v) for k, v in hdr.items())
    for name, kit in KITS.items():
        hit = False
        for sig in kit.get("signatures", ()):
            s = sig.lower()
            if ":" in s:
                h, _, v = s.partition(":")
                if v in hdr.get(h.strip(), ""):
                    hit = True
                    break
            elif s in text or s in hdr_join:
                hit = True
                break
        if not hit:
            for c in kit.get("cookies", ()):
                if c.lower() in ck or c.lower() in hdr.get("set-cookie", ""):
                    hit = True
                    break
        if not hit:
            for frag in HEADER_SIGNATURES.get(name, ()):
                if frag in " ".join("%s:%s" % (k, v)
                                    for k, v in hdr.items()):
                    hit = True
                    break
        if hit:
            found.append(name)
    return found


def kit_for(name):
    """Return the kit dict for a framework name (or None)."""
    return KITS.get(str(name or "").lower())


def kit_paths(names):
    """Union of kit probe paths for a list of framework names."""
    out = []
    for n in names or []:
        for p in (KITS.get(n, {}).get("paths") or ()):
            if p not in out:
                out.append(p)
    return out
