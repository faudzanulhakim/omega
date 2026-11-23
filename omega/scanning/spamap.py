"""omega/scanning/spamap — static JS/SPA endpoint mapper.

Covers the SPA blind spot without a headless browser: fetches the
target page, extracts <script src> assets, and statically analyzes
each JS bundle for API-surface markers:

  - fetch("...") / fetch('...')  |  axios.{get,post,put,...}("...")
  - XMLHttpRequest.open(METHOD, "...")
  - url: "..." / endpoint: "..." / baseURL: "..."
  - template-literal paths `...${id}` (params recorded as {id})

All responses are processed as DATA. Fetch budget is capped and
assets over ASSET_MAX bytes are truncated. Never sends anything
beyond benign GETs for the page and its scripts.
"""
import re

__all__ = ["map_spa_endpoints"]

FETCH_BUDGET = 8
try:
    from omega.scanning.probes import MAX_BODY as ASSET_MAX
except ImportError:  # standalone import; keep historical bound
    ASSET_MAX = 256 * 1024
_JS_RE = re.compile(r"""(?:fetch|axios\.\w+|open)\s*\(\s*["'`]([^"'`\s,]{2,200})["'`]""", re.I)
_URL_RE = re.compile(r"""(?:url|endpoint|baseURL|apiUrl|apiBase)\s*[:=]\s*["'`]([^"'`\s]{2,200})["'`]""", re.I)
_TPL_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-/{}$.\s]{2,120})["'`]""")
_METHOD_RE = re.compile(r"""(get|post|put|patch|delete)\s*\(\s*["'`]""", re.I)
_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+\.(?:js|mjs))["']""", re.I)


def _normalize(u):
    u = u.strip()
    u = re.sub(r"\$\{[^}]*\}", "{param}", u)
    if not u or u.startswith(("data:", "javascript:", "#")):
        return None
    if u.startswith("//"):
        u = "https:" + u
    return u


def _analyze_js(body, api_only=True):
    found = {}
    for m in _JS_RE.finditer(body):
        u = _normalize(m.group(1))
        if u:
            u = u.split("?", 1)[0]
        if u and (not api_only or u.startswith(("/api", "/v1", "/v2",
                                                 "/graphql")) or "api" in u):
            found[u] = "ajax"
    for m in _URL_RE.finditer(body):
        u = _normalize(m.group(1))
        if u and (not api_only or "api" in u.lower() or
                  u.startswith(("/", "/api"))):
            found[u] = "config"
    return found


def map_spa_endpoints(url, fetch=None, log=None, budget=FETCH_BUDGET):
    """Return {'endpoints': {path: [param names]}, 'assets': [...],
    'methods': {...}} — static analysis, no execution of JS."""
    out = {"endpoints": {}, "assets": [], "methods": {},
           "incomplete": False, "truncated_assets": []}

    def _get(u):
        """Fetch a URL through any supported fetch contract and return
        (body_text, truncated). Handles fetch(url), fetch("GET", url),
        3-tuples, 4-tuples with meta, and _FetchResp-like objects."""
        try:
            r = fetch(u)
        except TypeError:
            r = fetch("GET", u)
        if isinstance(r, tuple):
            if len(r) == 4:  # (status, headers, body, meta) — detailed
                body, meta = r[2], r[3]
                trunc = bool(meta.get("truncated")) \
                    if isinstance(meta, dict) else False
            else:
                body, trunc = r[2], False
            text = body.decode("utf-8", "replace") \
                if isinstance(body, bytes) else str(body or "")
            return text, trunc
        text = getattr(r, "text", None)
        if text is None:
            text = r if isinstance(r, str) else ""
        return text, False

    if fetch is None:
        try:
            from omega.scanning.probes import fetch_detailed as _fd
            fetch = lambda u: _fd("GET", u)  # noqa: E731
        except ImportError:
            from omega.deepchecks import default_fetch
            fetch = default_fetch
    try:
        page, _t = _get(url)
    except Exception as exc:
        if log:
            log("spamap: fetch failed: %s" % exc)
        return out
    srcs = [m.group(1) for m in _SRC_RE.finditer(page)][:budget]
    if log:
        log("spamap: %d script assets" % len(srcs))
    for src in srcs:
        if src.startswith("//"):
            src = "https:" + src
        if src.startswith("/"):
            root = url.split("://", 1)
            src = root[0] + "://" + root[1].split("/", 1)[0] + src
        elif not src.startswith("http"):
            continue
        out["assets"].append(src)
        if len(out["assets"]) >= budget:
            break
        try:
            body, truncated = _get(src)
        except Exception:
            continue
        if len(body) > ASSET_MAX:
            body = body[:ASSET_MAX]
            truncated = True
        if truncated:
            # asset was cut before fully analyzed: mark the result so no
            # one claims complete endpoint coverage for it
            out["incomplete"] = True
            out["truncated_assets"].append(src)
        for path, kind in _analyze_js(body).items():
            params = re.findall(r"\{(\w+)\}", path)
            out["endpoints"][path] = params
            mm = _METHOD_RE.search(body)
            if mm:
                out["methods"].setdefault(path, mm.group(1).upper())
    if log:
        log("spamap: %d candidate endpoints" % len(out["endpoints"]))
    return out
