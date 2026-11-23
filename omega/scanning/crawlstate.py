"""omega/scanning/crawlstate — stateful session crawler.

Static JS analysis (spamap) misses endpoints that only open after an
ACTION: login, add-to-cart, checkout, multi-step forms. crawlstate
walks action flows with a real session: parse forms, fill, submit,
collect every URL/state reached, and hand the expanded surface to the
brain. No headless browser — plain HTTP with html.parser. Never
submits destructive values; form fills use inert markers.
"""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

__all__ = ["CrawlState", "crawl_flows"]

_FORM_FIELDS_SKIP = ("password", "passwd", "pwd", "cvv", "card")


class _Forms(HTMLParser):
    """Collect forms + links from one page."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.links = []
        self._cur = None
        self._field = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action") or "",
                         "method": (a.get("method") or "GET").upper(),
                         "fields": []}
        elif tag == "input" and self._cur is not None:
            name = a.get("name")
            if name and (a.get("type") or "text").lower() not in \
                    ("submit", "hidden"):
                self._cur["fields"].append(
                    {"name": name, "type": (a.get("type") or "text")})
        elif tag == "textarea" and self._cur is not None:
            self._field = a.get("name")
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "form" and self._cur:
            self.forms.append(self._cur)
            self._cur = None
        elif tag == "textarea" and self._cur and self._field:
            self._cur["fields"].append({"name": self._field,
                                        "type": "text"})
            self._field = None


class CrawlState:
    """One crawling session with a bound fetch adapter."""

    def __init__(self, fetch, base, max_pages=30, log=None):
        self.fetch = fetch          # url_fetch()-compatible
        self.base = base
        self.max_pages = max_pages
        self.log = log
        self.visited = set()
        self.discovered = set()     # new urls (params stripped)
        self.forms = []             # actionable forms found
        self.flows = []             # action records

    def _text(self, url):
        resp = self.fetch(url)
        if resp is None:
            return "", 0
        return (resp if isinstance(resp, str) else
                getattr(resp, "text", "") or ""), \
            getattr(resp, "status", 0) or 0

    def crawl(self, start_urls):
        queue = [u for u in start_urls if u][:self.max_pages]
        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            norm = urlparse(url)._replace(query="", fragment="")\
                .geturl()
            if norm in self.visited:
                continue
            self.visited.add(norm)
            body, status = self._text(url)
            if not body:
                continue
            p = _Forms()
            try:
                p.feed(body)
            except Exception:
                continue
            for href in p.links[:25]:
                absu = urljoin(url, href)
                if urlparse(absu).netloc == urlparse(self.base).netloc:
                    self.discovered.add(urlparse(absu)
                                        ._replace(query="", fragment="")
                                        .geturl())
                    if absu not in self.visited:
                        queue.append(absu)
            for f in p.forms:
                action = urljoin(url, f["action"] or url)
                self.forms.append({"url": action, "method": f["method"],
                                   "fields": f["fields"]})
        if self.log:
            self.log(f"crawlstate: pages={len(self.visited)} "
                     f"discovered={len(self.discovered)} "
                     f"forms={len(self.forms)}")
        return self

    def submit_flow(self, form, marker="omegastate"):
        """Fill a form with inert markers and submit once.

        Records the resulting state (url + status). Sensitive fields
        (password/card) are NOT filled — those need real creds via
        --with-auth.
        """
        url = form["url"]
        method = form.get("method") or "GET"
        fills = {}
        for fld in form.get("fields") or []:
            name = fld.get("name") or ""
            ftype = (fld.get("type") or "text").lower()
            if any(s in name.lower() for s in _FORM_FIELDS_SKIP) or \
                    ftype == "password":
                continue
            fills[name] = f"{marker}_{name}"
        query = "&".join(f"{k}={v}" for k, v in fills.items())
        target = url if method == "POST" else \
            url + ("&" if "?" in url else "?") + query
        try:
            resp = self.fetch(target, method=method, body=query
                              if method == "POST" else None)
            status = getattr(resp, "status", 0)
        except Exception:
            status = 0
        rec = {"url": url, "method": method, "filled": list(fills),
               "status": status}
        self.flows.append(rec)
        if status and 200 <= status < 400:
            self.discovered.add(url)
        if self.log:
            self.log(f"crawlstate: submit {method} {url} -> {status}")
        return rec


def crawl_flows(fetch, base, start_urls, max_pages=30, submit=False,
                log=None):
    """Crawl the surface, optionally submit inert-marker flows.

    Returns {"urls": [...], "forms": [...], "flows": [...]} for the
    brain surface — the discovered endpoints join the next scan wave.
    """
    cs = CrawlState(fetch, base, max_pages=max_pages, log=log)
    cs.crawl(start_urls or [base])
    if submit:
        for f in cs.forms[:10]:
            cs.submit_flow(f)
    return {"urls": sorted(cs.discovered), "forms": cs.forms,
            "flows": cs.flows}
