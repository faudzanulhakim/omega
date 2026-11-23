"""omega/scanning/cloudsec.py — external cloud exposure checks (read-only).

HTTP-based, given a target domain / org name:

  * public storage buckets — anonymous GET/HEAD against constructed
    bucket URLs (S3 virtual-host + regional, GCS path-style, Azure
    blob). ``ListBucketResult`` XML in the response -> CRITICAL
    confirmed (public listing). ``AccessDenied`` -> INFO (exists but
    private). ``NoSuchBucket`` / any other error -> silent skip.
  * exposed cloud workloads — cloud-flavored paths on the target that
    the deepchecks layer does NOT already cover (/.aws/credentials,
    /appspec.yml, /docker-compose.yml); HIGH confirmed only when the
    body matches a fingerprint (honesty contract).
  * IMDSv1 via SSRF — when SSRF-prone parameters are known (passed in
    as ``ssrf_params``), the metadata URL
    http://169.254.169.254/latest/meta-data/ is injected; a response
    containing ``ami-id`` -> CRITICAL confirmed.

Anonymous read-only GETs only. ``run_cloudsec`` never raises.
"""

from __future__ import annotations

import urllib.parse

__all__ = [
    "BUCKET_SUFFIXES",
    "CLOUD_PATHS",
    "FINGERPRINTS",
    "IMDS_METADATA_URL",
    "bucket_names",
    "probe_buckets",
    "probe_cloud_paths",
    "probe_imds_ssrf",
    "run_cloudsec",
]

from omega.probes import Finding, allowlist_ok, default_fetch

FETCH_TIMEOUT = 5.0
DEFAULT_REGIONS = ("us-east-1", "eu-west-1", "us-west-2")

BUCKET_SUFFIXES = ("", "-backup", "-dev", "-assets", "-staging",
                   "-prod", "-media", "-data", "-logs", "-tmp")

IMDS_METADATA_URL = "http://169.254.169.254/latest/meta-data/"

# cloud-flavored exposed-workload paths (deepchecks already covers
# /.env, /.git/HEAD, /backup.zip, /config.json, /.DS_Store, /dump.sql)
CLOUD_PATHS = ("/.aws/credentials", "/appspec.yml", "/docker-compose.yml")

FINGERPRINTS = {
    "/.aws/credentials": ("[default]", "aws_access_key_id"),
    "/appspec.yml": ("version:", "hooks"),
    "/docker-compose.yml": ("services:", "environment",
                            ("password", "secret")),
}


def bucket_names(org):
    """Name candidates for an org: sanitized org name + common suffixes."""
    base = "".join(
        ch for ch in str(org or "").strip().lower()
        if ch.isalnum() or ch == "-").strip("-")
    if not base:
        return []
    return [base + sfx for sfx in BUCKET_SUFFIXES]


def _text(body):
    if isinstance(body, bytes):
        return body.decode("utf-8", "replace")
    return str(body or "")


def _fetcher(fetch):
    if fetch is not None:
        return fetch
    return default_fetch


def _get(fetch, url, timeout=FETCH_TIMEOUT):
    """One anonymous GET; returns (status, body_text) or None on error.

    Honors a ``timeout`` kwarg when the fetch accepts one; default_fetch
    uses its own constant otherwise. Never raises.
    """
    try:
        try:
            st, _h, body = fetch("GET", url, timeout=timeout)
        except TypeError:
            st, _h, body = fetch("GET", url)
        return int(st or 0), _text(body)
    except Exception:
        return None


# ------------------------------------------------------------- buckets

def _bucket_urls(name, regions, s3_base=None, gcs_base=None, azure_base=None):
    urls = []
    if s3_base:
        urls.append(s3_base.rstrip("/") + "/" + name)
    else:
        urls.append("https://%s.s3.amazonaws.com/" % name)
        for reg in regions or ():
            urls.append("https://%s.s3.%s.amazonaws.com/" % (name, reg))
    if gcs_base:
        urls.append(gcs_base.rstrip("/") + "/" + name)
    else:
        urls.append("https://storage.googleapis.com/" + name)
    if azure_base:
        urls.append(azure_base.rstrip("/") + "/" + name + "/")
    else:
        urls.append("https://%s.blob.core.windows.net/" % name)
    return urls


def probe_buckets(org, fetch=None, budget=20, regions=DEFAULT_REGIONS,
                  s3_base=None, gcs_base=None, azure_base=None):
    """Anonymous bucket probes. Returns findings:
    CRITICAL confirmed (public listing) / INFO (private but exists)."""
    fetch = _fetcher(fetch)
    findings = []
    sent = 0
    for name in bucket_names(org):
        if sent >= max(1, budget):
            break
        for url in _bucket_urls(name, regions, s3_base, gcs_base, azure_base):
            if sent >= max(1, budget):
                break
            sent += 1
            res = _get(fetch, url)
            if res is None:
                continue  # network failure: silent
            status, body = res
            if status == 200 and "ListBucketResult" in body:
                findings.append(Finding(
                    "Public cloud storage bucket with listable contents",
                    "critical", "confirmed",
                    "anonymous GET returned ListBucketResult XML: %s" % url,
                    "curl -sS -i '%s'  # anonymous listing" % url,
                    url, body[:200], "omega-cloudsec/public_bucket",
                    confidence="confirmed"))
                break  # one confirmed listing per bucket name is enough
            if status in (401, 403) or "AccessDenied" in body:
                findings.append(Finding(
                    "Cloud storage bucket exists but denies anonymous access",
                    "info", "candidate",
                    "bucket exists (AccessDenied on anonymous GET): %s" % url,
                    "curl -sS -i '%s'" % url,
                    url, "AccessDenied / HTTP %s" % status,
                    "omega-cloudsec/private_bucket", confidence="candidate"))
                break
            # 404 NoSuchBucket and anything else: silent skip
    return findings


# ------------------------------------------------- exposed cloud paths

def _matches_fp(path, body):
    fp = FINGERPRINTS.get(path)
    if not fp:
        return False
    low = body.lower()
    if not all(m in low for m in fp[:2]):
        return False
    third = fp[2] if len(fp) > 2 else None
    if isinstance(third, tuple):
        return any(m in low for m in third)
    return True


def probe_cloud_paths(target, fetch=None, allowlist=None, budget=10):
    """Probe CLOUD_PATHS on the target; HIGH confirmed when the body
    matches the path's fingerprint."""
    fetch = _fetcher(fetch)
    base = target if "://" in target else "http://" + target
    base = base.rstrip("/")
    if not allowlist_ok(base, allowlist):
        return []
    findings = []
    for path in CLOUD_PATHS[:max(1, budget)]:
        url = base + path
        res = _get(fetch, url)
        if res is None or res[0] != 200:
            continue
        body = res[1]
        if _matches_fp(path, body):
            findings.append(Finding(
                "Cloud workload file exposed on web root: %s" % path,
                "high", "confirmed",
                "GET %s returned fingerprint-matching content" % url,
                "curl -sS -i '%s'" % url,
                url, body[:200], "omega-cloudsec/cloud_path",
                confidence="confirmed"))
    return findings


# ----------------------------------------------------- IMDSv1 via SSRF

def probe_imds_ssrf(target, ssrf_params, fetch=None, allowlist=None,
                    budget=10):
    """Inject the AWS metadata URL into known SSRF-prone parameters.
    Response containing 'ami-id' -> CRITICAL confirmed."""
    if not ssrf_params:
        return []
    fetch = _fetcher(fetch)
    base = target if "://" in target else "http://" + target
    base = base.rstrip("/")
    if not allowlist_ok(base, allowlist):
        return []
    findings = []
    for param in list(ssrf_params)[:max(1, budget)]:
        sep = "&" if "?" in base else "?"
        probe_url = "%s%s%s=%s" % (
            base, sep, urllib.parse.quote(str(param)),
            urllib.parse.quote(IMDS_METADATA_URL, safe=""))
        res = _get(fetch, probe_url)
        if res is None or res[0] != 200:
            continue
        body = res[1]
        if "ami-id" in body:
            findings.append(Finding(
                "IMDSv1 metadata reachable via SSRF (instance role "
                "credentials exposed)",
                "critical", "confirmed",
                "SSRF via param %r returned instance metadata "
                "(ami-id present)" % param,
                "curl -sS -i '%s'  # metadata via SSRF" % probe_url,
                probe_url, body[:200], "omega-cloudsec/imds_ssrf",
                confidence="confirmed"))
            break
    return findings


# --------------------------------------------------------------- entry

def run_cloudsec(target, fetch=None, budget=20, log=None, allowlist=None,
                 org=None, ssrf_params=None, s3_base=None, gcs_base=None,
                 azure_base=None):
    """Entry point. Returns {findings, ran, skipped}. Never raises."""
    log = log or (lambda msg: None)
    ran, skipped = [], []

    def _step(name, fn, *a, **kw):
        try:
            res = fn(*a, **kw) or []
            ran.append(name)
            findings.extend(res)
        except Exception as exc:  # contained
            skipped.append({"tool": name, "reason":
                            "%s: %s" % (type(exc).__name__, exc)})
            log("[cloudsec] %s failed: %s" % (name, exc))

    findings = []
    _step("buckets", probe_buckets, org, fetch, max(1, budget),
          DEFAULT_REGIONS, s3_base, gcs_base, azure_base)
    _step("cloud_paths", probe_cloud_paths, target, fetch, allowlist,
          max(1, min(3, budget)))
    _step("imds_ssrf", probe_imds_ssrf, target, ssrf_params, fetch,
          allowlist, max(1, min(5, budget)))
    return {"findings": findings, "ran": ran, "skipped": skipped}
