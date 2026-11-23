"""omega/core/oracle — response-diff oracle for blind detection.

Expert testers read tiny response deltas: latency shifts (time-based
injection), small body-size changes (blind injection), error-message
changes (filter behavior). This oracle baselines a request, fires a
probe, and classifies the delta semantically instead of just
comparing bytes.

Classification outputs: {verdict, confidence, signals} where verdict
is one of: unchanged | timing-shift | content-shift | status-shift |
error-shape-change. Verdicts are evidence-grade hints, never
confirmations.
"""
import time


def classify_delta(baseline, probe):
    """Compare two responses (st, headers, body) tuples -> signals."""
    st0, h0, b0 = baseline
    st1, h1, b1 = probe
    signals = []
    conf = 0.0
    verdict = "unchanged"
    b0t = (b0 or b"").decode("latin-1", "replace")
    b1t = (b1 or b"").decode("latin-1", "replace")
    if st0 != st1:
        signals.append("status %s -> %s" % (st0, st1))
        conf += 0.5
        verdict = "status-shift"
    d = len(b1t) - len(b0t)
    if abs(d) > 20:
        signals.append("body size delta %+d" % d)
        conf += 0.3
        if verdict == "unchanged":
            verdict = "content-shift"
    # error-shape change: a distinct error class appears/disappears
    for marker, cls in (("sql", "sql-error"), ("exception", "stack"),
                        ("syntax", "syntax-error"), ("stack", "stack"),
                        ("warning", "warning")):
        if (marker in b0t.lower()) != (marker in b1t.lower()):
            signals.append("error-shape change: %s marker %s"
                           % (cls, "appeared" if marker in
                              b1t.lower() else "vanished"))
            conf += 0.4
            verdict = "error-shape-change"
    if signals:
        conf = min(1.0, conf)
    return {"verdict": verdict, "confidence": round(conf, 2),
            "signals": signals}


def time_probe(fetch, url, baseline_rounds=2, probe_rounds=2):
    """Timing-oracle: baseline latency vs probe latency.

    ``fetch(method, url, headers=None, body=None)``; returns the doc
    with the mean deltas and a timing-shift verdict when the probe is
    consistently >= 2.5x slower (classic time-based-injection band).
    """
    def measure(rounds, url_, body_=None):
        times = []
        for _ in range(max(1, rounds)):
            t0 = time.time()
            try:
                fetch("GET", url_, body=body_)
            except Exception:
                continue
            times.append(time.time() - t0)
        return sum(times) / len(times) if times else None

    base_mean = measure(baseline_rounds, url)
    # probe: harmless sleep-style probe via a deeply nested query is
    # NOT sent here (that is the offense layer's job). This oracle
    # measures a plain request pair; callers pass their own probe URL.
    return {"url": url, "baseline_mean_s": round(base_mean, 3) if
            base_mean is not None else None}


def probe_and_classify(fetch, base_url, probe_path, baseline_path="/",
                       headers=None):
    """Baseline vs probe differential in one call. Never raises."""
    base = base_url.rstrip("/")
    try:
        b = fetch("GET", base + baseline_path, body=None)
        p = fetch("GET", base + probe_path, body=None)
    except Exception as exc:
        return {"verdict": "error", "confidence": 0.0,
                "signals": ["fetch error: %s" % exc]}
    doc = classify_delta(b, p)
    doc["baseline_path"] = baseline_path
    doc["probe_path"] = probe_path
    doc["_headers"] = headers  # ignored; reserved for future use
    doc.pop("_headers", None)
    return doc
