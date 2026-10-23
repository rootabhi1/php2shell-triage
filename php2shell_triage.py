#!/usr/bin/env python3
"""
php2shell_triage.py

Passive, non-intrusive triage scanner for PHP2Shell (CVE-2026-109618 / CVE-2026-109619).

WHAT THIS DOES
--------------
For each URL in an input list, this script makes ordinary GET requests (homepage,
and a handful of common informational/debug paths) and inspects *response headers
and body content only*. It never sends a session.upload_progress payload, never
attempts to trigger the use-after-free, and never attempts code execution.

It produces a confidence-scored verdict so you can prioritize which hosts need a
real, one-at-a-time, isolated/staging verification (patch-status check, controlled
PoC in a lab clone, etc.) versus which are already clearly patched or clearly need
more manual digging.

WHAT THIS DOES NOT DO
----------------------
- Does NOT send any exploit payload or attempt to trigger the UAF condition.
- Does NOT attempt remote code execution.
- Is NOT a substitute for an authenticated/authorized deep scan or for actually
  patching. A "low confidence" or "unknown" verdict does NOT mean safe.

USE ONLY AGAINST SYSTEMS YOU ARE AUTHORIZED TO TEST.

Usage
-----
    python3 php2shell_triage.py -i urls.txt -o results.csv
    python3 php2shell_triage.py -i urls.txt -o results.csv --timeout 8 --workers 10

Input file: one URL per line (scheme required, e.g. https://example.com).
Output: CSV with url, verdict, confidence_score, signals, notes.
"""

import argparse
import csv
import re
import sys
import concurrent.futures
from dataclasses import dataclass, field
from datetime import datetime

try:
    import requests
except ImportError:
    sys.exit("This script requires the 'requests' library. Install with: pip install requests")

# ---------------------------------------------------------------------------
# Patched versions per branch (PHP project emergency release, 2026-10-21)
# ---------------------------------------------------------------------------
PATCHED_VERSIONS = {
    8: {5: 12, 4: 27, 3: 36, 2: 35},
}

# Common paths that sometimes leak version info or config state.
# All are ordinary, unauthenticated GET requests - nothing exploit-related.
PROBE_PATHS = [
    "",                     # homepage
    "/phpinfo.php",
    "/info.php",
    "/composer.json",
    "/composer.lock",
    "/wp-login.php",        # WordPress fingerprint
    "/CHANGELOG.txt",       # Drupal fingerprint
    "/administrator/",      # Joomla fingerprint
]

VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
CMS_SIGNATURES = {
    "WordPress": re.compile(r"wp-content|wp-includes|X-Powered-By:\s*WordPress", re.IGNORECASE),
    "Drupal": re.compile(r"Drupal|X-Generator:\s*Drupal", re.IGNORECASE),
    "Joomla": re.compile(r"Joomla", re.IGNORECASE),
}


@dataclass
class HostResult:
    url: str
    php_version: str = ""
    version_source: str = ""
    cms_detected: str = ""
    upload_progress_feature_hint: bool = False
    patched: bool = None  # True/False/None=unknown
    signals: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    confidence_score: int = 0
    verdict: str = ""


def parse_version(version_str: str):
    """Return (major, minor, patch) tuple or None."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def is_patched(version_tuple):
    """Return True if version_tuple is >= the patched release for its branch."""
    if not version_tuple:
        return None
    major, minor, patch = version_tuple
    branch = PATCHED_VERSIONS.get(major, {})
    fixed_patch = branch.get(minor)
    if fixed_patch is None:
        # Branch not in our known-affected map at all (e.g. PHP 7.x very old,
        # or a future branch not yet catalogued) -> unknown, needs manual check.
        return None
    return patch >= fixed_patch


def extract_version_from_headers(headers: dict):
    for h in ("Server", "X-Powered-By"):
        val = headers.get(h, "")
        m = VERSION_RE.search(val)
        if m:
            return f"{m.group(1)}.{m.group(2)}.{m.group(3)}", h
    return None, None


def scan_host(url: str, timeout: int, session: requests.Session) -> HostResult:
    result = HostResult(url=url)
    base = url.rstrip("/")

    combined_text_sample = ""
    found_version = None
    found_version_source = None
    cms_hits = set()

    for path in PROBE_PATHS:
        target = base + path
        try:
            resp = session.get(
                target,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "php2shell-passive-triage/1.0"},
            )
        except requests.RequestException as e:
            result.errors.append(f"{path or '/'}: {e.__class__.__name__}")
            continue

        # Header-based version detection (highest confidence signal)
        if not found_version:
            v, src = extract_version_from_headers(resp.headers)
            if v:
                found_version = v
                found_version_source = f"header:{src} @ {path or '/'}"

        # Light body sampling for CMS fingerprints and stray version strings
        # (only look at a capped amount of text to keep this cheap and safe)
        body_sample = resp.text[:20000] if resp.text else ""
        combined_text_sample += body_sample

        for cms, pattern in CMS_SIGNATURES.items():
            if pattern.search(body_sample) or pattern.search(str(resp.headers)):
                cms_hits.add(cms)

        # composer.lock / composer.json accidentally exposed can reveal
        # a 'php' platform requirement - informational only, not authoritative.
        if path in ("/composer.json", "/composer.lock") and resp.status_code == 200:
            m = re.search(r'"php"\s*:\s*"([^"]+)"', body_sample)
            if m and not found_version:
                result.signals.append(f"composer platform requirement hint: {m.group(1)}")

    if found_version:
        result.php_version = found_version
        result.version_source = found_version_source
        result.signals.append(f"PHP version disclosed via {found_version_source}: {found_version}")

    if cms_hits:
        result.cms_detected = ", ".join(sorted(cms_hits))
        result.signals.append(f"CMS fingerprint: {result.cms_detected}")

    # Heuristic: upload_progress is a default-on PHP feature historically, so its
    # mere plausibility (any multipart file-upload form present) is a very weak
    # signal only used to nudge confidence, never to assert vulnerability.
    if re.search(r'enctype=["\']multipart/form-data["\']', combined_text_sample, re.IGNORECASE):
        result.upload_progress_feature_hint = True
        result.signals.append("multipart file-upload form present (weak signal)")

    # ---- Score & verdict -----------------------------------------------
    score = 0
    version_tuple = parse_version(found_version) if found_version else None
    patched = is_patched(version_tuple) if version_tuple else None
    result.patched = patched

    if version_tuple:
        if patched is True:
            score = 90
            result.verdict = "PATCHED VERSION DISCLOSED - runtime/vendor build unverified"
        elif patched is False:
            score = 90
            result.verdict = "POTENTIALLY AFFECTED - disclosed version in affected range"
        else:
            score = 40
            result.verdict = "INCONCLUSIVE - disclosed version branch needs manual/vendor verification"
    else:
        if cms_hits:
            score = 55
            result.verdict = "MEDIUM CONFIDENCE - CMS fingerprint matched known-targeted stack, version unknown"
        elif result.upload_progress_feature_hint:
            score = 30
            result.verdict = "LOW CONFIDENCE - upload feature present, no version signal"
        else:
            score = 10
            result.verdict = "UNKNOWN - no reliable signal, manual check required"

    if result.errors and not found_version:
        score = max(score - 10, 0)
        result.signals.append(f"connectivity issues on some probes: {len(result.errors)}")

    result.confidence_score = score
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Passive triage scanner for PHP2Shell (CVE-2026-109618/109619) exposure. "
                     "No exploit payloads are sent. Use only on authorized targets."
    )
    parser.add_argument("-i", "--input", required=True, help="File with one URL per line")
    parser.add_argument("-o", "--output", required=True, help="Output CSV path")
    parser.add_argument("--timeout", type=int, default=8, help="Per-request timeout in seconds (default 8)")
    parser.add_argument("--workers", type=int, default=8, help="Concurrent workers (default 8)")
    args = parser.parse_args()

    with open(args.input) as f:
        urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not urls:
        sys.exit("No URLs found in input file.")

    print(f"[{datetime.now().isoformat(timespec='seconds')}] Scanning {len(urls)} URL(s) "
          f"with {args.workers} workers, {args.timeout}s timeout each...")
    print("NOTE: passive checks only - no exploit payloads sent.\n")

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Avoid sharing mutable requests.Session state between worker threads.
        future_map = {executor.submit(scan_host, url, args.timeout, requests.Session()): url for url in urls}
        for i, future in enumerate(concurrent.futures.as_completed(future_map), 1):
            url = future_map[future]
            try:
                res = future.result()
            except Exception as e:
                res = HostResult(url=url, verdict="ERROR", errors=[str(e)])
            results.append(res)
            print(f"[{i}/{len(urls)}] {url} -> {res.verdict} (score {res.confidence_score})")

    results.sort(key=lambda r: (0 if "POTENTIALLY AFFECTED" in r.verdict else 1, -r.confidence_score, r.url.lower()))

    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "url", "verdict", "confidence_score", "php_version",
            "version_source", "cms_detected", "signals", "errors"
        ])
        for r in results:
            writer.writerow([
                r.url, r.verdict, r.confidence_score, r.php_version,
                r.version_source, r.cms_detected,
                " | ".join(r.signals), " | ".join(r.errors),
            ])

    print(f"\nDone. Results written to {args.output}")
    vulnerable = [r for r in results if "POTENTIALLY AFFECTED" in r.verdict]
    if vulnerable:
        print(f"\n{len(vulnerable)} host(s) have a disclosed version below the known fix threshold - "
              f"verify package status and prioritize patching:")
        for r in vulnerable:
            print(f"  - {r.url} (PHP {r.php_version})")


if __name__ == "__main__":
    main()
