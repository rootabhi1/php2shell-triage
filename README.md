# php2shell-triage

Passive, non-intrusive triage scanner for **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619) —
a heap use-after-free in PHP's `session.upload_progress` handling, CVSS 9.2, patched by the
PHP project on 2026-10-21.

> **Scope:** This tool only sends ordinary GET requests and inspects headers/body for
> version and framework fingerprints. It **never** sends a `session.upload_progress`
> payload and **never** attempts to trigger the vulnerability or execute code.
> It is a triage/prioritization aid, not a vulnerability confirmation tool.
>
> **Use only against systems you own or are explicitly authorized to test.**

## Why passive-only

Reliably *confirming* this specific CVE requires approaching the actual use-after-free
condition, which can crash the PHP-FPM worker even on a "successful" check. That's not
something to run unattended across a batch of URLs. This script instead narrows a large
list down to a short list worth checking one at a time, by hand, in a controlled way.

## What it checks

- `Server` / `X-Powered-By` headers for an explicit PHP version string
- Whether that version falls in the affected range (PHP < 8.3.36 / < 8.4.27 / < 8.5.12)
- Exposed `composer.json` / `composer.lock` for a platform PHP requirement hint
- CMS fingerprints for WordPress / Drupal / Joomla (the stacks publicly demonstrated as
  exploitable via this chain)
- Presence of multipart file-upload forms (very weak signal — `upload_progress` is a
  long-standing PHP default, so this only nudges confidence, never asserts vulnerability)

## Verdict buckets

| Verdict | Meaning |
|---|---|
| HIGH CONFIDENCE - VULNERABLE | Disclosed PHP version falls in the affected range |
| HIGH CONFIDENCE - PATCHED | Disclosed PHP version is at or above the patched release |
| MEDIUM CONFIDENCE | CMS fingerprint matches a known-targeted stack, version unknown |
| LOW CONFIDENCE | Weak or partial signal only |
| UNKNOWN | No reliable signal found — **does not mean safe**, needs manual check |

A "LOW CONFIDENCE" or "UNKNOWN" result is not a clean bill of health — most production
servers correctly suppress version headers, so the *absence* of a signal is common and
uninformative. Treat anything that isn't "HIGH CONFIDENCE - PATCHED" as needing a manual
check.

## Install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# urls.txt: one URL per line, scheme required
python3 php2shell_triage.py -i urls.txt -o results.csv

# tune concurrency / timeout for a large batch
python3 php2shell_triage.py -i urls.txt -o results.csv --timeout 8 --workers 10
```

Output is a CSV: `url, verdict, confidence_score, php_version, version_source, cms_detected, signals, errors`.

## Recommended workflow

1. **Run this script** across your full URL list to get a ranked, scored CSV.
2. **Anything "HIGH CONFIDENCE - VULNERABLE"** → patch immediately
   (PHP 8.3.36 / 8.4.27 / 8.5.12), this is the priority list.
3. **Anything not "HIGH CONFIDENCE - PATCHED"** → spot-check manually:
   - SSH in and run `php -v` directly if you have access.
   - Check `session.upload_progress.enabled` in `php.ini` — setting it `Off` closes
     this specific vector even pre-patch.
   - Only if you need to *confirm* exploitability (not just version), do so **one host
     at a time, against a staging clone**, never production, and never in a batch loop.
4. **Log sweep for prior exploitation** (this CVE is under active exploitation):
   search existing access/error logs for:
   - `PHP_SESSION_UPLOAD_PROGRESS` in POST bodies
   - Session IDs arriving via POST body instead of cookie
   - Unexplained PHP-FPM worker crashes/restarts before your patch date
5. **Patch, then re-run this script** to confirm the fleet now reports patched versions
   where headers are disclosed, and re-verify config (`upload_progress.enabled=Off`)
   where they are not.

## Limitations

- Version headers are frequently suppressed in hardened production configs — this tool
  will under-report in exactly those environments. No signal ≠ not vulnerable.
- CMS fingerprinting is heuristic and can both false-positive and false-negative.
- This tool makes no attempt to check `session.upload_progress.enabled` remotely —
  that requires server-side access (SSH/config review), not something observable
  over HTTP without touching the vulnerable condition itself.
- Not a replacement for an authenticated scan, WAF/IDS rule deployment, or an actual
  patch cycle.

## References

- PHP project emergency release notes, 2026-10-21 (CVE-2026-109618 / CVE-2026-109619)
- Wiz research on unauthenticated RCE against WordPress/Drupal/Joomla via this chain
- Recorded Future / Abstract Security writeups on detection signatures (Suricata, ModSecurity)
