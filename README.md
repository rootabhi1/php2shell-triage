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

This is deliberately a passive, low-coverage inventory aid. It does not detect the vulnerable code path, test exploitability, or establish that a particular PHP deployment is affected.

- `Server` / `X-Powered-By` headers for an explicit PHP version string
- Whether that version falls in the affected range (PHP 8.2 < 8.2.35, 8.3 < 8.3.36, 8.4 < 8.4.27, or 8.5 < 8.5.12 (older/EOL branches require vendor-specific review))
- Exposed `composer.json` / `composer.lock` for a platform PHP requirement hint
- CMS fingerprints for WordPress / Drupal / Joomla (the stacks publicly demonstrated as
  exploitable via this chain)
- Presence of multipart file-upload forms (very weak signal — `upload_progress` is a
  long-standing PHP default, so this only nudges confidence, never asserts vulnerability)

## Verdict buckets

| Verdict | Meaning |
|---|---|
| POTENTIALLY AFFECTED | Disclosed PHP version is below the known fix for its supported branch; this is not proof the runtime is exploitable. |
| PATCHED VERSION DISCLOSED | Disclosed version meets the upstream fixed threshold; runtime and vendor build remain unverified. |
| INCONCLUSIVE | Version branch, vendor build, or evidence is insufficient; manual/vendor verification is required. |
| MEDIUM / LOW CONFIDENCE | Heuristic CMS or upload-form clues only; not proof of vulnerability. |
| UNKNOWN | No reliable signal found — **does not mean safe**; manual check required. |

A passive HTTP check cannot prove exploitability or verify the PHP runtime behind a proxy.
Even "PATCHED VERSION DISCLOSED" only describes the version string observed. Treat all
results as triage evidence and verify the actual package/build through authenticated host
access or the vendor.

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

Output is a CSV with the observed PHP version, verdict, score, evidence level/details, signals, and errors. The score is a heuristic prioritization value, not a calibrated probability of exploitability.

## Evidence-based verdicts

By default, the scanner still performs passive HTTP checks. It cannot safely prove remote code execution or test the vulnerable memory-corruption path. For stronger conclusions, pass an optional JSON file with runtime/package evidence obtained independently through authenticated host access or a trusted vendor inventory. The scanner does not collect or authenticate that evidence itself.

Example `evidence.json`:

```json
{
  "https://example.com/": {
    "runtime_version": "8.3.35",
    "runtime_verified": true,
    "package_verified": true,
    "evidence_source": "authenticated package inventory collected by the operator",
    "package_version": "php8.3-fpm vendor-build-123",
    "vendor_fix_confirmed": false,
    "notes": "Keep the supporting inventory record in your audit system."
  }
}
```

Run with:

```bash
python3 php2shell_triage.py -i urls.txt -o results.csv --evidence evidence.json
```

Supported evidence fields:
- `runtime_version`: exact PHP runtime version observed by the operator.
- `runtime_verified`: set to `true` only when verified through authenticated runtime/package inventory.
- `package_verified`: marks package/build provenance as independently verified; it does not alone prove the fix status.
- `vendor_fix_confirmed`: set to `true` only when an authoritative vendor advisory or package record confirms the fix and the package/runtime is verified.
- `evidence_source` and `package_version`: audit context displayed in the CSV.

Only explicitly verified evidence overrides a passive banner-based assessment. Evidence values are operator-supplied, not remotely validated by this program; preserve the supporting records. The tool never sends an exploit payload and does not claim proof of exploitability.

## Recommended workflow

1. **Run this script** across your full URL list to get a ranked, scored CSV.
2. **Anything "POTENTIALLY AFFECTED"** → verify the deployed package/build and prioritize
   updating to the applicable fixed release (PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).
3. **Anything other than a verified fix verdict** → spot-check manually:
   - SSH in and run `php -v` directly if you have access.
   - Check the effective PHP package/build and vendor advisory. Vendors may backport
     fixes without changing the upstream-looking version string.
   - Do not treat `session.upload_progress.enabled=Off` as a complete mitigation.
     Updating to a fixed release is the recommended remediation; configuration changes
     are not a substitute for patching. Do not use this passive tool to confirm exploitability.
4. **Log sweep for prior exploitation** (this CVE is under active exploitation):
   search existing access/error logs for:
   - `PHP_SESSION_UPLOAD_PROGRESS` in POST bodies
   - Session IDs arriving via POST body instead of cookie
   - Unexplained PHP-FPM worker crashes/restarts before your patch date
5. **Patch, then re-run this script** as a limited external cross-check. Verify the
   actual installed package/build through authenticated server-side checks, especially
   where headers are hidden or vendor backports may apply.

## Limitations

- Version headers are frequently suppressed or rewritten by proxies. No signal does not
  mean not vulnerable. Redirects are not followed, to avoid silently probing another host.
- Upstream version thresholds are evidence only; vendor builds may backport fixes without
  changing the displayed version. Verify package provenance with the vendor.
- CMS fingerprinting is heuristic and can both false-positive and false-negative.
- This tool makes no attempt to check `session.upload_progress.enabled` remotely —
  that requires server-side access (SSH/config review), not something observable
  over HTTP without touching the vulnerable condition itself.
- Not a replacement for an authenticated scan, WAF/IDS rule deployment, or an actual
  patch cycle.

## References

- [PHP security advisory and fixed release announcements](https://www.php.net/?p=6507) (CVE-2026-109618 / CVE-2026-109619); verify current fixed versions and vendor advisories before operational use
- Wiz research on unauthenticated RCE against WordPress/Drupal/Joomla via this chain
- Recorded Future / Abstract Security writeups on detection signatures (Suricata, ModSecurity)
