# PHP Oneshot Checker

A single Python file for **configuration and source review** of PHP deployments. It reports the upstream release status of CVE-2026-109618 and CVE-2026-109619, plus prerequisites for three separate paths: handler mismatch (including PHP's CVE-2026-115560 notice), upload progress with an application include, and unsafe deserialization relevant to `var_destroy` research. It does not send exploit payloads or claim to prove RCE.

Requires Python **3.10+**. No Python packages are needed.

The repository uses only the Python standard library. To run its deterministic checks:

```bash
python3 -m unittest discover -s tests -v
```

## Run it

From this repository:

```bash
python3 oneshot-checker.py --local
```

That finds `php` in `PATH` and reads its **CLI** configuration. For a specific installation and its application source:

```bash
python3 oneshot-checker.py --local --php /absolute/path/to/php --web-root /absolute/path/to/application
```

To sample the PHP that serves a site, supply its loopback URL and **actual document root**:

```bash
python3 oneshot-checker.py --local --site http://127.0.0.1:8080/index.php /absolute/document/root
```

`--site` creates one random, token-guarded PHP diagnostic in the document root, requests it once, and removes it. Run as an account able to create and delete files there. If the process is forcibly killed, remove any `oneshot-audit-*.php` file left in the root. Add another `--site URL DOCUMENT_ROOT` to compare two PHP contexts sharing sessions.

From Windows PowerShell, use `py -3 .\oneshot-checker.py`; for example:

```powershell
py -3 .\oneshot-checker.py --local --php 'C:\xampp\php\php.exe' --web-root 'C:\xampp\htdocs'
```

For a URL without local access:

```bash
python3 oneshot-checker.py --remote https://site.example/index.php
```

Remote mode requests one URL. Add `--discover` to request five additional same-origin diagnostic paths; redirects can add HTTP exchanges. A hidden PHP version produces `UNKNOWN_VERSION`; HTTP alone cannot establish any of the three application paths.
Version strings in HTTP headers or public pages can be stale or describe a different PHP pool; use `--site` for a sampled serving runtime when local access is available.

## Every flag

| Flag | What it does |
| --- | --- |
| `--local` | Select local PHP and application review. Use with `--php`, `--site`, or both. |
| `--remote URL` | Select GET-only review of one HTTP(S) origin. |
| `--php PATH` | Read version and effective CLI settings from this executable. Repeat for several binaries. If omitted, use `php` in `PATH`. |
| `--ini PATH` | Ask each CLI binary to load this `php.ini` with `-c`. This does not prove the web server uses it. |
| `--site URL DOCUMENT_ROOT` | Sample the actual serving PHP at a loopback URL through a temporary diagnostic; repeat for multiple sites. Also scans that document root's PHP source. |
| `--web-root PATH` | Scan another application source directory. Repeat for multiple roots. Matches are lexical leads. |
| `--max-files N` | Limit source scanning per root; default 2,000. A truncated scan is reported. |
| `--discover` | With `--remote`, request five common same-origin PHP diagnostic paths. No forms or payloads are sent. |
| `--timeout SECONDS` | Set the per-request timeout; default 5, range 0.1–30. |
| `--insecure` | Accept self-signed HTTPS certificates for a deliberately configured target. |
| `--json` | Print all observations, source locations, and explanations as JSON. |
| `--version` | Print the checker release version. |
| `-h`, `--help` | Show command help. |

## Read the result

`FIXED_UPSTREAM` means the observed PHP release includes the upstream fix for the **two 2026-10961x core CVEs**. `BELOW_UPSTREAM_FIX` means it predates that fix; a vendor may have backported it. `UNKNOWN_VERSION` and `OUTSIDE_SUPPORTED_MATRIX` require separate review. Upstream fixes are PHP **8.2.35, 8.3.36, 8.4.27 and 8.5.12**. The status of CVE-2026-115560 is assessed separately; the 21 October core fixes do not establish that it is fixed.

For CVE-2026-109618, the checker records the serving SAPI, `memory_limit`, `post_max_size`, and input/upload limits. It flags a finite memory limit and a larger post size as exposure indicators; a smaller post size does not establish safety. For CVE-2026-109619, it records upload progress and `fatal_error_backtraces` (a relevant producer on PHP 8.5). It does not assess early per-request INI diagnostics. Neither configuration check can prove that RCE is reachable or that other producer/consumer paths are absent.

`PUBLISHED_PREREQUISITES_OBSERVED` for **CVE-2026-115560** means the sampled configuration uses `php_binary` or `php_serialize`, upload progress is enabled, and a source file contains a literal switch to `php` before `session_start()`. PHP's notice describes this exact combination. The scanner cannot determine whether the code path runs or whether an exploitable class is available. `PARTIAL_EVIDENCE_REVIEW` means some, but not all, of these facts were seen. A separate `Shared session store with different serializers` line concerns two web contexts and is **not** an exact match to PHP's new notice.

`CLI_PROFILE_MATCH_REVIEW` means those same configuration and source patterns were seen using a CLI binary; confirm the site's serving PHP with `--site` before treating them as a web finding.

`SOURCE_NOT_SCANNED` means no application source was supplied for that runtime. `INCOMPLETE_SOURCE_SCAN` means the file limit was reached or some files could not be read. Neither status clears an application path. When source was scanned, `PUBLISHED_PATTERN_NOT_OBSERVED` only means this checker's literal pattern was absent from the scanned files.

`SOURCE_AND_STORAGE_LEADS_REVIEW` for the upload progress/include path means file-backed sessions, upload progress, and a PHP include statement were observed; it does not prove attacker control of that include. `SOURCE_LEADS_REVIEW` for `var_destroy` means `unserialize()` and a magic method appeared in scanned source; it does not prove an unsafe data flow or usable gadget. Missing source matches never prove safety, especially if the scan was truncated or the code builds calls dynamically.

Exit code **0** means the inventory completed, regardless of its findings. Exit code **1** means it could not complete. Use the printed finding or `--json`, not the exit code, for triage.

Example summary lines:

```text
[+] WEB http://127.0.0.1:8080/index.php: PHP 8.5.12 (cli-server)
    CVE-2026-109618: FIXED_UPSTREAM
    CVE-2026-109619: FIXED_UPSTREAM
    handler_mismatch_CVE-2026-115560: PUBLISHED_PATTERN_NOT_OBSERVED
```

The shown version is an example. The three path findings are assessed independently of the two upstream core fixes.

## Sources and limits

- [PHP advisory for CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP advisory for CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP's 23 October notice for CVE-2026-115560](https://www.php.net/archive/2026.php#2026-10-23-1)

The local source scan uses bounded text patterns; wrappers, dynamic settings, paths outside supplied roots, and conditional branches need manual review. It reports unreadable files and scan limits so missing matches are not mistaken for complete coverage. The web probe samples one request and may miss settings specific to another route or pool. The remote check is a version inventory only. No exploit proof is included in this repository.

## License

MIT; see [LICENSE](LICENSE).
