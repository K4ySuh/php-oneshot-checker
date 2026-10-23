#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only PHP exposure and application-prerequisite inventory.

The local web probe writes one guarded diagnostic to an explicitly supplied
document root, requests it once, and deletes it. No exploit payloads or
command-execution checks are sent to a web server.
"""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


__version__ = "0.1.0"
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
SETTINGS = (
    "memory_limit", "post_max_size", "max_file_uploads", "max_input_vars", "max_input_nesting_level",
    "session.upload_progress.enabled", "session.upload_progress.cleanup",
    "session.serialize_handler", "session.save_handler", "session.save_path",
    "session.auto_start", "fatal_error_backtraces",
)
DISCOVERY_PATHS = ("phpinfo.php", "info.php", "php_info.php", "php-version.php", "version.php")
SKIP_DIRS = {".git", "node_modules", "cache", "tmp", "logs", "tests", "test"}
VERSION = re.compile(r"\b(\d+)\.(\d+)\.(\d+)(?:[- ]?(dev|alpha\d*|beta\d*|RC\d+))?", re.I)
PHP_HEADER = re.compile(r"\bPHP/([0-9]+\.[0-9]+\.[0-9]+(?:[- ]?(?:dev|alpha\d*|beta\d*|RC\d+))?)", re.I)
RUNTIME_SWITCH = re.compile(
    r"\bini_set\s*\(\s*['\"]session\.serialize_handler['\"]\s*,\s*['\"]php['\"]\s*\)", re.I | re.S
)
SESSION_START = re.compile(r"\bsession_start\s*\(", re.I)
INCLUDE = re.compile(r"\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?\$", re.I)
DIRECT_INCLUDE = re.compile(
    r"\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\b", re.I
)
UNSERIALIZE = re.compile(r"\bunserialize\s*\(", re.I)
DIRECT_UNSERIALIZE = re.compile(r"\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b", re.I)
MAGIC_METHOD = re.compile(r"\bfunction\s+__(?:destruct|wakeup|unserialize)\s*\(", re.I)


def normalize_url(raw: str) -> str:
    """Accept only an HTTP(S) URL with a host; drop fragments."""
    url = urlsplit(raw)
    if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password:
        raise ValueError("URL must be http(s) with a host and no credentials")
    return urlunsplit((url.scheme, url.netloc, url.path or "/", url.query, ""))


def same_origin(a: str, b: str) -> bool:
    """Compare scheme, host and effective port before following a redirect."""
    left, right = urlsplit(a), urlsplit(b)
    def key(item):
        return (item.scheme.lower(), (item.hostname or "").lower(),
                item.port or (443 if item.scheme == "https" else 80))
    return key(left) == key(right)


class OriginRedirect(HTTPRedirectHandler):
    """Reject redirects that would leave the URL's original origin."""

    def __init__(self, base: str):
        super().__init__()
        self.base = base

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if target.username or target.password or not same_origin(self.base, newurl):
            raise ValueError("cross-origin redirect refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, timeout: float, insecure: bool = False) -> dict:
    """Fetch one bounded page; never send POST data or follow off-origin links."""
    base = normalize_url(url)
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    handlers = [OriginRedirect(base), HTTPSHandler(context=context)]
    if loopback(base):
        handlers.append(ProxyHandler({}))
    opener = build_opener(*handlers)
    request = Request(base, headers={"User-Agent": "PHP-Oneshot-Audit/1.0", "Accept": "text/html,application/json,*/*"})
    try:
        with opener.open(request, timeout=timeout) as response:
            return {"url": response.url, "status": response.status,
                    "headers": dict(response.headers.items()), "body": response.read(256 * 1024)}
    except HTTPError as error:
        try:
            return {"url": error.url, "status": error.code,
                    "headers": dict(error.headers.items()), "body": error.read(256 * 1024)}
        finally:
            error.close()
    except (URLError, OSError, ValueError) as error:
        return {"url": base, "status": None, "headers": {}, "body": b"", "error": str(error)}


def release_status(raw: str | None) -> str:
    """Classify an observed release against upstream fixes, not vendor backports."""
    match = VERSION.search(raw or "")
    if not match:
        return "UNKNOWN_VERSION"
    major, minor, patch = (int(match.group(i)) for i in (1, 2, 3))
    if match.group(4):
        return "PRERELEASE_REVIEW"
    if major != 8 or (major, minor) not in FIXED:
        return "OUTSIDE_SUPPORTED_MATRIX"
    return "FIXED_UPSTREAM" if patch >= FIXED[(major, minor)] else "BELOW_UPSTREAM_FIX"


def php_cli(binary: str, ini: str | None) -> dict:
    """Read effective CLI settings for the selected binary and optional ini."""
    resolved = shutil.which(binary) or (str(Path(binary).resolve()) if Path(binary).is_file() else None)
    if not resolved:
        raise ValueError(f"PHP executable not found: {binary}")
    command = [resolved]
    if ini:
        command += ["-c", str(Path(ini).resolve(strict=True))]
    command += ["-i"]
    result = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=15, check=False)
    if result.returncode:
        raise ValueError(f"PHP inventory failed for {resolved}: {result.stderr.strip()[-400:]}")
    parsed = {}
    for line in result.stdout.splitlines():
        if " => " not in line:
            continue
        parts = [part.strip() for part in line.split(" => ")]
        key = parts[0].lower()
        if key in SETTINGS and len(parts) > 1:
            parsed[key] = parts[1]
    version_match = re.search(r"^PHP Version =>\s*(\S+)", result.stdout, re.M)
    sapi_match = re.search(r"^Server API =>\s*(.+)$", result.stdout, re.M)
    return {"kind": "cli", "binary": resolved,
            "ini_override": str(Path(ini).resolve()) if ini else None,
            "version": version_match.group(1) if version_match else None,
            "sapi": sapi_match.group(1).strip() if sapi_match else "CLI",
            "settings": parsed}


def loopback(url: str) -> bool:
    """Require a literal loopback IP or localhost for the staged diagnostic."""
    host = urlsplit(url).hostname or ""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def web_probe(url: str, root: str, timeout: float, insecure: bool) -> dict:
    """Stage a token-guarded read-only PHP diagnostic and always remove it."""
    site = normalize_url(url)
    if not loopback(site):
        raise ValueError("--site URL must use localhost or a literal loopback address")
    document_root = Path(root).resolve(strict=True)
    if not document_root.is_dir():
        raise ValueError(f"not a directory: {document_root}")
    token = secrets.token_hex(16)
    filename = f"oneshot-audit-{token}.php"
    diagnostic = document_root / filename
    keys = json.dumps(list(SETTINGS))
    code = ("<?php\n"
            f"if (!hash_equals('{token}', $_GET['token'] ?? '')) {{ http_response_code(404); exit; }}\n"
            "header('Content-Type: application/json');\n"
            f"$keys = json_decode('{keys}', true);\n"
            "$settings = []; foreach ($keys as $key) { $settings[$key] = ini_get($key); }\n"
            f"echo json_encode(['token' => '{token}', 'version' => PHP_VERSION, "
            "'sapi' => PHP_SAPI, 'settings' => $settings]);\n")
    fd = os.open(diagnostic, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(code)
        os.chmod(diagnostic, 0o644)
        parts = urlsplit(site)
        directory = parts.path.rsplit("/", 1)[0]
        probe_url = urlunsplit((parts.scheme, parts.netloc, f"{directory}/{filename}", urlencode({"token": token}), ""))
        page = fetch(probe_url, timeout, insecure)
        if page["status"] != 200:
            raise ValueError(f"diagnostic returned HTTP {page['status']}: {page.get('error', 'check URL and document root')}")
        try:
            data = json.loads(page["body"])
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"diagnostic did not execute as PHP: {error}") from error
        if (not isinstance(data, dict) or data.get("token") != token or
                not isinstance(data.get("settings"), dict)):
            raise ValueError("diagnostic returned unexpected data")
        return {"kind": "web", "site": site, "document_root": str(document_root),
                "version": str(data.get("version") or ""), "sapi": str(data.get("sapi") or ""),
                "settings": {key: str(value) for key, value in data["settings"].items()}}
    finally:
        diagnostic.unlink(missing_ok=True)


def mask_php_comments(content: str) -> str:
    """Mask PHP comments while preserving string literals and line offsets."""
    out = list(content)
    state = "code"
    index = 0
    while index < len(content):
        char = content[index]
        next_char = content[index + 1] if index + 1 < len(content) else ""
        if state == "code":
            if char in {"'", '"', "`"}:
                state = char
            elif char == "/" and next_char in {"/", "*"}:
                state = "line" if next_char == "/" else "block"
                out[index] = out[index + 1] = " "
                index += 1
            elif char == "#" and next_char != "[":
                state = "line"
                out[index] = " "
        elif state in {"'", '"', "`"}:
            if char == "\\":
                index += 1
            elif char == state:
                state = "code"
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                out[index] = " "
        elif state == "block":
            if char == "*" and next_char == "/":
                out[index] = out[index + 1] = " "
                index += 1
                state = "code"
            elif char != "\n":
                out[index] = " "
        index += 1
    return "".join(out)


def source_scan(root: Path, max_files: int) -> dict:
    """Collect bounded lexical leads; this is not PHP data-flow analysis."""
    if not root.is_dir():
        raise ValueError(f"source root is not a directory: {root}")
    patterns = {"runtime_switch": RUNTIME_SWITCH, "session_start": SESSION_START,
                "include": INCLUDE, "direct_include": DIRECT_INCLUDE,
                "unserialize": UNSERIALIZE, "direct_unserialize": DIRECT_UNSERIALIZE,
                "magic_method": MAGIC_METHOD}
    hits = {name: [] for name in patterns}
    ordered_switch = []
    scanned = 0
    truncated = False
    errors = []

    def record_walk_error(error: OSError) -> None:
        errors.append(str(error))

    for directory, dirs, files in os.walk(root, onerror=record_walk_error):
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS and not name.startswith("."))
        for name in sorted(files):
            if not name.lower().endswith((".php", ".phtml", ".inc")):
                continue
            if scanned >= max_files:
                truncated = True
                break
            path = Path(directory) / name
            try:
                if path.is_symlink() or path.stat().st_size > 1024 * 1024:
                    continue
                content = mask_php_comments(path.read_text(encoding="utf-8", errors="replace"))
            except OSError as error:
                errors.append(f"{path}: {error}")
                continue
            scanned += 1
            relative = str(path.relative_to(root))
            found = {}
            for key, regex in patterns.items():
                matches = list(regex.finditer(content))
                found[key] = matches
                if matches and len(hits[key]) < 8:
                    line = content.count("\n", 0, matches[0].start()) + 1
                    hits[key].append(f"{relative}:{line}")
            if any(a.start() < b.start() for a in found["runtime_switch"] for b in found["session_start"]):
                ordered_switch.append(relative)
        if truncated:
            break
    return {"root": str(root), "files_scanned": scanned, "truncated": truncated,
            "read_errors": errors[:20], "read_error_count": len(errors),
            "hits": hits, "switch_before_session_start_same_file": ordered_switch[:8],
            "scope": "lexical leads only; comments, branches, wrappers and cross-file flow require review"}


def enabled(value: str | None) -> bool | None:
    """Normalize PHP's common on/off spellings without guessing on missing data."""
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "on", "yes", "true"}:
        return True
    if normalized in {"0", "off", "no", "false", ""}:
        return False
    return None


def size_bytes(value: str | None) -> int | None:
    """Convert PHP shorthand sizes; -1 indicates an unlimited PHP limit."""
    if value is None:
        return None
    match = re.fullmatch(r"\s*(-?\d+)\s*([KMG]?)\s*", value, re.I)
    if not match:
        return None
    number = int(match.group(1))
    return number * (1024 ** {"": 0, "K": 1, "M": 2, "G": 3}[match.group(2).upper()])


def findings(runtime: dict, scans: list[dict]) -> dict:
    """Keep observed facts separate from reachability and execution claims."""
    settings = runtime["settings"]
    version = release_status(runtime.get("version"))
    upload = enabled(settings.get("session.upload_progress.enabled"))
    serializer = settings.get("session.serialize_handler", "").strip().lower()
    save_handler = settings.get("session.save_handler", "").strip().lower()
    sapi = runtime.get("sapi", "").strip().lower()
    memory = size_bytes(settings.get("memory_limit"))
    post = size_bytes(settings.get("post_max_size"))
    source_coverage = ("NOT_SCANNED" if not scans else
                       "INCOMPLETE" if any(scan["truncated"] or scan["read_error_count"] for scan in scans)
                       else "SCANNED")
    merged = {name: any(scan["hits"][name] for scan in scans) for name in (
        "runtime_switch", "session_start", "include", "direct_include",
        "unserialize", "direct_unserialize", "magic_method")}
    ordered = any(scan["switch_before_session_start_same_file"] for scan in scans)
    if upload is False:
        handler = "PUBLISHED_PATH_DISABLED_BY_CONFIG"
    elif source_coverage == "NOT_SCANNED":
        handler = "SOURCE_NOT_SCANNED"
    elif serializer in {"php_binary", "php_serialize"} and upload is True and ordered:
        handler = ("PUBLISHED_PREREQUISITES_OBSERVED" if runtime["kind"] == "web"
                   else "CLI_PROFILE_MATCH_REVIEW")
    elif merged["runtime_switch"] or serializer in {"php_binary", "php_serialize"}:
        handler = "PARTIAL_EVIDENCE_REVIEW"
    else:
        handler = "INCOMPLETE_SOURCE_SCAN" if source_coverage == "INCOMPLETE" else "PUBLISHED_PATTERN_NOT_OBSERVED"
    if upload is False:
        include = "UPLOAD_PROGRESS_DISABLED"
    elif source_coverage == "NOT_SCANNED":
        include = "SOURCE_NOT_SCANNED"
    elif upload is True and save_handler == "files" and merged["include"]:
        include = "SOURCE_AND_STORAGE_LEADS_REVIEW"
    else:
        include = "INCOMPLETE_SOURCE_SCAN" if source_coverage == "INCOMPLETE" else "PREREQUISITES_NOT_ESTABLISHED"
    var_destroy = ("SOURCE_NOT_SCANNED" if source_coverage == "NOT_SCANNED" else
                   "SOURCE_LEADS_REVIEW" if merged["unserialize"] and merged["magic_method"] else
                   "INCOMPLETE_SOURCE_SCAN" if source_coverage == "INCOMPLETE" else
                   "APPLICATION_SINK_OR_GADGET_NOT_ESTABLISHED")
    return {
        "CVE-2026-109618": {"release": version,
            "sapi": runtime.get("sapi"),
            "startup_shutdown_exposure": ("MOD_PHP_SAPI_OBSERVED" if "apache" in sapi and "handler" in sapi
                                          else "OTHER_SAPI_REQUIRES_PATH_REVIEW"),
            "finite_memory_limit": memory is not None and memory >= 0,
            "post_max_size_exceeds_memory_limit": memory is not None and memory >= 0 and post is not None and post > memory,
            "max_file_uploads": settings.get("max_file_uploads"),
            "max_input_vars": settings.get("max_input_vars"),
            "max_input_nesting_level": settings.get("max_input_nesting_level"),
            "meaning": "version/configuration indicators only; no OOM or RCE proof"},
        "CVE-2026-109619": {"release": version,
            "upload_progress_enabled": upload,
            "fatal_error_backtraces_enabled": enabled(settings.get("fatal_error_backtraces")),
            "early_ini_diagnostic_path": "NOT_ASSESSED",
            "meaning": "upload progress is one published path; this does not cover all stale-state producers"},
        "handler_mismatch_CVE-2026-115560": {"status": handler,
            "source_coverage": source_coverage,
            "configured_serializer": serializer or None, "runtime_switch_to_php_found": merged["runtime_switch"],
            "switch_before_session_start_same_file": ordered,
            "meaning": "PHP's published pattern; source matches do not prove a reachable execution path"},
        "upload_progress_include": {"status": include,
            "source_coverage": source_coverage,
            "include_source_lead": merged["include"], "direct_input_include_lead": merged["direct_include"],
            "meaning": "an input-controlled include and readable session file require manual data-flow review"},
        "var_destroy": {"status": var_destroy,
            "source_coverage": source_coverage,
            "unserialize_source_lead": merged["unserialize"],
            "direct_input_unserialize_lead": merged["direct_unserialize"],
            "magic_method_lead": merged["magic_method"],
            "meaning": "source hints only; an unsafe input path and usable gadget are not proven"},
    }


def shared_store_mismatches(runtimes: list[dict]) -> list[dict]:
    """Flag separate web contexts that report one session store but different serializers."""
    web = [item for item in runtimes if item["kind"] == "web"]
    pairs = []
    for index, left in enumerate(web):
        for right in web[index + 1:]:
            a, b = left["settings"], right["settings"]
            path = a.get("session.save_path", "").strip()
            if (path and path == b.get("session.save_path", "").strip()
                    and a.get("session.save_handler", "").strip() == b.get("session.save_handler", "").strip()
                    and a.get("session.serialize_handler", "").strip() != b.get("session.serialize_handler", "").strip()):
                pairs.append({"sites": [left["site"], right["site"]], "shared_save_path": path,
                              "serializers": [a.get("session.serialize_handler"), b.get("session.serialize_handler")],
                              "scope": "cross-context mismatch lead; distinct from PHP's exact CVE-2026-115560 condition"})
    return pairs


def remote_inventory(url: str, timeout: float, insecure: bool, discover: bool) -> dict:
    """Use GET only and report a version only when the server discloses one."""
    target = normalize_url(url)
    pages = [fetch(target, timeout, insecure)]
    if discover:
        parts = urlsplit(target)
        for name in DISCOVERY_PATHS:
            candidate = urlunsplit((parts.scheme, parts.netloc, "/" + name, "", ""))
            if candidate != target:
                pages.append(fetch(candidate, timeout, insecure))
    if all(page["status"] is None for page in pages):
        raise ValueError(f"no HTTP response from {target}: {pages[0].get('error', 'request failed')}")
    evidence = []
    for page in pages:
        headers = {key.lower(): value for key, value in page["headers"].items()}
        for key in ("x-powered-by", "server"):
            match = PHP_HEADER.search(headers.get(key, ""))
            if match:
                evidence.append({"version": match.group(1), "source": f"{page['url']} {key}"})
        if page["status"] == 200:
            raw_body = page["body"].decode("utf-8", "replace")
            if re.search(r"<title>\s*phpinfo\(\)\s*</title>|<h1[^>]*>\s*PHP Version", raw_body, re.I):
                body = html.unescape(re.sub(r"<[^>]+>", " ", raw_body))
                match = re.search(r"\bPHP Version\s+(\d+\.\d+\.\d+)", body, re.I)
                if match:
                    evidence.append({"version": match.group(1), "source": f"{page['url']} phpinfo page"})
    observed = sorted({item["version"] for item in evidence})
    return {"mode": "remote", "target": target,
            "requests": [{"url": p["url"], "status": p["status"], "error": p.get("error")} for p in pages],
            "version_evidence": evidence,
            "core_release": release_status(observed[0]) if len(observed) == 1 else "CONFLICTING_VERSIONS" if observed else "UNKNOWN_VERSION",
            "application_paths": "UNKNOWN_FROM_HTTP_INVENTORY",
            "scope": "GET-only version evidence; no configuration, source reachability or exploitability proof"}


def local_inventory(args) -> dict:
    """Inventory CLI/web settings, bounded source leads, and each requested path."""
    runtimes = []
    binaries = args.php or ([shutil.which("php")] if not args.site and shutil.which("php") else [])
    for binary in binaries:
        runtimes.append(php_cli(binary, args.ini))
    for url, root in args.site:
        runtimes.append(web_probe(url, root, args.timeout, args.insecure))
    if not runtimes:
        raise ValueError("no PHP runtime found; pass --php PATH or --site URL DOCUMENT_ROOT")
    explicit_roots = {str(Path(value).resolve(strict=True)) for value in args.web_root}
    roots = set(explicit_roots)
    roots.update(str(Path(root).resolve(strict=True)) for _, root in args.site)
    scans = [source_scan(Path(root), args.max_files) for root in sorted(roots)]
    for runtime in runtimes:
        if runtime["kind"] == "web":
            document_root = runtime["document_root"]
            related = [scan for scan in scans if scan["root"] == document_root or
                       (scan["root"] in explicit_roots and
                        Path(document_root).is_relative_to(Path(scan["root"]))) ]
        else:
            related = [scan for scan in scans if scan["root"] in explicit_roots]
        runtime["findings"] = findings(runtime, related)
        runtime["source_roots_assessed"] = [scan["root"] for scan in related]
    return {"mode": "local", "runtimes": runtimes, "source_scans": scans,
            "shared_store_mismatch_leads": shared_store_mismatches(runtimes),
            "scope": "CLI and sampled web settings can differ; source matches are leads, not execution proof"}


def display(report: dict) -> None:
    """Print a short, stable summary for an operator."""
    if report["mode"] == "remote":
        print(f"[+] Remote: {report['target']}")
        print(f"[+] Core release: {report['core_release']}")
        print(f"[?] Application paths: {report['application_paths']}")
        print(f"[+] GET requests: {len(report['requests'])}")
        for item in report["version_evidence"][:5]:
            print(f"    PHP {item['version']} from {item['source']}")
        return
    for runtime in report["runtimes"]:
        label = runtime.get("site") or runtime.get("binary")
        print(f"[+] {runtime['kind'].upper()} {label}: PHP {runtime['version'] or 'unknown'} ({runtime['sapi']})")
        settings = runtime["settings"]
        print("    configuration: " + "; ".join(
            f"{name}={settings.get(name, 'unknown')}" for name in
            ("memory_limit", "post_max_size", "max_file_uploads", "max_input_vars",
             "max_input_nesting_level", "session.upload_progress.enabled",
             "fatal_error_backtraces", "session.serialize_handler",
             "session.save_handler", "session.save_path")))
        for cve in ("CVE-2026-109618", "CVE-2026-109619"):
            print(f"    {cve}: {runtime['findings'][cve]['release']}")
        for path in ("handler_mismatch_CVE-2026-115560", "upload_progress_include", "var_destroy"):
            print(f"    {path}: {runtime['findings'][path]['status']}")
    for item in report["source_scans"]:
        mark = " (limit reached)" if item["truncated"] else ""
        print(f"[+] Source: {item['root']}: {item['files_scanned']} files{mark}")
        if item["read_error_count"]:
            print(f"[?] Source read errors: {item['read_error_count']} (details in --json)")
        for name, places in item["hits"].items():
            if places:
                print(f"    {name}: {', '.join(places)}")
    for item in report["shared_store_mismatch_leads"]:
        print(f"[!] Shared session store with different serializers: {', '.join(item['sites'])}")
    print("[?] Findings are inventory and source leads; they do not prove or exclude RCE.")


def main(argv: list[str] | None = None) -> int:
    """Parse two explicit modes and return 0 on completed inventory, 1 on error."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"PHP Oneshot Checker {__version__}")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--local", action="store_true", help="inspect installed PHP and supplied local sites")
    mode.add_argument("--remote", metavar="URL", help="GET-only inventory of one HTTP(S) site")
    parser.add_argument("--php", action="append", default=[], metavar="PATH",
                        help="local PHP executable; repeat for multiple binaries (default: php in PATH)")
    parser.add_argument("--ini", metavar="PATH", help="load this php.ini for each --php CLI inventory")
    parser.add_argument("--site", nargs=2, action="append", default=[], metavar=("LOOPBACK_URL", "DOCUMENT_ROOT"),
                        help="sample the serving PHP with a temporary read-only diagnostic; repeat for sites")
    parser.add_argument("--web-root", action="append", default=[], metavar="PATH",
                        help="scan PHP source in this directory; repeat for applications")
    parser.add_argument("--max-files", type=int, default=2000, metavar="N",
                        help="maximum PHP source files per root (default: 2000)")
    parser.add_argument("--discover", action="store_true",
                        help="remote only: GET five common same-origin PHP diagnostic paths")
    parser.add_argument("--timeout", type=float, default=5.0, metavar="SECONDS",
                        help="per-request timeout, 0.1 to 30 seconds (default: 5)")
    parser.add_argument("--insecure", action="store_true", help="accept self-signed HTTPS certificates")
    parser.add_argument("--json", action="store_true", help="print structured JSON instead of the short summary")
    args = parser.parse_args(argv)
    if not 0.1 <= args.timeout <= 30:
        parser.error("--timeout must be between 0.1 and 30")
    if not 1 <= args.max_files <= 100000:
        parser.error("--max-files must be between 1 and 100000")
    if args.remote and (args.php or args.ini or args.site or args.web_root):
        parser.error("--php, --ini, --site and --web-root require --local")
    if args.local and args.discover:
        parser.error("--discover requires --remote")
    if args.local and args.ini and args.site and not args.php:
        parser.error("--ini needs --php when --site is also supplied; it cannot alter web settings")
    try:
        report = (local_inventory(args) if args.local else
                  remote_inventory(args.remote, args.timeout, args.insecure, args.discover))
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"[x] {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        display(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
