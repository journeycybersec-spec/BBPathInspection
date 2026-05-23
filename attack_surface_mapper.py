#!/usr/bin/env python3
"""
Attack Surface Mapper (v2)
==========================
Automated reconnaissance for ANY web app architecture (SPA or classic),
with optional integration of the bundled ./ffuf/ffuf and ./LinkFinder/linkfinder.py
tools and full per-tool execution logging in the HTML report.

USE ONLY ON SYSTEMS YOU OWN OR HAVE WRITTEN AUTHORIZATION TO TEST.
Unauthorized testing is a violation of the Computer Fraud and Abuse Act
(18 U.S.C. § 1030) and analogous statutes worldwide.

Workflow:
  1. Fetch the target homepage
  2. Auto-detect the SPA framework from HTML markers
  3. Discover JavaScript bundles referenced by <script src=...>
  4. Check each bundle for an accidentally-shipped .map file
  5. Extract endpoints from each bundle:
       - External: ./LinkFinder/linkfinder.py (if present)
       - Fallback: internal regex (LinkFinder-style)
  6. Extract client-side SPA routes using framework-specific regex
  7. If no framework AND no bundles (or --crawl-depth > 0), recursive same-origin
     crawl of <a href> + form actions, building the visible-link baseline
  8. Optionally fuzz API path prefixes with a wordlist:
       - External: ./ffuf/ffuf (if present)
       - Fallback: internal Python fuzzer
  9. Diff results against the visible-link baseline
 10. Report unlinked surface in JSON, text, and HTML (with full tool execution log)
"""

import argparse
import datetime
import html as html_lib
import json
import re
import shutil
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    sys.exit("Missing dependency. Run: pip install requests")

try:
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit("Missing dependency. Run: pip install beautifulsoup4")


# ====================================================================
# Constants
# ====================================================================

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_FFUF_BIN = SCRIPT_DIR / "ffuf" / "ffuf"
DEFAULT_LINKFINDER_PY = SCRIPT_DIR / "LinkFinder" / "linkfinder.py"

DEFAULT_USER_AGENT = "AttackSurfaceMapper/2.0 (Authorized-Testing-Only)"
DEFAULT_RATE_LIMIT_MS = 100
DEFAULT_TIMEOUT = 10
DEFAULT_OUTPUT_DIR = "asm_output"
DEFAULT_CRAWL_DEPTH = 1
DEFAULT_CRAWL_PAGES = 40
MAX_LOG_CAPTURE_BYTES = 12000  # per command stdout/stderr

# Endpoint extraction regex - LinkFinder-style fallback when external tool unavailable.
ENDPOINT_REGEX = re.compile(
    r"""(?:"|')
    (
      ((?:[a-zA-Z]{1,10}://|//)
       [^"'/]{1,}\.
       [a-zA-Z]{2,}[^"']{0,})
      |
      ((?:/|\.\./|\./)
       [^"'><,;| *()(%$^/\\\[\]]
       [^"'><,;|()]{1,})
      |
      ([a-zA-Z0-9_\-/]{1,}/
       [a-zA-Z0-9_\-/]{1,}
       \.(?:[a-zA-Z]{1,4}|action)
       (?:[\?|/][^"|']{0,}|))
      |
      ([a-zA-Z0-9_\-]{1,}
       \.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)
       (?:\?[^"|']{0,}|))
    )
    (?:"|')
    """,
    re.VERBOSE,
)

FRAMEWORKS = {
    "Next.js": {
        "html_markers": [
            r'<script[^>]*id=["\']__NEXT_DATA__["\']',
            r'/_next/static/',
            r'<div\s+id=["\']__next["\']',
        ],
        "route_regex": None,
        "route_url_style": "history",
        "note": (
            "Next.js uses file-based routing. Full route enumeration requires "
            "source map disclosure (check for .map files), inspecting the "
            "buildManifest.js file, or analyzing the App Router build output."
        ),
    },
    "Nuxt": {
        "html_markers": [
            r'<div\s+id=["\']__nuxt["\']',
            r'window\.__NUXT__',
            r'/_nuxt/',
        ],
        "route_regex": None,
        "route_url_style": "history",
        "note": (
            "Nuxt uses file-based routing similar to Next.js. Source map "
            "analysis or build manifest inspection recommended."
        ),
    },
    "Angular": {
        "html_markers": [
            r'ng-version=["\'][^"\']+["\']',
            r'<app-root',
            r'_ngcontent-[a-z0-9]+',
        ],
        "version_marker": r'ng-version=["\']([^"\']+)["\']',
        "route_regex": r'path\s*:\s*["\']([^"\']{1,150})["\']',
        "route_url_style": "hash",
        "route_filter": lambda r: (
            not r.startswith("http")
            and "://" not in r
            and " " not in r
            and "\n" not in r
            and "?" not in r
            and not r.endswith(".js")
            and not r.endswith(".css")
            and not r.endswith(".svg")
            and not r.endswith(".png")
            and not r.endswith(".jpg")
            and not r.endswith(".html")
            and len(r) > 0
        ),
        "note": (
            "Angular routes declared as 'path:' in routing modules. "
            "Filtered to exclude asset paths and obvious non-route strings."
        ),
    },
    "Svelte": {
        "html_markers": [
            r'class=["\'][^"\']*svelte-[a-z0-9]+',
            r'/_app/',
            r'data-svelte-h=',
        ],
        "route_regex": None,
        "route_url_style": "history",
        "note": (
            "Svelte/SvelteKit use file-based routing. Routes correspond to "
            "files under /routes in the source. Source map analysis recommended."
        ),
    },
    "Vue": {
        "html_markers": [
            r'data-v-[a-f0-9]+',
            r'window\.__VUE_OPTIONS_API__',
            r'window\.__VUE_PROD_DEVTOOLS__',
        ],
        "route_regex": r'\{\s*path\s*:\s*["\']([^"\']{1,150})["\']',
        "route_url_style": "hash",
        "route_filter": lambda r: (
            not r.startswith("http")
            and "://" not in r
            and " " not in r
            and len(r) > 0
        ),
        "note": (
            "Vue Router uses { path: '...' } objects in route arrays. "
            "Filtered to exclude full URLs."
        ),
    },
    "React": {
        # Tightened: id="root" alone is too generic — pair it with a React-specific
        # signal (devtools hook, react bundle name, data-reactroot, or hydration marker).
        "html_markers": [
            r'data-reactroot',
            r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
            r'/react(?:-dom)?(?:\.production|\.development)?(?:\.min)?\.js',
            r'react\.production\.min\.js',
            r'_reactProps',
            r'<!--\s*react-empty\s*-->',
        ],
        "route_regex": r'<Route\s+[^>]*path=["\']([^"\']+)["\']',
        "route_regex_alt": r'\{\s*path\s*:\s*["\']([^"\']{1,150})["\']',
        "route_url_style": "history",
        "route_filter": lambda r: (
            not r.startswith("http")
            and " " not in r
            and len(r) > 0
        ),
        "note": (
            "React Router has multiple syntaxes. v5 uses <Route path='...'>, "
            "v6 data routers use { path: '...' } objects. Both regexes applied. "
            "Modern React (16+) ships no HTML-side signature; detection here "
            "relies on bundle filename hints and the devtools hook."
        ),
    },
}

DETECTION_PRIORITY = ["Next.js", "Nuxt", "Angular", "Svelte", "Vue", "React"]

SUSPICIOUS_KEYWORDS = [
    "admin", "administration", "administrator",
    "debug", "dev",
    "internal", "private",
    "test", "testing",
    "sandbox", "staging", "beta",
    "backup", "bak",
    "secret", "hidden",
    "legacy", "deprecated",
    "root", "console",
    "/v0/", "/v0", "v0/",
    "actuator",
    "swagger", "graphiql",
]


def is_suspicious(name: str) -> bool:
    lower = name.lower()
    return any(kw in lower for kw in SUSPICIOUS_KEYWORDS)


def _truncate(s: str, limit: int = MAX_LOG_CAPTURE_BYTES) -> str:
    if not s:
        return ""
    if len(s) <= limit:
        return s
    return s[:limit] + f"\n... [truncated, {len(s) - limit} more bytes]"


# ====================================================================
# Data classes / logging
# ====================================================================

@dataclass
class LogEntry:
    phase: str
    tool: str = ""
    command: str = ""
    note: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None
    duration_s: float = 0.0
    timestamp: str = ""


@dataclass
class ScanResult:
    target: str
    framework_detected: Optional[str] = None
    framework_version: Optional[str] = None
    framework_note: Optional[str] = None
    bundles_discovered: list = field(default_factory=list)
    source_maps_found: list = field(default_factory=list)
    visible_links: list = field(default_factory=list)
    endpoints_extracted: list = field(default_factory=list)
    routes_extracted: list = field(default_factory=list)
    unlinked_endpoints: list = field(default_factory=list)
    unlinked_routes: list = field(default_factory=list)
    fuzz_hits: list = field(default_factory=list)
    crawled_pages: list = field(default_factory=list)
    forms_found: list = field(default_factory=list)
    tools_used: list = field(default_factory=list)
    architecture: str = "unknown"  # "spa" | "classic" | "unknown"
    logs: list = field(default_factory=list)


class RunLog:
    """Accumulates phase/tool log entries; prints a one-line summary as it goes."""

    def __init__(self, verbose: bool = True):
        self.entries: list[LogEntry] = []
        self.tools_used: set = set()
        self.verbose = verbose

    def add(self, phase: str, tool: str = "", command: str = "",
            note: str = "", stdout: str = "", stderr: str = "",
            exit_code: Optional[int] = None, duration_s: float = 0.0) -> LogEntry:
        entry = LogEntry(
            phase=phase,
            tool=tool,
            command=command,
            note=note,
            stdout=_truncate(stdout),
            stderr=_truncate(stderr),
            exit_code=exit_code,
            duration_s=round(duration_s, 3),
            timestamp=datetime.datetime.now().strftime("%H:%M:%S"),
        )
        self.entries.append(entry)
        if tool:
            self.tools_used.add(tool)
        if self.verbose:
            sym = "+" if (exit_code in (None, 0)) else "!"
            tail = f" ({duration_s:.2f}s)" if duration_s else ""
            label = f"{tool}: " if tool else ""
            msg = note or command or ""
            if msg:
                print(f"    [{sym}] {label}{msg[:120]}{tail}")
        return entry

    def to_dicts(self) -> list:
        return [asdict(e) for e in self.entries]


# ====================================================================
# HTTP session with rate limiting + logging
# ====================================================================

class Session:
    def __init__(self, user_agent: str, timeout: int, rate_limit_ms: int,
                 cookies: Optional[str] = None, headers: Optional[list] = None,
                 log: Optional[RunLog] = None):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        if cookies:
            self.session.headers["Cookie"] = cookies
        if headers:
            for h in headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    self.session.headers[k.strip()] = v.strip()
        self.timeout = timeout
        self.rate_limit_s = rate_limit_ms / 1000.0
        self._last_request_time = 0.0
        self.log = log

    def get(self, url: str, log_phase: Optional[str] = None):
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self.rate_limit_s:
            time.sleep(self.rate_limit_s - elapsed)
        t0 = time.monotonic()
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            self._last_request_time = time.monotonic()
            if self.log and log_phase:
                self.log.add(
                    phase=log_phase, tool="requests",
                    command=f"GET {url}",
                    note=f"{r.status_code} {len(r.content)}B",
                    exit_code=r.status_code,
                    duration_s=time.monotonic() - t0,
                )
            return r
        except requests.RequestException as e:
            self._last_request_time = time.monotonic()
            if self.log and log_phase:
                self.log.add(
                    phase=log_phase, tool="requests",
                    command=f"GET {url}",
                    note=f"error: {type(e).__name__}",
                    stderr=str(e),
                    exit_code=-1,
                    duration_s=time.monotonic() - t0,
                )
            return None


# ====================================================================
# Subprocess wrapper
# ====================================================================

def run_subprocess(cmd: list, log: RunLog, phase: str, tool: str,
                   timeout: int = 600, cwd: Optional[Path] = None) -> Optional[subprocess.CompletedProcess]:
    cmd_str = " ".join(str(c) for c in cmd)
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            [str(c) for c in cmd],
            capture_output=True, text=True,
            timeout=timeout, cwd=str(cwd) if cwd else None,
        )
        duration = time.monotonic() - t0
        log.add(
            phase=phase, tool=tool, command=cmd_str,
            stdout=proc.stdout, stderr=proc.stderr,
            exit_code=proc.returncode, duration_s=duration,
            note=f"exit={proc.returncode}",
        )
        return proc
    except subprocess.TimeoutExpired as e:
        duration = time.monotonic() - t0
        log.add(
            phase=phase, tool=tool, command=cmd_str,
            stdout=(e.stdout or "") if isinstance(e.stdout, str) else "",
            stderr=f"TIMEOUT after {timeout}s",
            exit_code=-1, duration_s=duration, note="timeout",
        )
        return None
    except FileNotFoundError as e:
        log.add(
            phase=phase, tool=tool, command=cmd_str,
            stderr=str(e), exit_code=-1, duration_s=0.0,
            note="binary not found",
        )
        return None
    except Exception as e:
        log.add(
            phase=phase, tool=tool, command=cmd_str,
            stderr=f"{type(e).__name__}: {e}",
            exit_code=-1, duration_s=time.monotonic() - t0,
            note="exception",
        )
        return None


# ====================================================================
# Core extraction
# ====================================================================

def confirm_consent(target: str) -> None:
    print()
    print("=" * 70)
    print("AUTHORIZATION CONFIRMATION REQUIRED")
    print("=" * 70)
    print(f"Target: {target}")
    print()
    print("This tool performs active reconnaissance against the target above.")
    print("It will:")
    print("  - Fetch the homepage and parse its HTML")
    print("  - Download all referenced JavaScript bundles")
    print("  - Probe for .map files (one GET per bundle)")
    print("  - Optionally crawl <a href> links same-origin (--crawl-depth)")
    print("  - Optionally fuzz API path prefixes with a wordlist (--fuzz)")
    print()
    print("Unauthorized testing is a violation of the Computer Fraud and")
    print("Abuse Act (18 U.S.C. § 1030) and analogous statutes worldwide.")
    print()
    response = input(
        "Do you have WRITTEN authorization to test this target? [yes/NO]: "
    ).strip().lower()
    if response not in ("yes", "y"):
        print("Aborted by user.")
        sys.exit(0)
    print()


def detect_framework(html: str) -> tuple:
    for fw_name in DETECTION_PRIORITY:
        fw_def = FRAMEWORKS[fw_name]
        for marker in fw_def.get("html_markers", []):
            if re.search(marker, html):
                version = None
                if "version_marker" in fw_def:
                    m = re.search(fw_def["version_marker"], html)
                    if m:
                        version = m.group(1)
                return fw_name, version
    return None, None


def discover_bundles(html: str, base_url: str) -> list:
    soup = BeautifulSoup(html, "html.parser")
    bundles = []
    for script in soup.find_all("script", src=True):
        url = urljoin(base_url, script["src"])
        if url not in bundles:
            bundles.append(url)
    return bundles


def extract_visible_links(html: str, base_url: str) -> list:
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.lower().startswith("javascript:"):
            continue
        if href.startswith("#"):
            links.add(href)
        else:
            links.add(urljoin(base_url, href))
    return sorted(links)


def check_source_maps(bundle_urls: list, session: Session, log: RunLog) -> list:
    found = []
    for url in bundle_urls:
        map_url = url + ".map"
        r = session.get(map_url, log_phase="source_map_probe")
        if r is not None and r.status_code == 200 and len(r.content) > 100:
            found.append(map_url)
    log.add(phase="source_map_probe", tool="internal",
            note=f"probed {len(bundle_urls)} bundles, {len(found)} maps exposed")
    return found


def extract_endpoints_internal(js_content: str) -> list:
    endpoints = set()
    for match in ENDPOINT_REGEX.finditer(js_content):
        endpoint = match.group(1)
        if endpoint and 2 < len(endpoint) < 500:
            endpoints.add(endpoint)
    return sorted(endpoints)


def extract_endpoints_linkfinder(bundle_path: Path, linkfinder_py: Path,
                                 log: RunLog) -> Optional[list]:
    """Run external LinkFinder on a saved bundle. Returns list, or None on failure."""
    if not linkfinder_py.exists():
        return None
    cmd = ["python3", linkfinder_py, "-i", bundle_path, "-o", "cli"]
    proc = run_subprocess(cmd, log, phase="endpoint_extraction",
                          tool="LinkFinder", timeout=120)
    if proc is None or proc.returncode != 0:
        return None
    endpoints = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip LinkFinder banner / status lines
        if line.startswith("[+]") or line.startswith("[!]") or line.startswith("Running"):
            continue
        if 2 < len(line) < 500:
            endpoints.append(line)
    return sorted(set(endpoints))


def extract_routes(js_content: str, framework: str) -> tuple:
    fw_def = FRAMEWORKS.get(framework, {})
    pattern = fw_def.get("route_regex")
    note = fw_def.get("note", "")
    if not pattern:
        return [], note
    routes = set()
    route_filter = fw_def.get("route_filter")
    for m in re.finditer(pattern, js_content):
        route = m.group(1)
        if route_filter and not route_filter(route):
            continue
        routes.add(route)
    alt_pattern = fw_def.get("route_regex_alt")
    if alt_pattern:
        for m in re.finditer(alt_pattern, js_content):
            route = m.group(1)
            if route_filter and not route_filter(route):
                continue
            routes.add(route)
    return sorted(routes), note


# ====================================================================
# Crawl mode (non-SPA / "any architecture")
# ====================================================================

def crawl_site(base_url: str, session: Session, log: RunLog,
               max_depth: int, max_pages: int) -> tuple:
    """Same-origin BFS crawl. Returns (pages, forms, all_links, page_endpoints)."""
    base_parsed = urlparse(base_url)
    base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

    visited: set = set()
    queue = deque([(base_url.rstrip("/"), 0)])
    pages: list = []
    forms: list = []
    all_links: set = set()
    page_endpoints: set = set()

    t0 = time.monotonic()
    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        r = session.get(url, log_phase="crawl")
        if r is None or r.status_code >= 400:
            continue
        ct = r.headers.get("Content-Type", "")
        if "html" not in ct.lower():
            continue
        pages.append({
            "url": url, "status": r.status_code,
            "depth": depth, "size": len(r.content),
        })
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.lower().startswith(("javascript:", "mailto:", "tel:")):
                continue
            absolute = urljoin(url, href).split("#")[0]
            if urlparse(absolute).netloc != base_parsed.netloc:
                continue
            all_links.add(absolute)
            if absolute not in visited:
                queue.append((absolute, depth + 1))
        for form in soup.find_all("form"):
            action = form.get("action", "") or url
            method = (form.get("method") or "GET").upper()
            inputs = [inp.get("name", "") for inp in form.find_all(["input", "textarea", "select"])
                      if inp.get("name")]
            forms.append({
                "page": url,
                "action": urljoin(url, action),
                "method": method,
                "inputs": inputs,
            })
        # Inline scripts -> endpoint candidates
        for script in soup.find_all("script"):
            if script.string:
                for ep in extract_endpoints_internal(script.string):
                    page_endpoints.add(ep)

    log.add(phase="crawl", tool="internal-crawler",
            note=f"visited {len(visited)} pages (depth<={max_depth}), "
                 f"{len(all_links)} links, {len(forms)} forms, "
                 f"{len(page_endpoints)} inline endpoints",
            duration_s=time.monotonic() - t0)
    return pages, forms, sorted(all_links), sorted(page_endpoints)


# ====================================================================
# Fuzzing
# ====================================================================

def fuzz_internal(base_url: str, wordlist_path: str, session: Session,
                  path_prefixes: list, log: RunLog,
                  match_codes: tuple = (200, 201, 204, 301, 302, 307, 401, 403, 405)) -> list:
    try:
        words = Path(wordlist_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except FileNotFoundError:
        log.add(phase="active_fuzzing", tool="internal-fuzzer",
                stderr=f"Wordlist not found: {wordlist_path}", exit_code=-1)
        return []
    hits = []
    t0 = time.monotonic()
    total = sum(1 for w in words if w.strip() and not w.startswith("#")) * len(path_prefixes)
    done = 0
    for prefix in path_prefixes:
        for word in words:
            word = word.strip()
            if not word or word.startswith("#"):
                continue
            done += 1
            url = urljoin(base_url, prefix.rstrip("/") + "/" + word)
            r = session.get(url)
            if r is None:
                continue
            if r.status_code in match_codes and len(r.content) > 0:
                hits.append({"url": url, "status": r.status_code, "size": len(r.content)})
            if done % 200 == 0:
                print(f"    [.] {done}/{total}...")
    log.add(phase="active_fuzzing", tool="internal-fuzzer",
            note=f"{done} requests, {len(hits)} hits",
            duration_s=time.monotonic() - t0)
    return hits


def fuzz_with_ffuf(base_url: str, wordlist: str, prefixes: list,
                   ffuf_bin: Path, rate_ms: int, log: RunLog,
                   output_dir: Path) -> list:
    """Run external ffuf against each prefix. Returns combined hits list."""
    all_hits = []
    delay_s = max(rate_ms / 1000.0, 0.0)
    for prefix in prefixes:
        target_url = base_url.rstrip("/") + "/" + prefix.strip("/") + "/FUZZ"
        safe_name = re.sub(r"[^a-z0-9]+", "_", prefix.lower()).strip("_") or "root"
        out_json = output_dir / f"ffuf_{safe_name}.json"
        cmd = [
            ffuf_bin,
            "-w", wordlist,
            "-u", target_url,
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-o", out_json,
            "-of", "json",
            "-s",
            "-noninteractive",
        ]
        if delay_s > 0:
            cmd += ["-p", f"{delay_s:.3f}"]
        proc = run_subprocess(cmd, log, phase="active_fuzzing",
                              tool="ffuf", timeout=1800)
        if proc is None:
            continue
        if not out_json.exists():
            continue
        try:
            data = json.loads(out_json.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            log.add(phase="active_fuzzing", tool="ffuf",
                    stderr=f"could not parse {out_json}", exit_code=-1)
            continue
        for r in data.get("results", []):
            all_hits.append({
                "url": r.get("url", ""),
                "status": r.get("status", 0),
                "size": r.get("length", 0),
            })
    return all_hits


def compute_diff(visible_links: list, endpoints: list, routes: list) -> tuple:
    visible_paths = set()
    for link in visible_links:
        parsed = urlparse(link)
        if parsed.path:
            visible_paths.add(parsed.path)
        if link.startswith("#/"):
            visible_paths.add(link[2:])

    unlinked_eps = []
    for ep in endpoints:
        ep_clean = ep.lstrip("/")
        ep_path = urlparse(ep).path.lstrip("/") if "://" in ep else ep_clean
        if not any(ep_path and ep_path in v.lstrip("/") for v in visible_paths):
            unlinked_eps.append(ep)

    unlinked_routes = []
    for route in routes:
        route_clean = route.lstrip("/").lstrip("#").lstrip("/")
        if not any(route_clean and route_clean in v.lstrip("/") for v in visible_paths):
            unlinked_routes.append(route)

    return unlinked_eps, unlinked_routes


# ====================================================================
# Reports
# ====================================================================

def write_reports(result: ScanResult, output_dir: Path) -> tuple:
    json_path = output_dir / "scan_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(asdict(result), f, indent=2)

    txt_path = output_dir / "summary.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("Attack Surface Mapper - Summary\n")
        f.write("================================\n\n")
        f.write(f"Target:           {result.target}\n")
        f.write(f"Architecture:     {result.architecture}\n")
        f.write(f"Framework:        {result.framework_detected or 'Unknown'}")
        if result.framework_version:
            f.write(f" {result.framework_version}")
        f.write("\n")
        f.write(f"Tools used:       {', '.join(result.tools_used) or 'internal-only'}\n\n")
        if result.framework_note:
            f.write(f"Framework note:\n  {result.framework_note}\n\n")
        if result.source_maps_found:
            f.write(f"== SOURCE MAPS EXPOSED ({len(result.source_maps_found)}) ==\n")
            f.write("FINDING: Information disclosure (OWASP A02:2025).\n")
            for m in result.source_maps_found:
                f.write(f"  {m}\n")
            f.write("\n")
        f.write(f"== UNLINKED ENDPOINTS ({len(result.unlinked_endpoints)}) ==\n")
        for ep in result.unlinked_endpoints:
            f.write(f"  {ep}\n")
        f.write("\n")
        f.write(f"== UNLINKED ROUTES ({len(result.unlinked_routes)}) ==\n")
        for r in result.unlinked_routes:
            f.write(f"  {r}\n")
        f.write("\n")
        if result.crawled_pages:
            f.write(f"== CRAWLED PAGES ({len(result.crawled_pages)}) ==\n")
            for p in result.crawled_pages:
                f.write(f"  [{p['status']}] depth={p['depth']} {p['url']}\n")
            f.write("\n")
        if result.forms_found:
            f.write(f"== FORMS ({len(result.forms_found)}) ==\n")
            for fm in result.forms_found:
                f.write(f"  {fm['method']} {fm['action']}  inputs={fm['inputs']}\n")
            f.write("\n")
        if result.fuzz_hits:
            f.write(f"== ACTIVE FUZZ HITS ({len(result.fuzz_hits)}) ==\n")
            for hit in result.fuzz_hits:
                f.write(f"  [{hit['status']}] {hit['url']} ({hit['size']} bytes)\n")
            f.write("\n")
        f.write(f"== TOOL EXECUTION LOG ({len(result.logs)} entries) ==\n")
        for entry in result.logs:
            f.write(f"  [{entry['timestamp']}] {entry['phase']:<22} "
                    f"{entry['tool']:<18} exit={entry['exit_code']} "
                    f"{entry['duration_s']}s  {entry['note'] or entry['command'][:80]}\n")
    return json_path, txt_path


def _esc(s) -> str:
    if s is None:
        return ""
    return html_lib.escape(str(s), quote=True)


def write_html_report(result: ScanResult, output_dir: Path) -> Path:
    html_path = output_dir / "report.html"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target = result.target.rstrip("/")
    framework = result.framework_detected or "Not detected"
    if result.framework_version:
        framework += f" {result.framework_version}"

    route_url_style = "hash"
    if result.framework_detected and result.framework_detected in FRAMEWORKS:
        route_url_style = FRAMEWORKS[result.framework_detected].get("route_url_style", "hash")

    def render_route_row(route):
        suspicious = is_suspicious(route)
        cls = "item-row suspicious" if suspicious else "item-row"
        return f"""
        <div class="{cls}">
          <a class="url" target="_blank" rel="noopener"
             data-route="{_esc(route)}" data-route-style="{route_url_style}"
             href="#">{_esc(route)}</a>
          <button type="button" class="btn" onclick="copyCurl(this)"
                  data-route="{_esc(route)}" data-route-style="{route_url_style}">Copy as curl</button>
        </div>"""

    def render_endpoint_row(endpoint):
        suspicious = is_suspicious(endpoint)
        cls = "item-row suspicious" if suspicious else "item-row"
        return f"""
        <div class="{cls}">
          <a class="url" target="_blank" rel="noopener"
             data-endpoint="{_esc(endpoint)}"
             href="#">{_esc(endpoint)}</a>
          <button type="button" class="btn" onclick="copyCurl(this)"
                  data-endpoint="{_esc(endpoint)}">Copy as curl</button>
        </div>"""

    if result.source_maps_found:
        rows = "\n".join(
            f"""<div class="item-row suspicious">
                <a class="url" target="_blank" rel="noopener"
                   data-absolute-url="{_esc(m)}" href="{_esc(m)}">{_esc(m)}</a>
                </div>"""
            for m in result.source_maps_found
        )
        source_maps_html = f"""
        <section class="finding-critical">
          <h2>Source Maps Exposed ({len(result.source_maps_found)})</h2>
          <p><strong>Finding:</strong> Information disclosure (OWASP A02:2025
          Security Misconfiguration / CWE-540). Source maps allow an attacker
          to reverse the JavaScript minification and read the original
          codebase, comments, and file structure.</p>
          {rows}
        </section>"""
    else:
        source_maps_html = ""

    if result.unlinked_routes:
        rows = "\n".join(render_route_row(r) for r in result.unlinked_routes)
        suspicious_count = sum(1 for r in result.unlinked_routes if is_suspicious(r))
        sus_note = (
            f"<p><strong>{suspicious_count}</strong> route(s) flagged as suspicious "
            f"(highlighted in red).</p>"
            if suspicious_count else ""
        )
        routes_html = f"""
        <section>
          <h2>Unlinked SPA Routes ({len(result.unlinked_routes)})</h2>
          <p>Routes declared in the framework's routing table but not reachable
          from the visible navigation. These are highest-priority leads.</p>
          {sus_note}
          {rows}
        </section>"""
    else:
        routes_html = """
        <section>
          <h2>Unlinked SPA Routes (0)</h2>
          <p class="empty">No unlinked routes detected. This can mean: (a) the app's UI exposes everything, (b) the framework uses file-based routing and routes couldn't be extracted via regex, (c) framework detection failed, or (d) target is not an SPA.</p>
        </section>"""

    if result.unlinked_endpoints:
        rows = "\n".join(render_endpoint_row(e) for e in result.unlinked_endpoints)
        suspicious_count = sum(1 for e in result.unlinked_endpoints if is_suspicious(e))
        sus_note = (
            f"<p><strong>{suspicious_count}</strong> endpoint(s) flagged as suspicious.</p>"
            if suspicious_count else ""
        )
        endpoints_html = f"""
        <section>
          <h2>Unlinked Endpoints ({len(result.unlinked_endpoints)})</h2>
          <p>API endpoints referenced in JS bundles but not loaded during normal navigation.</p>
          {sus_note}
          {rows}
        </section>"""
    else:
        endpoints_html = ""

    if result.fuzz_hits:
        rows = []
        for hit in result.fuzz_hits:
            sus = is_suspicious(hit["url"])
            cls = "item-row suspicious" if sus else "item-row"
            rows.append(f"""
            <div class="{cls}">
              <span class="status status-{hit['status']}">{hit['status']}</span>
              <a class="url" target="_blank" rel="noopener"
                 data-absolute-url="{_esc(hit['url'])}" href="{_esc(hit['url'])}">{_esc(hit['url'])}</a>
              <span class="size">{hit['size']} bytes</span>
              <button type="button" class="btn" onclick="copyCurl(this)"
                      data-absolute-url="{_esc(hit['url'])}">Copy as curl</button>
            </div>""")
        fuzz_html = f"""
        <section>
          <h2>Active Fuzz Hits ({len(result.fuzz_hits)})</h2>
          <p>Server-side paths discovered via wordlist enumeration.</p>
          {"".join(rows)}
        </section>"""
    else:
        fuzz_html = ""

    if result.crawled_pages:
        crawl_rows = "\n".join(
            f"""<div class="item-row">
                <span class="status status-{p['status']}">{p['status']}</span>
                <span class="depth">d{p['depth']}</span>
                <a class="url" target="_blank" rel="noopener"
                   data-absolute-url="{_esc(p['url'])}" href="{_esc(p['url'])}">{_esc(p['url'])}</a>
                <span class="size">{p['size']} bytes</span>
              </div>"""
            for p in result.crawled_pages
        )
        crawl_html = f"""
        <section>
          <h2>Crawled Pages ({len(result.crawled_pages)})</h2>
          <p>Pages reached by recursive same-origin <code>&lt;a href&gt;</code> traversal. This baseline replaces the homepage-only one when crawl mode is active.</p>
          {crawl_rows}
        </section>"""
    else:
        crawl_html = ""

    if result.forms_found:
        form_rows = "\n".join(
            f"""<div class="item-row">
                <span class="method">{_esc(fm['method'])}</span>
                <a class="url" target="_blank" rel="noopener"
                   data-absolute-url="{_esc(fm['action'])}" href="{_esc(fm['action'])}">{_esc(fm['action'])}</a>
                <span class="inputs">inputs: {_esc(', '.join(fm['inputs']) or 'none')}</span>
              </div>"""
            for fm in result.forms_found
        )
        forms_html = f"""
        <section>
          <h2>Forms Discovered ({len(result.forms_found)})</h2>
          <p>Form action URLs and input names discovered during crawl. Useful targets for parameter pollution, IDOR, and CSRF analysis.</p>
          {form_rows}
        </section>"""
    else:
        forms_html = ""

    # Tool execution log -- collapsible, per-entry stdout/stderr expandable
    if result.logs:
        log_rows = []
        for i, entry in enumerate(result.logs, start=1):
            exit_str = "-" if entry.get("exit_code") is None else str(entry["exit_code"])
            ok = entry.get("exit_code") in (None, 0, 200, 201, 204, 301, 302, 307)
            status_cls = "log-ok" if ok else "log-bad"
            stdout_block = (f"<pre class='log-out'>{_esc(entry['stdout'])}</pre>"
                            if entry.get("stdout") else "")
            stderr_block = (f"<pre class='log-err'>{_esc(entry['stderr'])}</pre>"
                            if entry.get("stderr") else "")
            cmd_block = (f"<div class='log-cmd'><code>{_esc(entry['command'])}</code></div>"
                         if entry.get("command") else "")
            note = entry.get("note") or ""
            log_rows.append(f"""
            <details class="log-entry {status_cls}">
              <summary>
                <span class="log-num">#{i}</span>
                <span class="log-ts">{_esc(entry.get('timestamp', ''))}</span>
                <span class="log-phase">{_esc(entry['phase'])}</span>
                <span class="log-tool">{_esc(entry.get('tool', ''))}</span>
                <span class="log-exit">exit={_esc(exit_str)}</span>
                <span class="log-dur">{entry.get('duration_s', 0)}s</span>
                <span class="log-note">{_esc(note)}</span>
              </summary>
              {cmd_block}
              {stdout_block}
              {stderr_block}
            </details>""")
        logs_html = f"""
        <section id="logs">
          <h2>Tool Execution Log ({len(result.logs)} entries)</h2>
          <p>Every HTTP fetch, subprocess call, and analysis phase recorded here.
          Click any row to expand the command, stdout, and stderr.
          Tools used in this scan: <strong>{_esc(', '.join(result.tools_used) or 'internal-only')}</strong>.</p>
          <div class="log-table">
            <div class="log-header">
              <span class="log-num">#</span>
              <span class="log-ts">time</span>
              <span class="log-phase">phase</span>
              <span class="log-tool">tool</span>
              <span class="log-exit">exit</span>
              <span class="log-dur">dur</span>
              <span class="log-note">note</span>
            </div>
            {''.join(log_rows)}
          </div>
        </section>"""
    else:
        logs_html = ""

    if result.framework_note:
        framework_note_html = f"""
        <div class="note">
          <strong>Framework note:</strong> {_esc(result.framework_note)}
        </div>"""
    else:
        framework_note_html = ""

    if result.visible_links:
        visible_items = "\n".join(
            f'<li><code>{_esc(link)}</code></li>' for link in result.visible_links
        )
    else:
        visible_items = '<li class="empty">No visible links extracted from initial HTML.</li>'

    tools_used_str = ", ".join(result.tools_used) if result.tools_used else "internal-only"
    architecture = result.architecture or "unknown"

    html_content = HTML_REPORT_TEMPLATE.format(
        target=_esc(target),
        target_js=json.dumps(target),
        framework=_esc(framework),
        timestamp=_esc(timestamp),
        architecture=_esc(architecture),
        tools_used=_esc(tools_used_str),
        source_maps_section=source_maps_html,
        routes_section=routes_html,
        endpoints_section=endpoints_html,
        fuzz_section=fuzz_html,
        crawl_section=crawl_html,
        forms_section=forms_html,
        logs_section=logs_html,
        framework_note_section=framework_note_html,
        visible_count=len(result.visible_links),
        visible_list=visible_items,
    )

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return html_path


HTML_REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Attack Surface Report - {target}</title>
<style>
* {{ box-sizing: border-box; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, sans-serif;
  max-width: 1200px;
  margin: 2rem auto;
  padding: 0 1.5rem;
  background: #fafafa;
  color: #222;
  line-height: 1.5;
}}
h1 {{ margin-bottom: 0.2rem; }}
h2 {{
  margin-top: 2.5rem;
  border-bottom: 1px solid #ccc;
  padding-bottom: 0.3rem;
}}
code, .url {{
  font-family: "SF Mono", Monaco, Menlo, Consolas, "Courier New", monospace;
  font-size: 0.92em;
}}
.meta {{
  background: #fff;
  border: 1px solid #ddd;
  border-radius: 6px;
  padding: 0.8rem 1.2rem;
  margin-bottom: 1.5rem;
}}
.meta div {{ margin: 0.25rem 0; }}
.base-url-rewriter {{
  background: #eaf3fb;
  border: 1px solid #99c0e0;
  padding: 1rem;
  border-radius: 6px;
  margin-bottom: 1.5rem;
}}
.base-url-rewriter label {{ display: block; font-weight: 600; margin-bottom: 0.3rem; }}
.base-url-rewriter input {{
  width: 100%;
  padding: 0.5rem;
  font-family: monospace;
  font-size: 1rem;
  border: 1px solid #99c0e0;
  border-radius: 3px;
}}
.base-url-rewriter small {{ display: block; margin-top: 0.5rem; color: #555; }}
.finding-critical {{
  background: #fff5f3;
  border: 1px solid #e07060;
  border-left: 5px solid #c33;
  padding: 1rem 1.2rem;
  border-radius: 6px;
  margin-bottom: 1.5rem;
}}
.finding-critical h2 {{
  margin-top: 0;
  color: #a22;
  border-bottom: none;
}}
.item-row {{
  background: #fff;
  border: 1px solid #e0e0e0;
  border-radius: 4px;
  padding: 0.55rem 0.9rem;
  margin-bottom: 0.5rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}}
.item-row.suspicious {{
  border-color: #d44;
  background: #fff5f5;
}}
.item-row.suspicious::before {{
  content: "\26A0";
  color: #c33;
  font-weight: bold;
  margin-right: 0.3rem;
}}
.item-row .url {{
  flex-grow: 1;
  word-break: break-all;
  color: #06c;
  text-decoration: none;
}}
.item-row .url:hover {{ text-decoration: underline; }}
.btn {{
  background: #f0f0f0;
  border: 1px solid #bbb;
  padding: 0.3rem 0.7rem;
  font-size: 0.85em;
  cursor: pointer;
  border-radius: 3px;
  font-family: inherit;
  color: #222;
}}
.btn:hover {{ background: #e0e0e0; }}
.btn.copied {{ background: #4a4; color: white; border-color: #383; }}
.status {{
  font-family: monospace;
  padding: 0.1rem 0.5rem;
  border-radius: 3px;
  font-weight: 600;
  font-size: 0.85em;
}}
.status-200, .status-201, .status-204 {{ background: #d4f4dd; color: #1a6e30; }}
.status-301, .status-302, .status-307 {{ background: #e0e0ff; color: #229; }}
.status-401, .status-403, .status-405 {{ background: #ffe5cc; color: #a64c00; }}
.status-500 {{ background: #ffd0d0; color: #a22; }}
.size {{ color: #777; font-size: 0.85em; }}
.depth {{
  background: #eef; color: #336;
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
  font-family: monospace;
  font-size: 0.8em;
}}
.method {{
  background: #ffe0b3; color: #663;
  padding: 0.1rem 0.5rem;
  border-radius: 3px;
  font-family: monospace;
  font-weight: 600;
  font-size: 0.85em;
}}
.inputs {{ color: #555; font-size: 0.85em; font-family: monospace; }}
details {{
  background: #fff;
  border: 1px solid #ddd;
  border-radius: 6px;
  padding: 0.5rem 1rem;
  margin: 0.5rem 0;
}}
details summary {{
  cursor: pointer;
  font-weight: 600;
  padding: 0.3rem 0;
}}
details ul {{ font-family: monospace; font-size: 0.88em; padding-left: 1.5rem; }}
.log-table {{
  background: #fff;
  border: 1px solid #ddd;
  border-radius: 6px;
  overflow: hidden;
}}
.log-header, .log-entry summary {{
  display: grid;
  grid-template-columns: 3rem 5rem 11rem 9rem 4rem 4.5rem 1fr;
  gap: 0.5rem;
  align-items: center;
  font-family: monospace;
  font-size: 0.85em;
}}
.log-header {{
  background: #f0f0f0;
  font-weight: 600;
  padding: 0.4rem 0.6rem;
  border-bottom: 1px solid #ddd;
  color: #555;
}}
.log-entry {{
  border: none;
  border-bottom: 1px solid #eee;
  margin: 0;
  padding: 0;
  border-radius: 0;
}}
.log-entry summary {{
  padding: 0.35rem 0.6rem;
  font-weight: normal;
  list-style: none;
}}
.log-entry summary::-webkit-details-marker {{ display: none; }}
.log-entry:hover {{ background: #fafafa; }}
.log-entry.log-bad {{ background: #fff5f5; }}
.log-entry.log-bad:hover {{ background: #ffeded; }}
.log-num {{ color: #888; }}
.log-ts {{ color: #555; }}
.log-phase {{ color: #225; font-weight: 600; }}
.log-tool {{ color: #060; }}
.log-exit {{ color: #444; }}
.log-dur {{ color: #777; text-align: right; }}
.log-note {{ color: #444; word-break: break-all; }}
.log-cmd, .log-out, .log-err {{
  font-family: monospace;
  font-size: 0.82em;
  padding: 0.5rem 0.7rem;
  margin: 0.3rem 0.6rem;
  border-radius: 3px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 18rem;
  overflow: auto;
}}
.log-cmd {{ background: #f6f8fa; border-left: 3px solid #88b; color: #225; }}
.log-out {{ background: #f5fff5; border-left: 3px solid #6a6; color: #232; }}
.log-err {{ background: #fff5f5; border-left: 3px solid #c44; color: #722; }}
footer {{
  margin-top: 3rem;
  padding-top: 1.5rem;
  border-top: 1px solid #ddd;
  color: #555;
  font-size: 0.9em;
}}
.empty {{ color: #888; font-style: italic; }}
.note {{
  background: #fffbe5;
  border-left: 4px solid #d4a017;
  padding: 0.7rem 1rem;
  margin: 0.8rem 0;
  border-radius: 4px;
}}
nav.toc {{
  background: #fff;
  border: 1px solid #ddd;
  border-radius: 6px;
  padding: 0.6rem 1rem;
  margin-bottom: 1.5rem;
  font-size: 0.9em;
}}
nav.toc a {{ margin-right: 1rem; color: #06c; text-decoration: none; }}
nav.toc a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>

<h1>Attack Surface Report</h1>
<div class="meta">
  <div><strong>Target:</strong> <code>{target}</code></div>
  <div><strong>Architecture:</strong> {architecture}</div>
  <div><strong>Framework:</strong> {framework}</div>
  <div><strong>Tools used:</strong> {tools_used}</div>
  <div><strong>Generated:</strong> {timestamp}</div>
</div>

<nav class="toc">
  <strong>Jump to:</strong>
  <a href="#logs">Tool Log</a>
</nav>

<div class="base-url-rewriter">
  <label for="base-url-input">Base URL (rewrites all links live):</label>
  <input id="base-url-input" type="text" value="{target}">
  <small>Edit this field to rewrite every clickable target throughout the report. All "Copy as curl" buttons will also use the rewritten URL.</small>
</div>

{source_maps_section}

{routes_section}

{endpoints_section}

{crawl_section}

{forms_section}

{fuzz_section}

{framework_note_section}

<details>
  <summary>Visible-link baseline ({visible_count} links)</summary>
  <p>URLs the script extracted from <code>&lt;a href&gt;</code> tags. For SPA targets this is just the homepage; in crawl mode this expands to all reachable same-origin pages.</p>
  <ul>
    {visible_list}
  </ul>
</details>

{logs_section}

<footer>
  <strong>Methodology reminder:</strong> The unlinked routes and endpoints listed above are <em>starting points</em>, not findings. Manually navigate to each one, verify what it exposes, and capture evidence before writing it up for a client. Regex-based extraction has false positives; the visible-link baseline is approximate.
  <br><br>
  Generated by <code>attack_surface_mapper.py</code> v2.
</footer>

<script>
(function() {{
  var baseUrl = {target_js};

  function normalizeBase(url) {{
    return (url || "").replace(/\/+$/, "");
  }}

  function buildRouteUrl(route, style) {{
    var r = String(route).replace(/^\/+/, "").replace(/^#\/?/, "");
    if (style === "hash") {{
      return baseUrl + "/#/" + r;
    }}
    return baseUrl + "/" + r;
  }}

  function buildEndpointUrl(endpoint) {{
    var e = String(endpoint);
    if (/^https?:\/\//i.test(e)) return e;
    if (/^\/\//.test(e)) return "https:" + e;
    if (e.charAt(0) === "/") return baseUrl + e;
    return baseUrl + "/" + e;
  }}

  function refreshLinks() {{
    document.querySelectorAll("[data-route]").forEach(function(el) {{
      if (el.tagName === "A") {{
        var url = buildRouteUrl(el.dataset.route, el.dataset.routeStyle);
        el.href = url;
        el.textContent = url;
      }}
    }});
    document.querySelectorAll("[data-endpoint]").forEach(function(el) {{
      if (el.tagName === "A") {{
        var url = buildEndpointUrl(el.dataset.endpoint);
        el.href = url;
        el.textContent = url;
      }}
    }});
  }}

  window.copyCurl = function(btn) {{
    var url;
    if (btn.dataset.absoluteUrl) {{
      url = btn.dataset.absoluteUrl;
    }} else if (btn.dataset.route) {{
      url = buildRouteUrl(btn.dataset.route, btn.dataset.routeStyle);
    }} else if (btn.dataset.endpoint) {{
      url = buildEndpointUrl(btn.dataset.endpoint);
    }} else {{
      return;
    }}
    var cmd = "curl -i '" + url + "'";
    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(cmd).then(function() {{
        flash(btn);
      }}).catch(function() {{
        fallbackCopy(cmd);
        flash(btn);
      }});
    }} else {{
      fallbackCopy(cmd);
      flash(btn);
    }}
  }};

  function fallbackCopy(text) {{
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    try {{ document.execCommand("copy"); }} catch (e) {{}}
    document.body.removeChild(ta);
  }}

  function flash(btn) {{
    var original = btn.textContent;
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(function() {{
      btn.textContent = original;
      btn.classList.remove("copied");
    }}, 1500);
  }}

  var input = document.getElementById("base-url-input");
  input.addEventListener("input", function(e) {{
    baseUrl = normalizeBase(e.target.value);
    refreshLinks();
  }});

  refreshLinks();
}})();
</script>

</body>
</html>
"""


# ====================================================================
# Main
# ====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Automated attack surface mapping (any web app architecture)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 attack_surface_mapper.py http://localhost:3000
  python3 attack_surface_mapper.py https://example.com --crawl-depth 2
  python3 attack_surface_mapper.py http://localhost:3000 --fuzz --wordlist /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
  python3 attack_surface_mapper.py https://target.tld --cookie "session=abc123" --header "X-Forwarded-For: 127.0.0.1"
        """,
    )
    parser.add_argument("target", help="Target URL (e.g. http://localhost:3000)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT_DIR, help="Output directory")
    parser.add_argument("--fuzz", action="store_true", help="Enable active API path fuzzing")
    parser.add_argument("--wordlist", help="Wordlist for --fuzz (required if --fuzz)")
    parser.add_argument(
        "--fuzz-paths",
        nargs="+",
        default=["/api/", "/rest/", "/v1/"],
        help="API path prefixes to fuzz (default: /api/ /rest/ /v1/)",
    )
    parser.add_argument("--crawl-depth", type=int, default=DEFAULT_CRAWL_DEPTH,
                        help=f"Same-origin crawl depth from homepage (default: {DEFAULT_CRAWL_DEPTH}; 0 = homepage only)")
    parser.add_argument("--crawl-pages", type=int, default=DEFAULT_CRAWL_PAGES,
                        help=f"Max pages to crawl (default: {DEFAULT_CRAWL_PAGES})")
    parser.add_argument("--cookie", help="Cookie header value to send with every request")
    parser.add_argument("--header", action="append", default=[],
                        help="Extra request header (repeatable). Format: 'Name: value'")
    parser.add_argument("--ffuf-path", default=str(DEFAULT_FFUF_BIN),
                        help=f"Path to ffuf binary (default: {DEFAULT_FFUF_BIN})")
    parser.add_argument("--linkfinder-path", default=str(DEFAULT_LINKFINDER_PY),
                        help=f"Path to LinkFinder linkfinder.py (default: {DEFAULT_LINKFINDER_PY})")
    parser.add_argument("--no-external-tools", action="store_true",
                        help="Force internal regex/fuzzer; ignore bundled ffuf/LinkFinder")
    parser.add_argument(
        "--rate-limit", type=int, default=DEFAULT_RATE_LIMIT_MS,
        help=f"Delay between requests in ms (default: {DEFAULT_RATE_LIMIT_MS})",
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent header")
    parser.add_argument(
        "--no-consent", action="store_true",
        help="Skip interactive consent prompt (CI use; you take responsibility)",
    )
    args = parser.parse_args()

    if args.fuzz and not args.wordlist:
        parser.error("--fuzz requires --wordlist")

    if not args.no_consent:
        confirm_consent(args.target)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    log = RunLog(verbose=True)
    session = Session(
        args.user_agent, args.timeout, args.rate_limit,
        cookies=args.cookie, headers=args.header, log=log,
    )

    ffuf_bin = Path(args.ffuf_path) if not args.no_external_tools else None
    linkfinder_py = Path(args.linkfinder_path) if not args.no_external_tools else None
    ffuf_available = bool(ffuf_bin and ffuf_bin.exists())
    linkfinder_available = bool(linkfinder_py and linkfinder_py.exists())

    log.add(phase="init", tool="config",
            note=f"ffuf={'yes' if ffuf_available else 'no'} ({ffuf_bin}); "
                 f"LinkFinder={'yes' if linkfinder_available else 'no'} ({linkfinder_py})")

    result = ScanResult(target=args.target)

    # Phase 1: fetch homepage
    print(f"[*] Fetching {args.target}")
    home = session.get(args.target, log_phase="fetch_homepage")
    if home is None or home.status_code != 200:
        status = home.status_code if home is not None else "no response"
        print(f"[!] Could not fetch target. Status: {status}")
        log.add(phase="fetch_homepage", tool="requests",
                stderr=f"homepage fetch failed: {status}", exit_code=-1)
        result.logs = log.to_dicts()
        result.tools_used = sorted(log.tools_used)
        write_reports(result, output_dir)
        write_html_report(result, output_dir)
        sys.exit(1)
    html = home.text

    # Phase 2: detect framework
    fw, ver = detect_framework(html)
    result.framework_detected = fw
    result.framework_version = ver
    if fw:
        print(f"[+] Framework detected: {fw}" + (f" {ver}" if ver else ""))
        result.framework_note = FRAMEWORKS[fw].get("note")
        log.add(phase="framework_detect", tool="internal",
                note=f"detected {fw}" + (f" {ver}" if ver else ""))
    else:
        print("[!] No SPA framework detected from HTML markers.")
        log.add(phase="framework_detect", tool="internal", note="no framework matched")

    # Phase 3: discover bundles
    bundles = discover_bundles(html, args.target)
    result.bundles_discovered = bundles
    print(f"[+] Discovered {len(bundles)} JavaScript bundles")
    log.add(phase="bundle_discovery", tool="internal",
            note=f"{len(bundles)} bundles found")

    # Decide architecture
    if fw or len(bundles) >= 3:
        result.architecture = "spa"
    elif len(bundles) > 0:
        result.architecture = "hybrid"
    else:
        result.architecture = "classic"
    log.add(phase="architecture_inference", tool="internal",
            note=f"architecture={result.architecture}")

    # Phase 4: visible-links baseline (always grab homepage links)
    visible = extract_visible_links(html, args.target)
    log.add(phase="baseline_extraction", tool="internal",
            note=f"{len(visible)} <a href> on homepage")

    # Phase 5: source map check
    if bundles:
        print("[*] Probing for source map disclosure (.map files)...")
        maps_found = check_source_maps(bundles, session, log)
        result.source_maps_found = maps_found
        if maps_found:
            print(f"[!!] SOURCE MAPS EXPOSED ({len(maps_found)}):")
            for m in maps_found:
                print(f"    - {m}")
        else:
            print("[+] No exposed source maps detected.")

    # Phase 6: analyze bundles (LinkFinder external preferred, internal fallback)
    all_endpoints = set()
    all_routes = set()
    for bundle_url in bundles:
        bundle_name = Path(urlparse(bundle_url).path).name or "bundle.js"
        print(f"[*] Analyzing {bundle_name}")
        r = session.get(bundle_url, log_phase="bundle_download")
        if r is None or r.status_code != 200:
            print(f"    [-] Could not download {bundle_url}")
            continue
        bundle_content = r.text
        local_path = output_dir / bundle_name
        local_path.write_text(bundle_content, encoding="utf-8")

        endpoints_from_lf = None
        if linkfinder_available:
            endpoints_from_lf = extract_endpoints_linkfinder(local_path, linkfinder_py, log)
        if endpoints_from_lf is not None:
            eps = endpoints_from_lf
            print(f"    [+] {len(eps)} endpoints (via LinkFinder)")
        else:
            eps = extract_endpoints_internal(bundle_content)
            log.add(phase="endpoint_extraction", tool="internal-regex",
                    note=f"{bundle_name}: {len(eps)} endpoints (regex fallback)")
            print(f"    [+] {len(eps)} endpoints (internal regex)")
        all_endpoints.update(eps)

        if fw and FRAMEWORKS[fw].get("route_regex"):
            routes, _ = extract_routes(bundle_content, fw)
            all_routes.update(routes)
            log.add(phase="route_extraction", tool="internal-regex",
                    note=f"{bundle_name}: {len(routes)} {fw} routes")
            print(f"    [+] {len(routes)} SPA route candidates")

    # Phase 7: crawl mode if non-SPA or user opted in
    do_crawl = (result.architecture in ("classic", "hybrid")) or args.crawl_depth >= 2
    if do_crawl and args.crawl_depth > 0:
        print(f"[*] Crawling site (depth={args.crawl_depth}, max-pages={args.crawl_pages})...")
        pages, forms, crawl_links, page_endpoints = crawl_site(
            args.target, session, log,
            max_depth=args.crawl_depth, max_pages=args.crawl_pages,
        )
        result.crawled_pages = pages
        result.forms_found = forms
        all_endpoints.update(page_endpoints)
        # Crawl links REPLACE the visible baseline for non-SPAs (richer signal)
        if result.architecture in ("classic", "hybrid"):
            visible = sorted(set(visible) | set(crawl_links))
        else:
            visible = sorted(set(visible) | set(crawl_links))
        print(f"[+] Crawled {len(pages)} pages, {len(forms)} forms, "
              f"{len(page_endpoints)} endpoints from inline scripts")

    result.visible_links = visible
    result.endpoints_extracted = sorted(all_endpoints)
    result.routes_extracted = sorted(all_routes)

    # Phase 8: diff
    unlinked_eps, unlinked_routes = compute_diff(visible, list(all_endpoints), list(all_routes))
    result.unlinked_endpoints = unlinked_eps
    result.unlinked_routes = unlinked_routes
    log.add(phase="diff", tool="internal",
            note=f"{len(unlinked_eps)} unlinked endpoints, "
                 f"{len(unlinked_routes)} unlinked routes")

    # Phase 9: optional fuzz
    if args.fuzz:
        print(f"[*] Active fuzzing with {args.wordlist} against {args.fuzz_paths}")
        if ffuf_available:
            print(f"    using external ffuf: {ffuf_bin}")
            hits = fuzz_with_ffuf(args.target, args.wordlist, args.fuzz_paths,
                                  ffuf_bin, args.rate_limit, log, output_dir)
        else:
            print("    using internal fuzzer (ffuf not found)")
            hits = fuzz_internal(args.target, args.wordlist, session,
                                 args.fuzz_paths, log)
        result.fuzz_hits = hits
        print(f"[+] {len(hits)} active hits")

    # Phase 10: report
    result.logs = log.to_dicts()
    result.tools_used = sorted(log.tools_used)

    print()
    print("=" * 70)
    print("SCAN COMPLETE")
    print("=" * 70)
    print(f"Target:              {result.target}")
    print(f"Architecture:        {result.architecture}")
    print(f"Framework:           {result.framework_detected or 'Unknown'} {result.framework_version or ''}")
    print(f"Tools used:          {', '.join(result.tools_used) or 'none'}")
    print(f"JS bundles:          {len(result.bundles_discovered)}")
    print(f"Source maps exposed: {len(result.source_maps_found)}")
    print(f"Visible links:       {len(result.visible_links)}")
    print(f"Crawled pages:       {len(result.crawled_pages)}")
    print(f"Forms discovered:    {len(result.forms_found)}")
    print(f"Endpoints found:     {len(result.endpoints_extracted)}")
    print(f"Routes found:        {len(result.routes_extracted)}")
    print(f"Unlinked endpoints:  {len(result.unlinked_endpoints)}")
    print(f"Unlinked routes:     {len(result.unlinked_routes)}")
    print(f"Log entries:         {len(result.logs)}")
    if args.fuzz:
        print(f"Fuzz hits:           {len(result.fuzz_hits)}")

    if result.unlinked_routes:
        print()
        print("UNLINKED SPA ROUTES (highest-priority leads):")
        for r in result.unlinked_routes:
            print(f"  - {r}")

    json_path, txt_path = write_reports(result, output_dir)
    html_path = write_html_report(result, output_dir)
    print()
    print(f"[+] HTML report:  {html_path}")
    print(f"[+] JSON report:  {json_path}")
    print(f"[+] Text summary: {txt_path}")
    print(f"[+] Bundles saved to: {output_dir}/")
    print()
    print("REMEMBER: The unlinked-route list is a starting point, not a finding")
    print("list. Manually navigate to each one and verify what it exposes before")
    print("reporting to the client.")


if __name__ == "__main__":
    main()
