# BBPathInspection — Attack Surface Mapper

Automated reconnaissance for **any web app architecture** (SPA or classic).
Finds the unlinked attack surface a normal user never sees: hidden routes,
unreferenced API endpoints, leaked source maps, and fuzz-discovered paths.

> **Use only on systems you own or have written authorization to test.**
> Unauthorized testing violates the Computer Fraud and Abuse Act
> (18 U.S.C. § 1030) and analogous statutes worldwide.

---

## What it does

Given a target URL, the script runs an end-to-end pipeline:

1. **Fetches the homepage** and parses the HTML.
2. **Detects the SPA framework** (Angular, React, Vue, Next.js, Nuxt, Svelte) from HTML markers.
3. **Discovers JS bundles** referenced by `<script src=...>`.
4. **Probes for source maps** (`.map` files) — a real OWASP A02:2025 finding when exposed.
5. **Extracts endpoints** from each bundle:
   - Uses the bundled **LinkFinder** (`./LinkFinder/linkfinder.py`) when available
   - Falls back to an internal LinkFinder-style regex
6. **Extracts SPA routes** from bundles using framework-specific regex.
7. **Crawls the site** (same-origin BFS over `<a href>` + forms) when the
   target isn't a pure SPA, or when `--crawl-depth > 0`. Captures inline-script
   endpoints and form actions/inputs along the way.
8. **Fuzzes API path prefixes** with a wordlist (optional):
   - Uses the bundled **ffuf** (`./ffuf/ffuf`) when available
   - Falls back to an internal Python fuzzer
9. **Diffs** discovered endpoints/routes against the visible-link baseline and
   reports the **unlinked** surface — your highest-priority leads.
10. **Writes reports**: a self-contained HTML report (with copy-as-curl
    buttons, base-URL rewriter, and full tool execution log), plus JSON
    and text summaries.

## What it's for

- **Bug bounty recon**: rapidly enumerate hidden routes and API endpoints across any target tech stack.
- **Pentest scoping**: build an attack-surface inventory before manual testing.
- **Source-map disclosure audits**: confirm whether production builds leak `.map` files.
- **CTF / training**: works out-of-the-box against OWASP Juice Shop and similar SPA targets.

---

## Layout

```
BBPathInspection/
├── attack_surface_mapper.py   # the script
├── ffuf/                      # (optional) drop ffuf binary here
│   └── ffuf
├── LinkFinder/                # (optional) clone LinkFinder here
│   └── linkfinder.py
└── README.md
```

If `ffuf/ffuf` or `LinkFinder/linkfinder.py` are missing, the script transparently falls back to internal implementations — it never breaks.

---

## Installation

### Dependencies (one-time)

```bash
pip install requests beautifulsoup4
```

### Optional external tools

The script runs fine on its own (internal regex extraction + Python fuzzer), but pairs better with the real tools when present:

```bash
# LinkFinder — endpoint extraction
git clone https://github.com/GerbenJavado/LinkFinder.git
pip install -r LinkFinder/requirements.txt

# ffuf — active fuzzing
# https://github.com/ffuf/ffuf/releases — drop the binary at ./ffuf/ffuf
```

Or point the script at existing installs with `--linkfinder-path` and `--ffuf-path`.

### Optional: make the script executable from anywhere

```bash
chmod +x attack_surface_mapper.py
```

---

## Usage

Run from the project folder so `./ffuf/ffuf` and `./LinkFinder/linkfinder.py` are auto-detected if you installed them:

```bash
cd BBPathInspection
python3 attack_surface_mapper.py <TARGET_URL> [options]
```

The first time you scan a target, an **authorization prompt** appears.
Type `yes` to confirm. Use `--no-consent` to skip in scripts/CI.

### Common command recipes

| Goal | Command |
|---|---|
| **SPA scan (Juice Shop, etc.)** | `python3 attack_surface_mapper.py http://localhost:3000` |
| **Classic / unknown site** | `python3 attack_surface_mapper.py https://example.com --crawl-depth 2` |
| **Deep crawl** | `python3 attack_surface_mapper.py https://target.tld --crawl-depth 3 --crawl-pages 100` |
| **With active fuzzing** | `python3 attack_surface_mapper.py http://localhost:3000 --fuzz --wordlist /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt` |
| **Behind a login** | `python3 attack_surface_mapper.py https://target.tld --cookie "session=abc123"` |
| **Custom header(s)** | `python3 attack_surface_mapper.py https://target.tld --header "X-API-Key: foo" --header "X-Forwarded-For: 127.0.0.1"` |
| **Slow & stealthy** | `python3 attack_surface_mapper.py https://target.tld --rate-limit 1000` |
| **Custom API prefixes to fuzz** | `python3 attack_surface_mapper.py https://target.tld --fuzz --wordlist wl.txt --fuzz-paths /api/ /rest/ /v2/ /graphql/` |
| **Force internal-only (no ffuf/LinkFinder)** | `python3 attack_surface_mapper.py http://localhost:3000 --no-external-tools` |
| **Unattended / CI** | `python3 attack_surface_mapper.py http://localhost:3000 --no-consent --output ./scan_results` |

### All flags

```
target                      Target URL (positional, required)

--output DIR                Output directory (default: asm_output)
--crawl-depth N             Same-origin crawl depth from homepage (default: 1; 0 = homepage only)
--crawl-pages N             Max pages to crawl (default: 40)

--fuzz                      Enable active API path fuzzing
--wordlist PATH             Wordlist for --fuzz (required if --fuzz)
--fuzz-paths P [P ...]      API path prefixes to fuzz (default: /api/ /rest/ /v1/)

--cookie VALUE              Cookie header for every request
--header "Name: value"      Extra request header (repeatable)
--user-agent STRING         Override the User-Agent

--ffuf-path PATH            Path to ffuf binary (default: ./ffuf/ffuf)
--linkfinder-path PATH      Path to linkfinder.py (default: ./LinkFinder/linkfinder.py)
--no-external-tools         Force internal regex/fuzzer; ignore bundled ffuf/LinkFinder

--rate-limit MS             Delay between requests in ms (default: 100)
--timeout SEC               Per-request timeout in seconds (default: 10)

--no-consent                Skip the interactive authorization prompt
-h, --help                  Show help
```

---

## Output

After a scan completes, the output directory (`asm_output/` by default) contains:

| File | Purpose |
|---|---|
| `report.html` | **Open this first.** Self-contained HTML report with: collapsible Tool Execution Log (every HTTP fetch + subprocess call, with stdout/stderr/exit code/duration), suspicious-keyword highlighting, copy-as-curl buttons, live base-URL rewriter. |
| `scan_report.json` | Full machine-readable result — useful for piping into other tools or diffing across runs. |
| `summary.txt` | Plain-text summary of findings. |
| `<bundle-name>.js` | Each downloaded JS bundle is saved here for offline analysis. |
| `ffuf_<prefix>.json` | Raw ffuf JSON output per fuzzed prefix (only with `--fuzz`). |

### What to look at first

1. **Source Maps Exposed** section — if non-empty, that's an immediate finding.
2. **Unlinked SPA Routes** — admin panels, dev/debug routes, internal tools.
3. **Suspicious-flagged rows** (red highlight, ⚠ icon) — names matching keywords like `admin`, `debug`, `internal`, `secret`, `actuator`, `swagger`, etc.
4. **Tool Execution Log** — click any row to expand and see what each tool actually returned. Useful when results look thin.

---

## Examples

### Scan OWASP Juice Shop

```bash
docker run --rm -d -p 3000:3000 bkimminich/juice-shop
python3 attack_surface_mapper.py http://localhost:3000 --no-consent
xdg-open asm_output/report.html
```

Expect: ~3 bundles, ~3 source maps exposed, ~44 SPA routes including `score-board`, `administration`, `web3-sandbox`, ~190 endpoints.

### Recon a target with auth + active fuzzing

```bash
python3 attack_surface_mapper.py https://app.target.tld \
    --cookie "session=eyJ..." \
    --header "X-Forwarded-For: 127.0.0.1" \
    --crawl-depth 2 \
    --fuzz --wordlist /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    --fuzz-paths /api/ /rest/ /v1/ /v2/ /graphql/ \
    --rate-limit 250 \
    --output ./target_scan
```

---

## Limitations (be honest)

- **The script does not render the page.** It cannot replicate a human walking a logged-in SPA. The visible-link baseline comes from `<a href>` tags in initial HTML + crawled pages — it understates what a real user would see. For comprehensive testing, **proxy through Burp Suite** and use the HTTP history as your baseline instead of relying solely on this tool's diff.
- **Regex extraction has false positives.** The output is a starting point for manual review, not a finished finding list.
- **Active fuzzing sends real traffic.** Only enable on authorized targets with appropriate `--rate-limit` settings.
- **File-based-routing frameworks** (Next.js, Nuxt, Svelte) don't expose routes through bundle regex. The script flags this in the report — you'll need source map disclosure or build-manifest inspection to enumerate their routes.

---

## Acknowledgments

- **LinkFinder** by Gerben Javado — endpoint extraction (MIT)
  https://github.com/GerbenJavado/LinkFinder
- **ffuf** by Joohoi — fast web fuzzer (MIT)
  https://github.com/ffuf/ffuf

Framework fingerprints verified against the official Angular, React, Vue, and Next.js detection sources.
