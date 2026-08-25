# Seekore

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Seekore** is a lightweight, modular Python tool that scrapes security
blogs and threat reports for **Indicators of Compromise (IOCs)** — IPv4
addresses (including "defanged" ones like `192[.]168.1.1`) and SHA256
hashes — and outputs them as a structured JSON report mapping every IOC
back to the source(s) it was found on.

Built for SOC analysts, threat intel teams, and anyone who wants a
repeatable, no-code-editing way to sweep a rotating list of blogs for
freshly published indicators.

---

## Features

- **Two front-ends, one shared engine** — a desktop GUI (`gui.py`) for
  point-and-click use, and a CLI (`main.py`) for scripting/cron. Both call
  the exact same `skills/scanner.py` logic, so they never behave differently.
- **Concurrent scanning** — sources are fetched in parallel (up to 5 at a
  time, one polite request per source), so a full run takes roughly as long
  as the *slowest* source instead of the *sum* of all of them. Scans can
  also be cancelled mid-run (the GUI's **Stop** button).
- **Bot-resistant fetching** — sends realistic browser headers (User-Agent,
  Accept, Accept-Language) so requests aren't trivially blocked, plus
  automatic retries with backoff for transient server errors.
- **Clean text extraction** — uses BeautifulSoup to strip HTML markup,
  scripts, and stylesheets down to plain, readable text before scanning it.
- **IOC extraction via regex**:
  - Standard IPv4 addresses (`8.8.8.8`)
  - SHA256 hashes (64 hex characters)
  - **Defanged IPv4 addresses**, including partially-defanged and mixed
    styles: `192[.]168.1.1`, `192.168.1[.]1`, `192(.)168(.)1(.)1`,
    `192{.}168{.}1{.}1`, `192[dot]168[dot]1[dot]1`, `192(dot)168(dot)1(dot)1`
  - Longer dotted sequences (e.g. the version string `1.2.3.4.5`) are
    **not** mis-detected as IPv4 addresses.
- **Automatic refanging** — defanged IPs are converted back to standard
  dotted-decimal form and merged with plain IPs, so the same underlying
  address is never counted (or reported) twice.
- **Deduplication** — every IOC is deduplicated per source and globally.
- **Zero hardcoded URLs** — all targets live in `sources.json`. Add, edit,
  remove, or temporarily disable a blog without touching a single line of
  Python — either by hand-editing the file or through the GUI's Sources panel.
- **Graceful failure handling** — a dead link, a `403 Forbidden`, a
  timeout, or an unreachable host on one source is logged and recorded in
  the report, but never crashes the run or blocks the remaining sources.
- **Structured JSON output** — a full audit trail (`ioc_report.json`) with
  per-source results plus a reverse index of IOC → source URLs.

---

## Project Structure

```
Seekore/
├── main.py                  # CLI orchestrator — thin wrapper around skills.scanner.
├── gui.py                   # Desktop GUI (Tkinter) — same engine, point-and-click front-end.
├── sources.json             # Dynamic target list — the ONLY file you edit to add/remove blogs.
├── requirements.txt         # Python dependencies.
├── README.md                # This file.
├── skills/
│   ├── __init__.py
│   ├── web_scraper.py       # HTTP fetching (headers, retries, error handling) + HTML-to-text.
│   ├── regex_parser.py      # IOC regex patterns: IPv4, SHA256, defanged IPs, and the refang() function.
│   ├── scanner.py           # Shared scan engine: process_source() + run_full_scan(). Used by BOTH main.py and gui.py.
│   └── file_handler.py      # Reads/writes sources.json, writes the JSON report.
├── tests/
│   ├── test_regex_parser.py # Unit tests for the IOC extraction patterns.
│   └── test_scanner.py      # Unit tests for the scan engine (network mocked out).
└── output/
    └── ioc_report.json      # Generated automatically after each run (CLI or GUI).
```

---

## Installation

Requires Python 3.8+.

```bash
# 1. Clone or copy the project, then move into it
cd Seekore

# 2. (Recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

**GUI users on minimal Linux installs:** Tkinter is part of the Python
standard library, but some minimal distros (e.g. slim Docker images)
ship Python without it. If `python3 gui.py` fails with
`ModuleNotFoundError: No module named 'tkinter'`, install it with:

```bash
sudo apt-get install python3-tk      # Debian/Ubuntu
sudo dnf install python3-tkinter     # Fedora
```

No such step is needed on Windows or macOS — Tkinter is bundled with the
standard python.org installer there.

---

## Configuring Sources (`sources.json`)

This is the **only file you need to touch** to change what gets scraped.
No Python code is ever hardcoded with URLs.

```json
{
  "sources": [
    {
      "name": "The Hacker News",
      "url": "https://thehackernews.com/",
      "active": true
    },
    {
      "name": "Dark Reading",
      "url": "https://www.darkreading.com/threat-intelligence",
      "active": false
    }
  ]
}
```

| Field    | Required | Description                                                                 |
|----------|----------|-------------------------------------------------------------------------------|
| `name`   | No       | Friendly label used in logs and the report. Falls back to the URL if omitted. |
| `url`    | Yes      | The page to scrape.                                                           |
| `active` | No       | `true`/`false`. Set to `false` to temporarily disable a source without deleting it. Defaults to `true` if omitted. |

**To add a source:** append a new object to the `sources` array.
**To remove a source:** delete its object (or just set `"active": false`).
**To pause a source:** set `"active": false` — it stays in the file for later, but the scraper skips it.

---

## Running the Scraper

```bash
python3 main.py
```

You'll see live progress in the terminal:

```
2026-08-23 10:00:00 | INFO | ThreatIntelScraper.main | 3 active source(s) out of 4 configured in sources.json
2026-08-23 10:00:00 | INFO | ThreatIntelScraper.main | Scanning: The Hacker News (https://thehackernews.com/)
2026-08-23 10:00:01 | INFO | ThreatIntelScraper.main |   -> 4 IPv4 IOC(s), 2 SHA256 hash(es) (1 were defanged) found on The Hacker News
2026-08-23 10:00:01 | INFO | ThreatIntelScraper.main | Scanning: Krebs on Security (https://krebsonsecurity.com/)
2026-08-23 10:00:02 | WARNING | ThreatIntelScraper.web_scraper | 403 Forbidden -- site is likely blocking scrapers: https://krebsonsecurity.com/
...
2026-08-23 10:00:03 | INFO | ThreatIntelScraper.file_handler | Report written: output/ioc_report.json (2,412 bytes)
```

The finished report is written to `output/ioc_report.json`.

---

## Running the GUI (recommended for interactive use)

```bash
python3 gui.py
```

This opens a desktop window with three parts:

**1. Sources panel (top)**
A live, editable view of `sources.json`. Select a row and click **Edit...**
or double-click it to change the name/URL/active flag; use **Add...** to
create a new one, **Remove** to delete one, or **Toggle Active** to quickly
enable/disable it. URLs entered without a scheme are automatically given
`https://`, and adding a URL that's already configured asks for
confirmation first. Changes are held in memory until you click
**Save to disk** (or press **Ctrl+S**) — the window title shows
`[unsaved changes]` until you do, and closing the window with unsaved
changes prompts you to save them. **Reload from disk** discards unsaved
changes (after confirming) and re-reads `sources.json`.

**2. Scan controls (middle)**
Click **▶ Run Scan** (or press **F5**) to scrape every currently-active
source. Sources are fetched concurrently on background threads, so the
window stays responsive even on slow or hanging sites; the progress bar
fills as each source finishes and result rows appear live, one per
completed source. **■ Stop** cancels the rest of a running scan (requests
already in flight finish first). A status bar at the very bottom
summarizes the last completed run (sources succeeded/failed, unique IOCs
by type, and the report path). **Open Output Folder** opens `output/` in
your OS's file browser.

**3. Results tabs (bottom)**
- **Live Log** — the same timestamped log lines you'd see in the terminal
  running `main.py`, streamed in live as the scan progresses. WARNING
  lines are highlighted yellow and ERROR lines red, so failures stand out.
- **Results by Source** — one row per scanned source, color-coded green
  (success) or red (failed), with counts of IPv4s/hashes found and the
  error message for any source that failed.
- **IOC → Source Mapping** — one row per unique indicator, its type
  (IPv4/SHA256), and every source URL it was found on — the same reverse
  index that's saved in `ioc_report.json`. The toolbar above the table
  lets you **search** indicators/sources as you type, filter by **type**,
  **copy** selected indicators to the clipboard (also right-click or
  Ctrl+C), and **export** the currently filtered rows to CSV or a plain
  text list.

Every column header in all three tables is clickable to sort (click again
to reverse).

Every scan run from the GUI writes the same `output/ioc_report.json` file
that `main.py` produces — the GUI is just a different way to trigger and
view the exact same underlying scan (see `skills/scanner.py`).

---

## Understanding the Output

```json
{
    "scan_metadata": {
        "scan_timestamp_utc": "2026-08-23T10:00:03.123456+00:00",
        "total_sources_configured": 4,
        "total_sources_scanned": 3,
        "sources_succeeded": 2,
        "sources_failed": 1,
        "total_unique_iocs": 6,
        "total_unique_ipv4": 5,
        "total_unique_sha256": 1,
        "cancelled": false
    },
    "results_by_source": {
        "https://thehackernews.com/": {
            "source_name": "The Hacker News",
            "status": "success",
            "error": null,
            "ipv4_addresses": ["198.51.100.23", "203.0.113.45"],
            "sha256_hashes": ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"],
            "defanged_ips_refanged": ["203.0.113.45"]
        },
        "https://krebsonsecurity.com/": {
            "source_name": "Krebs on Security",
            "status": "failed",
            "error": "Failed to retrieve content -- see log line above for the specific reason.",
            "ipv4_addresses": [],
            "sha256_hashes": [],
            "defanged_ips_refanged": []
        }
    },
    "ioc_to_source_mapping": {
        "198.51.100.23": ["https://thehackernews.com/"],
        "203.0.113.45": ["https://thehackernews.com/"],
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": ["https://thehackernews.com/"]
    }
}
```

- **`scan_metadata`** — a quick summary of the run (timing, success/failure counts, total unique IOCs).
- **`results_by_source`** — full detail per URL, including `status: "failed"` and a human-readable `error` for anything that didn't load. `defanged_ips_refanged` shows which of the reported `ipv4_addresses` originally appeared defanged in the source text.
- **`ioc_to_source_mapping`** — a reverse index: every IOC value mapped to the list of source URLs it was found on. If the same indicator shows up on two different blogs, you'll see both URLs here — useful for spotting corroborated threats.

---

## How IOC Detection Works (`skills/regex_parser.py`)

| IOC Type          | Pattern Summary                                                                 |
|--------------------|----------------------------------------------------------------------------------|
| IPv4               | Four dot-separated octets, each validated to the 0–255 range. Guarded so longer dotted sequences (e.g. the version string `1.2.3.4.5`) don't produce a bogus match. |
| SHA256             | Exactly 64 hexadecimal characters, bounded so it can't match inside a longer hex string (e.g. a SHA512 hash won't false-positive). |
| Defanged IPv4      | Same octet validation, but separators may be `.`, `[.]`, `(.)`, `{.}`, `[dot]`, or `(dot)` — independently per position, so partially-defanged addresses like `192.168.1[.]1` are still matched in full. |

After extraction, `refang_ip()` normalizes any defanged match back to
standard dotted form (`192[.]168[.]1[.]1` → `192.168.1.1`), and the result
is merged into the same IPv4 set used for plain addresses — so a defanged
and a plain mention of the same host collapse into a single deduplicated
entry.

---

## Error Handling

`skills/web_scraper.py` treats network trouble as *expected*, not
exceptional. A single bad source never stops the scan:

| Situation                     | Behavior                                                                 |
|--------------------------------|---------------------------------------------------------------------------|
| `403 Forbidden`                | Logged as a likely bot block; source marked `"status": "failed"` in the report. |
| `404 Not Found` (dead link)     | Logged and marked failed; scan continues with the next source.           |
| Connection refused / DNS failure | Logged and marked failed after a couple of quick retries.              |
| Timeout (>15s)                  | Logged and marked failed; no hanging.                                    |
| `500`/`502`/`503`/`504`         | Automatically retried (up to 2 extra attempts with backoff) before giving up. |

---

## Extending the Tool

Because logic is split into skills, adding a new IOC type (e.g. MD5
hashes, domains, or URLs) only touches `skills/regex_parser.py` and
`skills/scanner.py`:

1. Add a new compiled regex pattern (following the existing `_OCTET` /
   `SHA256_PATTERN` style) in `skills/regex_parser.py`.
2. Add an `extract_<new_type>()` function there.
3. Import and call it from `process_source()` in `skills/scanner.py`, and
   add its results to the `result` dict and to `build_ioc_mapping()`.

Because both `main.py` and `gui.py` call into `skills/scanner.py`, this
one change automatically shows up in both the CLI report and the GUI's
Results/IOC tabs — no changes needed in either front-end file, and none
needed in `web_scraper.py` or `file_handler.py` for this kind of extension.

---

## Responsible Use

- Only scrape sites you're authorized to access, and respect each site's
  `robots.txt` and Terms of Service.
- This tool makes exactly one polite request per configured source (a few
  different sites are fetched in parallel, but no single site is ever hit
  more than once per run) — it is not built for aggressive or high-volume
  crawling. If you scale it up, add rate limiting between requests.
- Intended for aggregating **publicly published** threat write-ups for
  defensive purposes (blocklisting, enrichment, correlation) — not for
  bypassing paywalls or access controls.

---

## Running the Tests

The `tests/` directory contains a unit-test suite for the IOC extraction
patterns and the scan engine. All network I/O is mocked, so the tests run
offline in well under a second and need nothing beyond the standard
library:

```bash
python3 -m unittest discover tests -v
```

---

## Quick Sanity Test

To confirm your setup works without waiting on live sites, you can point
`sources.json` at any single reachable URL you control and check that
`output/ioc_report.json` is created with a `"status": "success"` entry.
A `"status": "failed"` entry with a clear `error` message means the
network path or target site is the issue — not the scraper's parsing logic.

---

## License

MIT — see [LICENSE](LICENSE) for the full text. Use it, modify it, ship it.
