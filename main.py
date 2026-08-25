#!/usr/bin/env python3
"""
main.py -- Seekore (CLI Orchestrator)

Seekore is a Threat Intelligence Web Scraper that extracts Indicators of
Compromise (IOCs) from security blogs.

This script does NOT contain any scraping, parsing, or file-I/O logic
itself. Its only job is to:

    1. Load the active target sources from sources.json
    2. Run the scan (delegated to skills.scanner)
    3. Write the resulting report to disk
    4. Print a final summary

All real logic lives in the /skills modules:
    skills/web_scraper.py  -> HTTP fetching + HTML-to-text
    skills/regex_parser.py -> IOC extraction (IPv4 / SHA256 / defanged IPs)
    skills/scanner.py      -> per-source scanning + report assembly (shared with gui.py)
    skills/file_handler.py -> reading config / writing the report

A graphical alternative to this CLI is available in gui.py -- it uses the
exact same skills.scanner logic, just with a Tkinter front-end instead of
a terminal. Run `python3 gui.py` if you'd prefer that.

Usage:
    python3 main.py
"""

import logging
import sys

from skills.file_handler import ensure_output_dir, load_sources, save_json_report
from skills.scanner import run_full_scan

# ---------------------------------------------------------------------------
# Logging: a single, timestamped, human-readable stream for operators to
# watch during a run. Individual skills log to their own named loggers
# (e.g. "ThreatIntelScraper.web_scraper") so the source of any message is
# always clear, but they all share this one configuration.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ThreatIntelScraper.main")

# ---------------------------------------------------------------------------
# The only two "paths" in this whole project -- everything else (which
# sites to scrape) lives in sources.json, per the "no hardcoded URLs" rule.
# ---------------------------------------------------------------------------
SOURCES_CONFIG_PATH = "sources.json"
OUTPUT_REPORT_PATH = "output/ioc_report.json"


def main():
    logger.info("=== Threat Intelligence Scraper -- run started ===")
    ensure_output_dir("output")

    # -------------------------------------------------------------------
    # Load sources dynamically. Any error here (missing file, invalid
    # JSON, missing "sources" key) is treated as fatal -- there's nothing
    # useful to scrape without a valid config -- so we log and exit(1)
    # cleanly rather than raising an ugly traceback at the user.
    # -------------------------------------------------------------------
    try:
        all_sources = load_sources(SOURCES_CONFIG_PATH)
    except (FileNotFoundError, ValueError) as e:
        logger.critical(f"Could not load sources config: {e}")
        sys.exit(1)

    active_sources = [s for s in all_sources if s.get("active", True)]
    logger.info(
        f"{len(active_sources)} active source(s) out of {len(all_sources)} configured in {SOURCES_CONFIG_PATH}"
    )

    if not active_sources:
        logger.warning("No active sources to scan. Check the 'active' flags in sources.json. Exiting.")
        sys.exit(0)

    # -------------------------------------------------------------------
    # Scrape every active source and assemble the report. A failure on any
    # single source (dead link, 403, timeout) is captured in its own
    # result entry and does NOT stop the run -- the rest still get scanned.
    # -------------------------------------------------------------------
    report = run_full_scan(active_sources, total_configured=len(all_sources))
    save_json_report(report, OUTPUT_REPORT_PATH)

    meta = report["scan_metadata"]
    logger.info(
        f"Done. {meta['sources_succeeded']} source(s) succeeded, {meta['sources_failed']} failed, "
        f"{meta['total_unique_iocs']} unique IOC(s) extracted."
    )
    logger.info("=== Threat Intelligence Scraper -- run finished ===")


if __name__ == "__main__":
    main()
