"""
skills/scanner.py

The core "scan one source, then build a full report" logic.

This was pulled out of main.py so that BOTH front-ends -- the CLI
(main.py) and the desktop GUI (gui.py) -- call the exact same functions.
Without this shared module, a GUI would either have to duplicate the
scanning logic (risking the two front-ends drifting out of sync as the
project evolves) or the CLI would have to import from gui.py (dragging a
Tkinter dependency into headless/server use of the CLI). Putting it here
avoids both problems.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from skills.regex_parser import (
    extract_defanged_ips,
    extract_ipv4_addresses,
    extract_sha256_hashes,
    refang_ip,
)
from skills.web_scraper import extract_visible_text, fetch_page

logger = logging.getLogger("ThreatIntelScraper.scanner")


def process_source(source):
    """
    Scrape a single source and return (url, result_dict).

    result_dict always has a "status" of either "success" or "failed" so
    the final report clearly shows which sources worked and which didn't
    (dead link, 403, timeout, etc.) without crashing the overall run.
    """
    url = source.get("url", "")
    name = source.get("name", url)

    logger.info(f"Scanning: {name} ({url})")

    result = {
        "source_name": name,
        "status": "failed",
        "error": None,
        "ipv4_addresses": [],
        "sha256_hashes": [],
        "defanged_ips_refanged": [],
    }

    if not url:
        result["error"] = "Source entry is missing a 'url' field."
        logger.error(f"Skipping malformed source entry: {source}")
        return url, result

    # --- Step 1: fetch the raw HTML (returns None on any failure) ----------
    html = fetch_page(url)
    if html is None:
        result["error"] = "Failed to retrieve content -- see log line above for the specific reason."
        return url, result

    # --- Step 2: strip HTML down to plain visible text ----------------------
    text = extract_visible_text(html)

    # --- Step 3: extract each IOC type via regex -----------------------------
    plain_ips = set(extract_ipv4_addresses(text))

    defanged_raw = extract_defanged_ips(text)
    refanged_ips = set(refang_ip(ip) for ip in defanged_raw)

    # A refanged IP IS a standard IPv4 address, so we fold it into the same
    # set. This is also where "192.168.1[.]1" and "192[.]168.1.1" for the
    # SAME underlying address collapse into a single deduplicated entry.
    all_ips = plain_ips.union(refanged_ips)

    hashes = set(extract_sha256_hashes(text))

    result.update(
        {
            "status": "success",
            "ipv4_addresses": sorted(all_ips),
            "sha256_hashes": sorted(hashes),
            "defanged_ips_refanged": sorted(refanged_ips),
        }
    )

    logger.info(
        f"  -> {len(all_ips)} IPv4 IOC(s), {len(hashes)} SHA256 hash(es) "
        f"({len(refanged_ips)} were defanged) found on {name}"
    )
    return url, result


def build_ioc_mapping(results_by_source):
    """
    Build a reverse index: IOC value -> list of source URLs it appeared on.

    This is the "map IOCs to their specific source URLs" deliverable --
    it lets an analyst instantly see whether an indicator showed up on
    just one blog or was corroborated across multiple independent sources.
    """
    ioc_to_source_mapping = {}

    for url, result in results_by_source.items():
        if result["status"] != "success":
            continue

        all_iocs = result["ipv4_addresses"] + result["sha256_hashes"]
        for ioc in all_iocs:
            sources_for_ioc = ioc_to_source_mapping.setdefault(ioc, [])
            if url not in sources_for_ioc:
                sources_for_ioc.append(url)

    return ioc_to_source_mapping


def run_full_scan(active_sources, total_configured, max_workers=5, progress_callback=None, cancel_event=None):
    """
    Run process_source() over every active source and assemble the final
    report dict (metadata + per-source results + IOC reverse index).

    Sources are fetched CONCURRENTLY (up to `max_workers` at a time) --
    scraping is almost entirely network-bound waiting, so scanning several
    slow blogs in parallel cuts total wall-clock time dramatically without
    hammering any single site (each individual source still gets exactly
    one polite request).

    Optional hooks (both used by gui.py, both safe to omit from the CLI):
        progress_callback(completed_count, total_count, url, result)
            Called from worker threads as each source finishes. Callers
            that update a UI must marshal this onto their UI thread
            themselves (the GUI does this via a queue).
        cancel_event (threading.Event)
            If set mid-scan, sources that haven't started yet are skipped
            (in-flight requests still finish). Skipped sources are simply
            absent from the report, and scan_metadata["cancelled"] is True.

    This does NOT write the report to disk -- callers (main.py, gui.py)
    decide when/whether to persist it, which keeps this function usable
    in contexts (like a future "dry run" mode) that don't want a file
    written at all.
    """
    total = len(active_sources)
    # Pre-seed with None per source position so the final report preserves
    # the configured source order even though completion order is arbitrary.
    results_by_position = [None] * total
    completed = 0

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, total))) as executor:
        future_to_position = {}
        for position, source in enumerate(active_sources):
            if cancel_event is not None and cancel_event.is_set():
                break
            future_to_position[executor.submit(process_source, source)] = position

        for future in as_completed(future_to_position):
            position = future_to_position[future]
            url, result = future.result()
            results_by_position[position] = (url, result)
            completed += 1
            if progress_callback is not None:
                progress_callback(completed, total, url, result)

    results_by_source = {}
    for entry in results_by_position:
        if entry is not None:
            url, result = entry
            results_by_source[url] = result

    ioc_to_source_mapping = build_ioc_mapping(results_by_source)
    successful = sum(1 for r in results_by_source.values() if r["status"] == "success")
    scanned = len(results_by_source)
    unique_ips = set()
    unique_hashes = set()
    for r in results_by_source.values():
        unique_ips.update(r["ipv4_addresses"])
        unique_hashes.update(r["sha256_hashes"])

    report = {
        "scan_metadata": {
            "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "total_sources_configured": total_configured,
            "total_sources_scanned": scanned,
            "sources_succeeded": successful,
            "sources_failed": scanned - successful,
            "total_unique_iocs": len(ioc_to_source_mapping),
            "total_unique_ipv4": len(unique_ips),
            "total_unique_sha256": len(unique_hashes),
            "cancelled": bool(cancel_event is not None and cancel_event.is_set()),
        },
        "results_by_source": results_by_source,
        "ioc_to_source_mapping": ioc_to_source_mapping,
    }
    return report
