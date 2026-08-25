"""
skills/file_handler.py

Handles all filesystem I/O for the scraper:
    - Reading the dynamic sources configuration (sources.json)
    - Writing the final structured IOC report (output/ioc_report.json)

Isolating this here means swapping storage formats later (e.g. loading
sources from a database, or emitting a CSV report instead of JSON) only
ever touches this one file -- main.py and the other skills stay unchanged.
"""

import json
import logging
import os

logger = logging.getLogger("ThreatIntelScraper.file_handler")


def load_sources(config_path):
    """
    Load the list of target sources from a JSON configuration file.

    Expected format:
        {
            "sources": [
                {"name": "Example Blog", "url": "https://example.com", "active": true},
                ...
            ]
        }

    This is the mechanism that satisfies "no hardcoded URLs" -- a user adds,
    edits, removes, or disables (via "active": false) a target simply by
    editing this JSON file. No Python code ever needs to change.

    Raises:
        FileNotFoundError: if the config file doesn't exist.
        ValueError: if the file exists but isn't valid JSON, or is missing
                    the required "sources" array.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(
            f"Sources config not found at '{config_path}'. "
            f"Create it -- see sources.json in the project root for the expected format."
        )

    with open(config_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"'{config_path}' is not valid JSON: {e}")

    sources = data.get("sources")
    if sources is None:
        raise ValueError(f"'{config_path}' is missing the required 'sources' array.")

    return sources


def save_sources(sources, config_path):
    """
    Write the list of source dicts back to `config_path` in the same
    {"sources": [...]} format that load_sources() reads.

    Used by the GUI's "Save to disk" action so the on-disk format is
    defined in exactly one place (here, next to load_sources).
    """
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump({"sources": sources}, f, indent=2, ensure_ascii=False)
        f.write("\n")
    logger.info(f"Sources config written: {config_path} ({len(sources)} source(s))")


def ensure_output_dir(dir_path):
    """Create `dir_path` (and any missing parent directories) if needed."""
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)


def save_json_report(data, output_path):
    """
    Write `data` to `output_path` as pretty-printed, UTF-8 JSON.

    Creates the parent directory automatically if it doesn't exist yet, so
    callers don't need to remember to call ensure_output_dir() themselves.
    """
    ensure_output_dir(os.path.dirname(output_path))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    size_bytes = os.path.getsize(output_path)
    logger.info(f"Report written: {output_path} ({size_bytes:,} bytes)")
