"""
skills package

This package contains the individual, single-responsibility modules
("skills") that main.py orchestrates:

    - web_scraper.py   -> HTTP fetching + HTML-to-text extraction
    - regex_parser.py  -> IOC pattern matching (IPv4, SHA256, defanged IPs)
    - file_handler.py  -> reading sources.json / writing the JSON report

Keeping these separate means each one can be tested, replaced, or extended
in isolation without touching the orchestration logic in main.py.
"""
