"""
skills/web_scraper.py

Responsible for ALL network I/O and HTML-to-text conversion.

Isolating this logic here means the rest of the application (main.py,
regex_parser.py) never has to know anything about requests, sessions,
headers, retries, or BeautifulSoup internals. It just calls fetch_page()
and extract_visible_text() and gets back simple strings (or None).
"""

import logging
import threading

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("ThreatIntelScraper.web_scraper")

# ---------------------------------------------------------------------------
# A realistic browser User-Agent avoids basic bot filters that auto-reject
# Python's default "python-requests/x.x.x" User-Agent string. We also send
# a couple of other common browser headers so the request looks less like
# an obvious script and more like a normal page load.
# ---------------------------------------------------------------------------
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

REQUEST_TIMEOUT = 15  # seconds -- fail fast instead of hanging on a dead source


def _build_session():
    """
    Build a requests.Session configured with automatic retries for
    transient, server-side failures (500/502/503/504) and a short
    exponential backoff between attempts.

    Client errors like 403 (Forbidden) or 404 (Not Found) are NOT in the
    retry list on purpose -- retrying a hard block or a genuinely missing
    page just wastes time and hammers the target site.
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=2,                                   # 2 retries = 3 attempts total
        backoff_factor=1.5,                         # 0s, 1.5s, 3s between tries
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# One session per thread, created lazily and reused for every request that
# thread makes -- this keeps the underlying TCP connections alive
# (keep-alive) across sources for speed. requests.Session is not guaranteed
# thread-safe, and skills/scanner.py now scans sources concurrently, so
# each worker thread gets its own session instead of sharing one.
_THREAD_LOCAL = threading.local()


def _get_session():
    session = getattr(_THREAD_LOCAL, "session", None)
    if session is None:
        session = _build_session()
        _THREAD_LOCAL.session = session
    return session


def fetch_page(url):
    """
    Fetch raw HTML from `url`.

    Returns:
        str:  the page's HTML on success.
        None: on ANY failure. The specific reason (403, dead link, timeout,
              DNS failure, etc.) is logged for the operator, but callers
              only need to know "did this work or not" -- a single bad
              source should never crash the whole scan.
    """
    try:
        response = _get_session().get(url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()  # raises HTTPError for 4xx/5xx status codes
        return response.text

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "unknown"
        if status == 403:
            logger.warning(f"403 Forbidden -- site is likely blocking scrapers: {url}")
        elif status == 404:
            logger.warning(f"404 Not Found -- dead/removed link: {url}")
        else:
            logger.warning(f"HTTP {status} error for {url}: {e}")

    except requests.exceptions.ConnectionError:
        logger.warning(f"Connection error (DNS failure, dead host, or refused connection): {url}")

    except requests.exceptions.Timeout:
        logger.warning(f"Request timed out after {REQUEST_TIMEOUT}s: {url}")

    except requests.exceptions.RequestException as e:
        # Catch-all for anything else requests can throw (bad redirects,
        # SSL errors, etc.) so an unexpected edge case still degrades
        # gracefully instead of crashing the whole run.
        logger.warning(f"Unexpected request error for {url}: {e}")

    return None


def extract_visible_text(html):
    """
    Convert raw HTML into plain, human-readable text using BeautifulSoup.

    We strip <script>, <style>, and <noscript> tags before extracting text
    because their contents are never "visible" to a reader -- and, more
    importantly for us, minified JavaScript often contains long hex
    strings that could otherwise false-positive as SHA256 hashes.
    """
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    # separator=" " stops text from adjacent tags (e.g. "<p>a</p><p>b</p>")
    # from being glued together into "ab" with no space between them.
    text = soup.get_text(separator=" ", strip=True)
    return text
