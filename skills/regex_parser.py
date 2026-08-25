"""
skills/regex_parser.py

All Indicator of Compromise (IOC) pattern matching lives here. Keeping the
regex patterns as module-level constants (instead of burying them inline
in main.py) makes them easy to unit test, tune, and extend independently
of the scraping/orchestration logic.

IOC types handled:
    1. Standard IPv4 addresses        e.g. 192.168.1.1
    2. SHA256 hashes                  e.g. 64 hex characters
    3. Defanged IPv4 addresses        e.g. 192[.]168.1.1  or 192.168.1[.]1
"""

import re

# ---------------------------------------------------------------------------
# Building block: a single IPv4 octet (0-255), reused by every pattern below.
# Non-capturing group so it doesn't interfere with findall()'s return shape.
# ---------------------------------------------------------------------------
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"

# ---------------------------------------------------------------------------
# 1) Standard IPv4 address: four octets joined by literal dots.
# ---------------------------------------------------------------------------
IPV4_PATTERN = re.compile(r"\b" + r"\.".join([_OCTET] * 4) + r"\b")

# ---------------------------------------------------------------------------
# 2) SHA256 hash: exactly 64 hex characters, word-boundary bounded so it
#    can't match as a substring of a longer hex blob (e.g. a SHA512 hash).
# ---------------------------------------------------------------------------
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

# ---------------------------------------------------------------------------
# 3) Defanged IPv4 address.
#
# Analysts "defang" IOCs in write-ups so the address can't be accidentally
# clicked, pinged, or auto-linked by an email client. Common substitutions
# for the "." separator include:
#     [.]     e.g. 192[.]168[.]1[.]1
#     (.)     e.g. 192(.)168(.)1(.)1
#     [dot]   e.g. 192[dot]168[dot]1[dot]1
#
# Real-world write-ups often only defang ONE octet of an address (e.g.
# "192.168.1[.]1" or "192[.]168.1.1"), so each of the three separators in
# the pattern is independently allowed to be EITHER a defanged style OR a
# plain "." -- that's what lets partially-defanged IOCs match in full.
# ---------------------------------------------------------------------------
_DEFANGED_SEP = r"(?:\[\.\]|\(\.\)|\[dot\]|\.)"

DEFANGED_IP_PATTERN = re.compile(
    r"\b" + _OCTET + (_DEFANGED_SEP + _OCTET) * 3 + r"\b",
    re.IGNORECASE,
)


def extract_ipv4_addresses(text):
    """Return every plain (non-defanged) IPv4 address found in `text`."""
    return IPV4_PATTERN.findall(text)


def extract_sha256_hashes(text):
    """Return every SHA256 hash found in `text`."""
    return SHA256_PATTERN.findall(text)


def extract_defanged_ips(text):
    """
    Return every IP-like string in `text` that contains at least one
    defanged separator ([.], (.), or [dot]).

    Matches that turn out to be FULLY plain (e.g. "192.168.1.1", which the
    pattern above can also match because "." is one of the allowed
    separators) are filtered out here, since extract_ipv4_addresses()
    already captures those -- returning them again would just create
    duplicate work for the caller.
    """
    defanged_matches = []
    for match in DEFANGED_IP_PATTERN.finditer(text):
        candidate = match.group(0)
        if "[" in candidate or "(" in candidate:
            defanged_matches.append(candidate)
    return defanged_matches


def refang_ip(defanged_ip):
    """
    Convert a defanged IP string back into standard dotted-decimal form.

    Examples:
        "192[.]168[.]1[.]1"  -> "192.168.1.1"
        "192(.)168(.)1(.)1"  -> "192.168.1.1"
        "192[dot]168.1[.]1"  -> "192.168.1.1"
    """
    refanged = defanged_ip
    refanged = refanged.replace("[.]", ".")
    refanged = refanged.replace("(.)", ".")
    refanged = re.sub(r"\[dot\]", ".", refanged, flags=re.IGNORECASE)
    return refanged
