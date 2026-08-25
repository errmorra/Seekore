"""
Unit tests for skills/regex_parser.py -- the IOC extraction patterns.

Run the whole suite from the project root with:
    python3 -m unittest discover tests -v
"""

import unittest

from skills.regex_parser import (
    extract_defanged_ips,
    extract_ipv4_addresses,
    extract_sha256_hashes,
    refang_ip,
)

SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
SHA512 = (
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)


class TestIPv4Extraction(unittest.TestCase):
    def test_simple_ip(self):
        self.assertEqual(extract_ipv4_addresses("C2 at 203.0.113.45 today"), ["203.0.113.45"])

    def test_octet_range_validation(self):
        self.assertEqual(extract_ipv4_addresses("bogus 999.1.1.1 and 256.1.1.1"), [])
        self.assertEqual(extract_ipv4_addresses("edge 255.255.255.255 ok"), ["255.255.255.255"])
        self.assertEqual(extract_ipv4_addresses("zero 0.0.0.0 ok"), ["0.0.0.0"])

    def test_version_string_not_matched(self):
        """A 5-part dotted sequence like a version string must not yield a
        bogus 4-octet 'IP' from either end."""
        self.assertEqual(extract_ipv4_addresses("upgrade to version 1.2.3.4.5 now"), [])

    def test_ip_at_end_of_sentence(self):
        """A sentence-ending period right after the IP must not block the match."""
        self.assertEqual(extract_ipv4_addresses("The C2 was 203.0.113.45."), ["203.0.113.45"])

    def test_multiple_ips(self):
        text = "primary 198.51.100.23, fallback 203.0.113.45"
        self.assertEqual(extract_ipv4_addresses(text), ["198.51.100.23", "203.0.113.45"])


class TestSHA256Extraction(unittest.TestCase):
    def test_valid_hash(self):
        self.assertEqual(extract_sha256_hashes(f"payload: {SHA256}"), [SHA256])

    def test_uppercase_hash(self):
        self.assertEqual(extract_sha256_hashes(SHA256.upper()), [SHA256.upper()])

    def test_sha512_not_matched(self):
        """64 hex chars inside a longer hex blob (e.g. SHA512) must not match."""
        self.assertEqual(extract_sha256_hashes(f"sha512: {SHA512}"), [])

    def test_too_short_not_matched(self):
        self.assertEqual(extract_sha256_hashes("md5: " + "a" * 32), [])


class TestDefangedIPs(unittest.TestCase):
    def test_bracket_dot_style(self):
        self.assertEqual(extract_defanged_ips("c2 at 198[.]51[.]100[.]23"), ["198[.]51[.]100[.]23"])

    def test_paren_dot_style(self):
        self.assertEqual(extract_defanged_ips("at 198(.)51(.)100(.)99 now"), ["198(.)51(.)100(.)99"])

    def test_brace_dot_style(self):
        self.assertEqual(extract_defanged_ips("at 198{.}51{.}100{.}99 now"), ["198{.}51{.}100{.}99"])

    def test_bracket_dot_word_style(self):
        self.assertEqual(
            extract_defanged_ips("at 203[dot]0[dot]113[dot]200"), ["203[dot]0[dot]113[dot]200"]
        )

    def test_paren_dot_word_style(self):
        self.assertEqual(
            extract_defanged_ips("at 203(dot)0(dot)113(dot)200"), ["203(dot)0(dot)113(dot)200"]
        )

    def test_partially_defanged(self):
        """Only one separator defanged -- the whole address must still match."""
        self.assertEqual(extract_defanged_ips("seen at 192.0.2[.]77 today"), ["192.0.2[.]77"])

    def test_fully_plain_ip_excluded(self):
        """A completely plain IP is extract_ipv4_addresses()'s job, not ours."""
        self.assertEqual(extract_defanged_ips("plain 192.0.2.77 here"), [])


class TestRefang(unittest.TestCase):
    def test_all_styles_refang_to_same_address(self):
        for defanged in (
            "192[.]168[.]1[.]1",
            "192(.)168(.)1(.)1",
            "192{.}168{.}1{.}1",
            "192[dot]168[dot]1[dot]1",
            "192(dot)168(dot)1(dot)1",
            "192[DOT]168.1[.]1",
        ):
            self.assertEqual(refang_ip(defanged), "192.168.1.1", defanged)


if __name__ == "__main__":
    unittest.main()
