"""Strings and IOC extraction.

Extracts printable ASCII and UTF-16LE strings, then regex-extracts indicators
of compromise: URLs, IPv4 addresses, domains, emails, Windows paths, registry
keys, and mutex-like tokens. Results are deduplicated and capped.
"""

from __future__ import annotations

import re

from ghostbox.analyzers import Analyzer, register
from ghostbox.report import Report

_MIN_STR_LEN = 4

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STR_LEN)
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % _MIN_STR_LEN)

# IOC regexes operate on extracted text.
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]]{4,}", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|biz|io|co|ru|cn|top|xyz|club|online|site|gov|edu|de|uk|us|tk|ml)\b",
    re.IGNORECASE,
)
_WINPATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\?)+")
_REGKEY_RE = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[^\s\"'<>]+", re.IGNORECASE
)
# Mutex / event style names often appear as Global\ or Local\ prefixed tokens.
_MUTEX_RE = re.compile(r"\b(?:Global|Local|Session)\\[A-Za-z0-9._{}-]{3,}")


def extract_strings(data: bytes, max_strings: int) -> list[str]:
    """Extract ASCII and UTF-16LE printable strings, deduplicated, capped."""
    seen: dict[str, None] = {}
    for match in _ASCII_RE.finditer(data):
        s = match.group().decode("ascii", "replace")
        seen.setdefault(s, None)
        if len(seen) >= max_strings:
            return list(seen.keys())
    for match in _UTF16_RE.finditer(data):
        s = match.group().decode("utf-16-le", "replace")
        seen.setdefault(s, None)
        if len(seen) >= max_strings:
            break
    return list(seen.keys())


def extract_iocs(strings: list[str]) -> dict[str, list[str]]:
    """Run IOC regexes over the joined strings; return deduped, sorted lists."""
    blob = "\n".join(strings)
    urls = _dedup(_URL_RE.findall(blob))
    ips = [ip for ip in _dedup(_IPV4_RE.findall(blob)) if not _is_trivial_ip(ip)]
    emails = _dedup(_EMAIL_RE.findall(blob))
    # Domains: exclude those already captured inside emails/urls hosts to reduce noise.
    domains = _dedup(_DOMAIN_RE.findall(blob))
    return {
        "urls": urls,
        "ipv4": ips,
        "domains": domains,
        "emails": emails,
        "windows_paths": _dedup(_WINPATH_RE.findall(blob)),
        "registry_keys": _dedup(_REGKEY_RE.findall(blob)),
        "mutexes": _dedup(_MUTEX_RE.findall(blob)),
    }


def _dedup(items: list[str]) -> list[str]:
    return sorted(set(items))


def _is_trivial_ip(ip: str) -> bool:
    return ip in {"0.0.0.0", "127.0.0.1", "255.255.255.255"} or ip.startswith("0.")


class StringsIOCAnalyzer(Analyzer):
    name = "strings_ioc"

    def __init__(self, max_strings: int = 2000) -> None:
        self.max_strings = max_strings

    def analyze(self, data: bytes, report: Report) -> None:
        strings = extract_strings(data, self.max_strings)
        iocs = extract_iocs(strings)
        report.sections[self.name] = {
            "string_count": len(strings),
            "strings_sample": strings[:50],
            "iocs": iocs,
        }
        # Full string list for downstream analyzers (not serialized in JSON output).
        report.sections["_strings_full"] = strings

        net_count = len(iocs["urls"]) + len(iocs["ipv4"]) + len(iocs["domains"])
        if net_count:
            report.add_signal(
                "network-iocs",
                min(3 + 2 * net_count, 15),
                f"{net_count} network IOC(s) extracted",
            )
        if iocs["registry_keys"]:
            report.add_signal(
                "registry-references",
                min(2 * len(iocs["registry_keys"]), 8),
                f"{len(iocs['registry_keys'])} registry key reference(s)",
            )


register(StringsIOCAnalyzer())
