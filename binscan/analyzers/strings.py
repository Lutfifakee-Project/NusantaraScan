"""
String extraction and analysis - dengan whitelist filter.
"""

import re

from ..config import (
    MAX_STRINGS_EXTRACT,
    WHITELIST_DOMAINS,
    WHITELIST_APIS,
    WHITELIST_STRING_PATTERNS,
)


class StringAnalyzer:
    """Analyzer string dengan filter whitelist."""

    SUSPICIOUS_PATTERNS = {
        "url": r"https?://[^\s\"'<>]+",
        "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "domain": r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|id|xyz|top|onion|ru|cn|info|biz)\b",
        "api_call": r"(CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|CreateProcess|WinExec|ShellExecute|RegOpenKey|RegSetValue|InternetOpen|URLDownloadToFile|NtCreateThreadEx|RtlMoveMemory)",
        "powershell": r"powershell(?:\.exe)?",
        "cmd": r"cmd\.exe",
        "registry": r"HKEY_|HKLM|HKCU|HKCR",
        "c2": r"\bC2\b|beacon|callback|payload|stager",
        "obfuscation": r"base64|xor|encrypt|decode",
        "suspicious_path": r"\\Temp\\|\\AppData\\|\\Users\\Public\\|\\Windows\\Temp\\",
    }

    def __init__(self, filepath: str, data: bytes = None):
        self.filepath = filepath
        if data is None:
            with open(filepath, "rb") as f:
                data = f.read()
        self.data = data
        self.strings = self._extract_strings()

    def _extract_strings(self, min_length: int = 4) -> list:
        strings = []
        current = bytearray()
        for byte in self.data:
            if 32 <= byte <= 126 or byte in (9, 10, 13):
                current.append(byte)
            else:
                if len(current) >= min_length:
                    strings.append(current.decode("ascii", errors="ignore"))
                    if len(strings) >= MAX_STRINGS_EXTRACT:
                        return strings
                current = bytearray()
        if len(current) >= min_length:
            strings.append(current.decode("ascii", errors="ignore"))
        return strings

    # ── Whitelist checks ──────────────────────────────────────
    @staticmethod
    def _is_whitelisted_domain(text: str) -> bool:
        lower = text.lower()
        return any(domain in lower for domain in WHITELIST_DOMAINS)

    @staticmethod
    def _is_whitelisted_api(text: str) -> bool:
        return any(api in text for api in WHITELIST_APIS)

    @staticmethod
    def _is_whitelisted_string(text: str) -> bool:
        return any(pat in text for pat in WHITELIST_STRING_PATTERNS)

    def _is_false_positive(self, text: str) -> bool:
        """Return True jika string ini kemungkinan false positive."""
        if self._is_whitelisted_domain(text):
            return True
        if self._is_whitelisted_api(text):
            return True
        if self._is_whitelisted_string(text):
            return True
        return False

    # ── Public methods ────────────────────────────────────────
    def find_suspicious(self) -> list:
        suspicious = set()
        for s in self.strings:
            # Skip kalau masuk whitelist
            if self._is_false_positive(s):
                continue

            for pattern in self.SUSPICIOUS_PATTERNS.values():
                if re.search(pattern, s, re.IGNORECASE):
                    suspicious.add(s)
                    break
        return sorted(suspicious)

    def find_urls(self) -> list:
        urls = set()
        for s in self.strings:
            urls.update(re.findall(self.SUSPICIOUS_PATTERNS["url"], s, re.IGNORECASE))
        # Filter domain whitelist
        return sorted(u for u in urls if not self._is_whitelisted_domain(u))

    def find_ips(self) -> list:
        ips = set()
        for s in self.strings:
            for match in re.findall(self.SUSPICIOUS_PATTERNS["ip"], s):
                try:
                    if all(0 <= int(o) <= 255 for o in match.split(".")):
                        ips.add(match)
                except ValueError:
                    continue
        return sorted(ips)

    def find_apis(self) -> list:
        apis = set()
        for s in self.strings:
            matches = re.findall(
                self.SUSPICIOUS_PATTERNS["api_call"], s, re.IGNORECASE
            )
            for m in matches:
                # Filter API whitelist
                if not self._is_whitelisted_api(m):
                    apis.add(m)
        return sorted(apis)