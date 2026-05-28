"""
String extraction and analysis
"""

import re
import string

class StringAnalyzer:
    """Analyzer for strings in binary"""
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        'url': r'https?://[^\s]+',
        'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'domain': r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        'api_call': r'(CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|CreateProcess|WinExec|ShellExecute|RegOpenKey|RegSetValue|InternetOpen|URLDownloadToFile)',
        'powershell': r'powershell|PowerShell',
        'cmd': r'cmd\.exe|CMD\.EXE',
        'registry': r'HKEY_|HKLM|HKCU|HKCR',
        'c2': r'C2|beacon|callback|payload|stager',
        'obfuscation': r'base64|xor|encrypt|decode',
        'suspicious_path': r'\\Temp\\|\\AppData\\|\\Users\\Public\\|\\Windows\\Temp\\',
    }
    
    def __init__(self, filepath):
        self.filepath = filepath
        self.strings = self._extract_strings()
    
    def _extract_strings(self, min_length=4):
        """Extract strings from binary"""
        strings = []
        current = []
        
        with open(self.filepath, 'rb') as f:
            data = f.read()
            
            for byte in data:
                # Check if byte is printable ASCII
                if 32 <= byte <= 126 or byte in [9, 10, 13]:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        strings.append(''.join(current))
                    current = []
            
            # Check last string
            if len(current) >= min_length:
                strings.append(''.join(current))
        
        return strings
    
    def find_suspicious(self):
        """Find suspicious strings based on patterns"""
        suspicious = []
        
        for s in self.strings:
            for pattern_name, pattern in self.SUSPICIOUS_PATTERNS.items():
                if re.search(pattern, s, re.IGNORECASE):
                    if s not in suspicious:
                        suspicious.append(s)
        
        return suspicious
    
    def find_urls(self):
        """Find URLs in strings"""
        urls = []
        for s in self.strings:
            matches = re.findall(self.SUSPICIOUS_PATTERNS['url'], s, re.IGNORECASE)
            urls.extend(matches)
        return list(set(urls))
    
    def find_ips(self):
        """Find IP addresses in strings"""
        ips = []
        for s in self.strings:
            matches = re.findall(self.SUSPICIOUS_PATTERNS['ip'], s)
            # Filter out invalid IPs
            valid_ips = [ip for ip in matches if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
            ips.extend(valid_ips)
        return list(set(ips))
    
    def find_apis(self):
        """Find API calls in strings"""
        apis = []
        for s in self.strings:
            matches = re.findall(self.SUSPICIOUS_PATTERNS['api_call'], s, re.IGNORECASE)
            apis.extend(matches)
        return list(set(apis))