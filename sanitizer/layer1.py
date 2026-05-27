import re
import urllib.parse
from vault.vault import TokenVault

# Common date patterns to protect from tokenization
DATE_PATTERNS = [
    re.compile(r'\d{4}/\d{2}/\d{2}'),           # 2026/05/26
    re.compile(r'\d{4}-\d{2}-\d{2}'),           # 2026-05-26
    re.compile(r'\d{2}/\w{3}/\d{4}'),           # 26/May/2026
    re.compile(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'),  # May 26 03:14:22
]

class Layer1Tokenizer:
    # Layer 1 - Regex tokenizer
    # Replaces all known PPI patterns with session-scoped tokens
    # This is the first and most deterministic layer of the sanitization pipeline

    def __init__(self, vault: TokenVault):
        self.vault = vault  # shared vault instance for token assignment

        # Regex patterns for known PPI types
        # Order matters — more specific patterns must come before general ones
        self.patterns = [
            # IPv4 addresses
            (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'ip'),

            # IPv4 with port
            (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b'), 'ip_port'),

            # IPv6 addresses
            (re.compile(r'\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'), 'ipv6'),

            # IPv6 link local with interface
            (re.compile(r'fe80::[0-9a-fA-F:%]+'), 'ipv6_link'),

            # MAC addresses
            (re.compile(r'\b([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b'), 'mac'),

            # Domain names
            (re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'), 'domain'),

            # File paths
            (re.compile(r'(/[a-zA-Z0-9_\-\.]+){2,}'), 'path'),

            # API keys and tokens — common prefixes
            (re.compile(r'\b(sk-|ghp_|gho_|Bearer\s)[a-zA-Z0-9_\-]{16,}\b'), 'apikey'),

            # JWT tokens
            (re.compile(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*'), 'jwt'),

            # WireGuard and generic base64 keys 32+ chars
            (re.compile(r'\b[a-zA-Z0-9+/]{32,}={0,2}\b'), 'b64key'),

            # base64 encoded values — only match known base64 prefixes
            (re.compile(r'\b(base64|encoded)_?\w*=[A-Za-z0-9+/]{8,}={0,2}'), 'b64val'),
            
            # Email addresses
            (re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'), 'email'),

            # Port numbers in context
            (re.compile(r'\bport[=:\s]+(\d{2,5})\b', re.IGNORECASE), 'port'),

            # Usernames in context
            (re.compile(r'\b(username|user|usr)[=:\s]+\S+', re.IGNORECASE), 'user'),

            # Passwords in context
            (re.compile(r'\b(password|passwd|pwd)[=:\s]+\S+', re.IGNORECASE), 'password'),
        ]

    def sanitize(self, text: str) -> str:
        # Protect dates from tokenization — dates belong to SFL transformer not Layer 1
        text = urllib.parse.unquote(text)
        placeholders = {}
        date_patterns = [
            re.compile(r'\b\d{2}:\d{2}:\d{2}(\.\d+)?\b'),        # 03:14:22 or 03:14:22.000
            re.compile(r'\d{4}/\d{2}/\d{2}'),                      # 2026/05/26
            re.compile(r'\d{4}-\d{2}-\d{2}'),                      # 2026-05-26
            re.compile(r'\d{2}/\w{3}/\d{4}'),                      # 26/May/2026
            re.compile(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'),   # May 26 03:14:22
        ]
        for i, dp in enumerate(date_patterns):
            for match in dp.finditer(text):
                key = f'__DATE_{i}_{match.start()}__'
                placeholders[key] = match.group(0)
                text = text.replace(match.group(0), key, 1)

        # Run all PII regex patterns against the input text
        # Replace every match with its corresponding session token
        for pattern, label in self.patterns:
            text = pattern.sub(lambda m: str(self.vault.tokenize(m.group(0))), text)

        # Restore dates — pass through untouched for SFL transformer
        for key, value in placeholders.items():
            text = text.replace(key, value)

        return text