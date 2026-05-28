import re
import base64
import binascii
import urllib.parse
from vault.vault import TokenVault

# --- Obfuscation normalization -------------------------------------------------
# Invisible / zero-width characters carry no visible content but split tokens, so
# they are used to slip PII past the regex layer (e.g. 192<ZWSP>.168.1.57).
# Stripped entirely before any matching.
_ZERO_WIDTH_CHARS = (
    "​‌‍⁠⁡⁢⁣⁤"  # ZWSP/ZWNJ/ZWJ/word-joiner
    "﻿‎‏­"                          # BOM, LRM/RLM, soft hyphen
)
# Unicode characters that imitate the ASCII '.' separator (used to break IP and
# domain matching, e.g. the Lisu letter 192ꓸ168ꓸ1ꓸ57). Folded to '.' so the
# dotted-quad and domain regexes still fire.
_DOT_CONFUSABLES = "․。．ꓸ܁܂﹒‧｡"


def _build_normalize_table():
    # Translation table: delete control/invisible chars, fold dot look-alikes.
    table = {}
    for cp in range(0x00, 0x20):            # C0 controls incl. NUL ...
        if cp not in (0x09, 0x0A, 0x0D):    # ... but keep tab / newline / CR
            table[cp] = None
    table[0x7F] = None                      # DEL
    for ch in _ZERO_WIDTH_CHARS:
        table[ord(ch)] = None
    for ch in _DOT_CONFUSABLES:
        table[ord(ch)] = ord(".")
    return table


_NORMALIZE_TABLE = _build_normalize_table()

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
        # Order matters — more specific patterns must come before general ones.
        # NOTE: normalize() already rewrites hex/decimal/octal-encoded IPs to
        # dotted-quad form before these run, so the three encoded-IP rules below
        # are now fail-closed fallbacks for any encoding the normalizer skipped.
        self.patterns = [
            # Encoded IPv4 — hex form (0xC0A80139). Must precede the dotted IPv4
            # rule so obfuscated addresses are caught before plain matching.
            (re.compile(r'\b0x[0-9a-fA-F]{8}\b'), 'hex_ip'),

            # Encoded IPv4 — single decimal integer form (e.g. 3232235833).
            # Covers the full 10-digit IPv4 integer range 1,000,000,000 to
            # 4,294,967,295 ([1-3] billions, plus 4.0-4.29 billion). Kept to 10
            # digits so it never re-tokenizes the 8-digit vault tokens.
            (re.compile(r'\b[1-3][0-9]{9}\b|\b4[0-2][0-9]{8}\b'), 'decimal_ip'),

            # Encoded IPv4 — dotted octal form with leading-zero octets.
            (re.compile(r'\b0\d{3}\.\d+\.\d+\.\d+\b'), 'octal_ip'),

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

            # Windows registry paths (HKEY_LOCAL_MACHINE\Software\...). Must
            # precede the path rules so the full key is captured as one token.
            (re.compile(r'HKEY_[A-Z_]+(?:\\[^\s=]+)+'), 'winreg'),

            # Windows backslash file paths (C:\Users\admin\file). The forward-
            # slash path rule below does not cover these.
            (re.compile(r'([A-Za-z]:\\(?:[^\s\\]+\\)*[^\s\\]*)'), 'winpath'),

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

            # Application identifier patterns — key=integer
            (re.compile(r'\b\w+[Ii][Dd]=\d+'), 'appid'),
            (re.compile(r'\bpid=\d+', re.IGNORECASE), 'pid'),

            # Bare metric — <digits><unit/percent>. Tokenised whole so the digit
            # run never surfaces as an unproven numeric to Layer 4's proof gate.
            # Trailing (?!\w) (not \b) so that '%' — itself non-word — still
            # terminates the match cleanly ('\b' would require a word/non-word
            # transition, which fails between '%' and a following space).
            (re.compile(r'\b\d+(?:%|ms|s|m|h|d|kb|mb|gb|tb|b)(?!\w)', re.IGNORECASE), 'metric'),
        ]

    # ----------------------------------------------------------- normalizer
    # Encoded-IP shapes the numeric decoders recognise. Compiled once.
    _HEX_IP_RE = re.compile(r'\b0[xX][0-9a-fA-F]{8}\b')
    _DEC_IP_RE = re.compile(r'\b\d{10}\b')
    _OCTAL_IP_RE = re.compile(
        r'\b(0[0-7]{1,3})\.(0?[0-7]{1,3})\.(0?[0-7]{1,3})\.(0?[0-7]{1,3})\b')
    # base64: a labelled value (base64=…, encoded:…) and a bare ≥16-char blob.
    _B64_LABELLED_RE = re.compile(
        r'\b(base64|b64|encoded)([=:])([A-Za-z0-9+/]{8,}={0,2})', re.IGNORECASE)
    _B64_BLOB_RE = re.compile(
        r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])')

    @staticmethod
    def _int_to_ipv4(n: int) -> str:
        # Pack a 32-bit integer into dotted-quad form (192.168.1.1).
        return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"

    def _decode_url(self, text: str) -> str:
        # Decode percent-encoding (%xx), iterating to peel multi-layer encodings
        # (e.g. %2520 -> %20 -> ' '). unquote leaves invalid escapes and already
        # decoded text untouched, so the loop reaches a fixpoint quickly.
        for _ in range(3):
            decoded = urllib.parse.unquote(text)
            if decoded == text:
                break
            text = decoded
        return text

    def _decode_hex_ips(self, text: str) -> str:
        # 0xC0A80101 -> 192.168.1.1 (8 hex digits = one packed IPv4).
        return self._HEX_IP_RE.sub(
            lambda m: self._int_to_ipv4(int(m.group(0), 16)), text)

    def _decode_decimal_ips(self, text: str) -> str:
        # A bare 32-bit integer in IPv4 range -> dotted quad (3232235777 ->
        # 192.168.1.1). Restricted to 10-digit values so it never collides with
        # the vault's 8-digit tokens or short numeric metrics; out-of-range
        # 10-digit numbers are left untouched.
        def repl(m):
            n = int(m.group(0))
            return self._int_to_ipv4(n) if n <= 0xFFFFFFFF else m.group(0)
        return self._DEC_IP_RE.sub(repl, text)

    def _decode_octal_ips(self, text: str) -> str:
        # Dotted-octal IPv4 (0300.0250.01.01 -> 192.168.1.1). The leading-zero
        # first octet is the octal marker, so ordinary decimal IPs are not
        # touched here (they are caught by the dotted-IPv4 regex instead).
        def repl(m):
            octets = [int(g, 8) for g in m.groups()]
            if all(o <= 255 for o in octets):
                return ".".join(str(o) for o in octets)
            return m.group(0)
        return self._OCTAL_IP_RE.sub(repl, text)

    def _try_decode_b64(self, blob: str):
        # Return the decoded text for a base64 blob, or None if it is not a safe
        # candidate. Conservative on purpose: JWT segments are left for the JWT
        # pattern, and only valid base64 that decodes to printable ASCII is
        # substituted — binary/garbage decodes are left in place so the b64key
        # regex can still tokenize them.
        if blob.startswith("eyJ"):                      # JWT segment
            return None
        try:
            raw = base64.b64decode(blob, validate=True)
            decoded = raw.decode("ascii")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None
        if not decoded or decoded == blob or not decoded.isprintable():
            return None
        return decoded

    def _decode_base64(self, text: str) -> str:
        # Decode base64-wrapped values so any PII they hide (an IP, email, host)
        # is exposed in plaintext for the regex layer below.
        def repl_labelled(m):
            decoded = self._try_decode_b64(m.group(3))
            return m.group(0) if decoded is None else f"{m.group(1)}{m.group(2)}{decoded}"
        text = self._B64_LABELLED_RE.sub(repl_labelled, text)

        def repl_blob(m):
            decoded = self._try_decode_b64(m.group(0))
            return m.group(0) if decoded is None else decoded
        return self._B64_BLOB_RE.sub(repl_blob, text)

    def _strip_obfuscation(self, text: str) -> str:
        # Remove invisible / zero-width and control characters (including NUL) and
        # fold Unicode separator look-alikes to ASCII. This denies the attacker
        # the ability to split a value — 192<ZWSP>.168.1.57, /etc/<NUL>passwd,
        # 192<LISU-DOT>168<LISU-DOT>1<LISU-DOT>57 — to slip it past the structural
        # regexes. Runs first, before any decoding, so the decoders and the regex
        # layer all see the de-obfuscated text.
        return text.translate(_NORMALIZE_TABLE)

    def normalize(self, text: str) -> str:
        # Log normalizer (ZKDP SPEC, Layer 1): decode every supported encoding
        # into canonical form BEFORE the regex layer runs, so obfuscated PII is
        # matched as real PII. Strip obfuscation characters first, then URL-decode
        # (an outer percent-encoding may wrap any of the others), then base64
        # blobs (which may themselves contain an encoded IP), then numeric IPs.
        text = self._strip_obfuscation(text)
        text = self._decode_url(text)
        text = self._decode_base64(text)
        text = self._decode_hex_ips(text)
        text = self._decode_decimal_ips(text)
        text = self._decode_octal_ips(text)
        return text

    def sanitize(self, text: str) -> str:
        # Normalize all encodings before any pattern matching (see normalize()).
        text = self.normalize(text)

        # Protect dates from tokenization — dates belong to SFL transformer not Layer 1
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