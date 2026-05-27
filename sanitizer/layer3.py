import re
import math

# Layer 3 — Egress Leak Check.
#
# The final fail-closed safety net before transmission. It shares NO code with
# Layer 1 or Layer 2: every pattern here is written from scratch and this module
# imports nothing from layer1 or layer2. It independently pattern-matches the
# COMPLETE outbound payload one last time against the known PII universe and
# aborts the moment anything still looks like real infrastructure data.
#
# Philosophy: unknown is treated as suspicious, not safe. The first failing check
# wins and returns immediately — partial cleanliness is treated as not clean.

# --- Independent detection patterns (deliberately re-derived, not shared) ---

# Raw dotted-quad IPv4 (e.g. 10.0.0.1). Token output is 8 plain digits with
# no dots, so this only fires on a real address that slipped through.
_IPV4 = re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')

# Colon-separated hex groups — candidate IPv6. Validated further below so that
# HH:MM:SS clock times are not mistaken for addresses.
_IPV6_CANDIDATE = re.compile(r'[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,}')

# MAC address (aa:bb:cc:dd:ee:ff).
_MAC = re.compile(r'(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])')

# Email address.
_EMAIL = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')

# PEM / OpenSSH private key (and any) header.
_PRIVKEY = re.compile(r'-----BEGIN[ A-Z0-9]*')

# Known credential prefixes and bearer tokens.
_APIKEY = re.compile(r'\b(?:sk-|ghp_|gho_)[A-Za-z0-9_\-]{8,}')
_BEARER = re.compile(r'\bBearer\s+[A-Za-z0-9_\-\.]{16,}')

# Unix path with two or more segments, Windows drive path, and registry key.
_UNIX_PATH = re.compile(r'(?:/[A-Za-z0-9._\-]+){2,}')
_WIN_PATH = re.compile(r'[A-Za-z]:\\[^\s]+')
_WIN_REG = re.compile(r'HKEY_[A-Z_]+(?:\\[^\s=]+)+')

# username= / user= / usr= followed by a value (case-insensitive). The value is
# checked separately against the vault — only a real (non-token) value fails.
_USER_CTX = re.compile(r'\b(?:username|user|usr)\s*[=:]\s*(\S+)', re.IGNORECASE)

# Candidate runs for the high-entropy scan: contiguous secret-alphabet
# characters. This breaks on '=', ':', quotes, spaces, and dots, so a labelled
# token like user_agent=55384961 is split into "user_agent" and "55384961"
# rather than measured as one blob. A real secret has no such separators mid-run.
_SECRET_RUN = re.compile(r'[A-Za-z0-9+/_\-]{13,}')

# High-entropy thresholds.
_ENTROPY_MIN_LEN = 12     # only inspect tokens longer than this
_ENTROPY_BITS = 4.0       # bits/char above which a long token is suspicious


class EgressChecker:
    # Independent egress verifier. Constructed with the session vault so it can
    # distinguish a genuine session token from a real high-entropy value via the
    # vault's own proof (verify), without sharing any sanitizer logic.

    def __init__(self, vault):
        # Keep a reference to the session vault for token verification only.
        self.vault = vault

    def check(self, text):
        # Run every independent check against the full payload in order. Return
        # (False, reason) on the first failure (fail closed); (True, "clean") only
        # if every check passes.
        if text is None:
            return False, "null payload"

        # Private key material — cheapest and most catastrophic, checked first.
        if _PRIVKEY.search(text):
            return False, "private key header detected"

        # Credential prefixes / bearer tokens.
        if _APIKEY.search(text):
            return False, "api key prefix detected"
        if _BEARER.search(text):
            return False, "bearer token detected"

        # Email addresses.
        if _EMAIL.search(text):
            return False, "email address detected"

        # MAC before IPv6 so a MAC is reported as a MAC, not an IPv6 literal.
        if _MAC.search(text):
            return False, "MAC address detected"

        # IPv6 literal (timestamp-aware).
        ipv6 = self._find_ipv6(text)
        if ipv6:
            return False, f"IPv6 address detected: {ipv6}"

        # Raw IPv4.
        m = _IPV4.search(text)
        if m:
            return False, f"raw IPv4 address detected: {m.group(0)}"

        # File paths — Unix, Windows, registry.
        if _WIN_REG.search(text):
            return False, "windows registry path detected"
        if _WIN_PATH.search(text):
            return False, "windows file path detected"
        if _UNIX_PATH.search(text):
            return False, "unix file path detected"

        # username=/user=/usr= carrying a non-token value.
        leaked_user = self._find_user_leak(text)
        if leaked_user:
            return False, f"username context with real value: {leaked_user}"

        # High-entropy strings that are not valid session tokens.
        hot = self._find_high_entropy(text)
        if hot:
            return False, f"high-entropy non-token string detected: {hot}"

        return True, "clean"

    # ------------------------------------------------------------- helpers
    def _find_ipv6(self, text):
        # Return the first colon-hex run that looks like a real IPv6 address.
        # A run qualifies only if it uses '::' compression, contains a hex letter,
        # or has 4+ colon groups — this excludes HH:MM:SS clock times, which are
        # pure decimal, uncompressed, and have at most two colons.
        for m in _IPV6_CANDIDATE.finditer(text):
            s = m.group(0)
            if "::" in s or re.search(r'[A-Fa-f]', s) or s.count(":") >= 4:
                return s
        return None

    def _is_session_token(self, value):
        # True only if value is the string form of a current, vault-verified
        # session token. Uses the vault's own proof — no sanitizer code reused.
        if not value or not value.isdigit():
            return False
        try:
            return bool(self.vault.verify(int(value)))
        except Exception:
            return False

    def _find_user_leak(self, text):
        # Return the first username/user/usr value that is NOT a valid session
        # token (i.e. a real username that slipped through).
        for m in _USER_CTX.finditer(text):
            value = m.group(1).strip().strip('.,;:"\'()[]{}')
            if value and not self._is_session_token(value):
                return value
        return None

    def _entropy(self, s):
        # Shannon entropy in bits per character (independent implementation).
        n = len(s)
        if n < 2:
            return 0.0
        counts = {}
        for ch in s:
            counts[ch] = counts.get(ch, 0) + 1
        bits = 0.0
        for c in counts.values():
            p = c / n
            bits -= p * math.log2(p)
        return bits

    def _find_high_entropy(self, text):
        # Return the first secret-alphabet run longer than 12 chars whose entropy
        # exceeds 4.0 bits/char and which is not a valid session token. Such a run
        # is what a leaked key, hash, or credential looks like.
        for m in _SECRET_RUN.finditer(text):
            token = m.group(0)
            if len(token) <= _ENTROPY_MIN_LEN:
                continue
            if self._is_session_token(token):
                continue
            if self._entropy(token) > _ENTROPY_BITS:
                return token
        return None


if __name__ == "__main__":
    # Self-test. The imports of Layers 1 and 2 below are for exercising the full
    # pipeline only; EgressChecker itself imports nothing from those modules.
    from vault.vault import TokenVault
    from sanitizer.layer1 import Layer1Tokenizer
    from sanitizer.layer2 import Layer2Scanner

    v = TokenVault()
    v.new_session()
    l1 = Layer1Tokenizer(v)
    l2 = Layer2Scanner(v)
    l3 = EgressChecker(v)

    # Test 1 - clean payload should pass
    clean = '85148536 - admin connected from 74822897 at port 4533'
    after_l1 = l1.sanitize(clean)
    after_l2 = l2.scan(after_l1)
    result, reason = l3.check(after_l2)
    print(f'Clean test: {result} - {reason}')

    # Test 2 - raw IP should fail
    dirty = '10.0.0.1 connected successfully'
    result, reason = l3.check(dirty)
    print(f'Dirty test: {result} - {reason}')

    # Test 3 - run full batch through all 3 layers
    for f in ['tests/test_batch1_ssh.txt', 'tests/test_batch2_app.txt', 'tests/test_batch3_network.txt']:
        with open(f) as fh:
            content = fh.read()
        after_l1 = l1.sanitize(content)
        after_l2 = l2.scan(after_l1)
        result, reason = l3.check(after_l2)
        print(f'{f}: clean={result} reason={reason}')
