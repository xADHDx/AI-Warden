import os
import re
import math
from collections import Counter
import requests
from vault.vault import TokenVault

# Ollama endpoint for the ESCALATE auditor.
# IMPORTANT: never hardcode a real LAN IP into a committed file. The host is read
# from the environment so the real Ollama address lives only in the local runtime,
# never in source control. Default is loopback so a fresh clone never points at
# someone else's infrastructure.
OLLAMA_URL = os.environ.get("AIWARDEN_OLLAMA_URL", "http://localhost:11434") + "/api/generate"
OLLAMA_MODEL = os.environ.get("AIWARDEN_OLLAMA_MODEL", "tinyllama")
OLLAMA_TIMEOUT = float(os.environ.get("AIWARDEN_OLLAMA_TIMEOUT", "10"))

# ---------------------------------------------------------------------------
# Signal 1 reference data — Vocabulary classifier (VOCAB_CLASS)
# A token whose lowercased core appears here is a recognised, non-identifying
# system word. Tokens built entirely from these are SYSTEM; tokens with no known
# part are UNKNOWN; a mix is MIXED. This is an allow-list: unknown = risk.
# ---------------------------------------------------------------------------
SAFE_VOCABULARY = {
    # Generic system / service nouns
    "server", "service", "services", "daemon", "process", "thread", "job", "task",
    "system", "kernel", "module", "driver", "device", "interface", "socket",
    "connection", "session", "request", "response", "client", "host", "node",
    "container", "instance", "cluster", "pod", "volume", "mount", "disk",
    "memory", "cpu", "cache", "buffer", "queue", "pool", "worker", "handler",
    # State / event verbs and adjectives (these describe transitions, not identity)
    "started", "starting", "stopped", "stopping", "running", "restarted",
    "connected", "disconnected", "reconnecting", "listening", "bound", "closed",
    "opened", "accepted", "refused", "rejected", "denied", "granted", "allowed",
    "failed", "succeeded", "ok", "healthy", "unhealthy", "ready", "active",
    "inactive", "enabled", "disabled", "available", "unavailable", "timeout",
    "timed", "expired", "missing", "found", "loaded", "unloaded", "mounted",
    "created", "deleted", "updated", "removed", "added", "killed", "spawned",
    "online", "offline", "up", "down", "degraded", "recovered", "retrying",
    # Log level words
    "trace", "debug", "info", "notice", "warn", "warning", "error", "err",
    "crit", "critical", "alert", "emerg", "emergency", "fatal", "fail", "panic",
    # HTTP / network protocol terms
    "get", "post", "put", "patch", "delete", "head", "options", "connect",
    "http", "https", "tcp", "udp", "tls", "ssl", "dns", "icmp", "arp", "ssh",
    "method", "status", "code", "header", "headers", "body", "payload", "route",
    "upstream", "downstream", "gateway", "proxy", "redirect", "handshake",
    "port", "ports", "protocol", "proto", "packet", "packets", "peer", "pid",
    # Common log connective / preposition words (keeps prose readable, never PII)
    "from", "to", "at", "on", "in", "of", "for", "by", "with", "via", "and",
    "the", "a", "an", "is", "was", "has", "had", "after", "before", "during",
    "while", "when", "then", "due", "not", "no", "yes", "true", "false", "null",
    "none", "score", "exit", "signal", "level", "count", "total", "size",
    "bytes", "kb", "mb", "gb", "tb", "ms", "sec", "secs", "min", "mins", "hour",
    "hours", "percent", "version", "config", "default", "unknown",
    "all", "any", "some", "each", "every", "systems", "errors", "warnings",
    "messages", "logs", "log", "data", "out", "off", "this", "that", "it",
}

# Keys whose left-hand side acts as a descriptive label (role KEY).
KEY_NAMES = {
    "key", "api_key", "apikey", "token", "secret", "password", "passwd", "pwd",
    "auth", "authorization", "user", "username", "usr", "uid", "owner", "host",
    "hostname", "server", "node", "addr", "address", "ip", "client", "peer",
    "endpoint", "upstream", "email", "mail", "domain", "url", "uri", "path",
    "file", "dir", "directory", "mac", "hwaddr", "status", "level", "code",
    "container", "image", "method", "exit_code", "port", "pid", "score",
}

# Role EVENT — log-level words and state/action descriptors.
EVENT_WORDS = {
    "trace", "debug", "info", "notice", "warn", "warning", "error", "err",
    "crit", "critical", "alert", "emerg", "emergency", "fatal", "fail", "panic",
    "started", "starting", "stopped", "stopping", "running", "restarted",
    "connected", "disconnected", "listening", "accepted", "refused", "rejected",
    "denied", "granted", "failed", "succeeded", "expired", "missing", "killed",
    "mounted", "created", "deleted", "timeout", "online", "offline", "up", "down",
    "healthy", "unhealthy", "active", "inactive", "ready", "available",
    "unavailable", "enabled", "disabled", "degraded", "recovered", "ok",
}

# Role CONTROL — protocol or format tokens. Structural, never identity.
PROTOCOL_TOKENS = {
    "get", "post", "put", "patch", "delete", "head", "options", "connect",
    "http", "https", "tcp", "udp", "tls", "ssl", "dns", "icmp", "arp", "ssh",
    "true", "false", "null", "none", "->", "=>", "<-",
}

# Role METRIC — a numeric value, optionally with a unit/percent suffix.
METRIC_RE = re.compile(r'^[+-]?\d+(?:\.\d+)?(?:%|s|ms|m|h|d|kb|mb|gb|tb|b)?$', re.IGNORECASE)

# Role CONTROL — punctuation/operators only.
CONTROL_RE = re.compile(r'^[^\w]+$')

# Signal 3 — SOURCE_CLASS keyword signatures. The category with the most keyword
# hits across the whole input classifies the log source.
SOURCE_SIGNATURES = {
    "AUTH": {"sshd", "sudo", "auth", "authentication", "password", "publickey",
             "login", "logout", "pam", "credential", "invalid user",
             "failed password"},
    "SYSTEM": {"kernel", "systemd", "init", "cgroup", "oom", "out of memory",
               "segfault", "panic", "module", "udev", "journal"},
    "NETWORK": {"tcp", "udp", "wg0", "wireguard", "handshake", "endpoint",
                "upstream", "connect()", "interface", "eth0", "arp", "route",
                "gateway", "icmp", "packet", "firewall", "nginx", "proxy"},
    "APP": {"http", "https", "request", "response", "status", "container",
            "image", "transcode", "codec", "api"},
}


class Layer2Scanner:
    # Layer 2 — Three-Signal Context Sanitizer (per ZKDP SPEC v0.2).
    #
    # Runs on the output of Layer 1 and catches the PII regex cannot: bare
    # hostnames, usernames, and odd-shaped identifiers with no fixed pattern. It
    # fuses three independent signals plus per-token entropy and uniqueness into
    # a single risk score, then emits one of four decisions per token:
    #   Signal 1 — Vocabulary (VOCAB_CLASS): SYSTEM / MIXED / UNKNOWN
    #   Signal 2 — Role:                     KEY / VALUE / METRIC / EVENT / CONTROL
    #   Signal 3 — Source (SOURCE_CLASS):    AUTH / SYSTEM / APP / NETWORK / UNKNOWN
    #
    # The LLM auditor fires ONLY on ESCALATE — a rare exception handler, not the
    # primary scanner. Layer 2 fails closed: any unexpected error returns the
    # input unchanged so Layers 3 and 4 remain the final authority, and any LLM
    # failure during ESCALATE tokenizes the value so it can never leak.

    # Signal weights (ZKDP SPEC v0.2 — Layer 2 risk scoring).
    W_VALUE = 0.4        # ROLE = VALUE (a value positioned after '=' or ':')
    W_UNKNOWN = 0.3      # VOCAB_CLASS = UNKNOWN or MIXED
    W_AUTH = 0.2         # SOURCE_CLASS = AUTH
    W_ENTROPY = 0.2      # Shannon entropy above 3.5 bits/char
    W_UNIQUE = 0.1       # token appears only once in the log
    ENTROPY_BITS = 3.5   # bits-per-char threshold for the entropy bonus

    # Decision thresholds (ZKDP SPEC v0.2).
    SAFE_MAX = 0.3       # score < 0.3              → SAFE
    SANITIZE_MAX = 0.6   # 0.3 <= score < 0.6      → SANITIZE
    TOKENIZE_MAX = 0.8   # 0.6 <= score < 0.8      → TOKENIZE; >= 0.8 → ESCALATE

    def __init__(self, vault: TokenVault):
        # Hold the shared session vault so tokens stay consistent across layers.
        self.vault = vault

    # ------------------------------------------------------------------ entry
    def scan(self, text: str) -> str:
        # Top-level entry point. Classify the source once, count token frequencies
        # for the uniqueness signal, then evaluate every word and rebuild the line.
        # Wrapped so any failure falls through to returning the original text.
        try:
            source = self._classify_source(text)
            words = text.split(" ")
            decomposed = [self._decompose(w) for w in words]

            # Uniqueness signal — how often each scored token appears in the line.
            counts = Counter(d[2] for d in decomposed if d[2])

            out = []
            for word, (lead, prefix, token, trail, value_pos) in zip(words, decomposed):
                if not word or token == "":
                    out.append(word)  # empty or pure-punctuation word
                    continue
                new_token = self._evaluate(token, source, value_pos, counts[token])
                out.append(f"{lead}{prefix}{new_token}{trail}")
            return " ".join(out)
        except Exception:
            # Fail closed — never emit a half-sanitized line. Layers 3/4 catch leaks.
            return text

    # --------------------------------------------------------- word structure
    def _split_affixes(self, word: str):
        # Separate leading/trailing punctuation from a word's core so a token like
        # "refused," or "(myhost)" is classified on its core while the surrounding
        # punctuation is preserved. Internal characters ('=', '_', '.') stay.
        m = re.match(r'^(\W*)(.*?)(\W*)$', word, re.DOTALL)
        if not m:
            return "", word, ""
        return m.group(1), m.group(2), m.group(3)

    def _decompose(self, word: str):
        # Break a word into (lead, prefix, token, trail, value_position). The
        # prefix is the retained "key=" / "key:" label; the token is the part to
        # classify; value_position is True when the token sits after '=' or ':'.
        lead, core, trail = self._split_affixes(word)
        if core == "":
            return lead, "", "", trail, False
        if "=" in core:
            key, _, value = core.partition("=")
            if value != "":
                return lead, f"{key}=", value, trail, True
        if ":" in core:
            key, _, value = core.partition(":")
            # Only treat as key:value when the left side is an alphabetic label;
            # this avoids splitting times, ratios, and ipv6 fragments.
            if key.isalpha() and value != "":
                return lead, f"{key}:", value, trail, True
        return lead, "", core, trail, False

    # --------------------------------------------------------- decision engine
    def _evaluate(self, token: str, source: str, value_pos: bool, count: int) -> str:
        # Score one token across all signals and apply the resulting decision.
        # Returns the (possibly transformed) token string.
        role = self._role_signal(token)
        vocab = self._vocab_signal(token, role)
        score = self._risk_score(role, vocab, source, token, value_pos, count)
        decision = self._decide(score)

        if decision == "SAFE":
            return token
        if decision in ("SANITIZE", "TOKENIZE"):
            # SPEC: SANITIZE "passes to tokenizer"; TOKENIZE replaces with a token.
            return str(self.vault.tokenize(token))
        if decision == "ESCALATE":
            return self._escalate(token, source)
        return token  # unreachable; defensive default keeps text intact

    def _decide(self, score: float) -> str:
        # Map a fused risk score to one of the four protocol decisions.
        if score < self.SAFE_MAX:
            return "SAFE"
        if score < self.SANITIZE_MAX:
            return "SANITIZE"
        if score < self.TOKENIZE_MAX:
            return "TOKENIZE"
        return "ESCALATE"

    def _risk_score(self, role, vocab, source, token, value_pos, count) -> float:
        # Fuse the three signals plus entropy and uniqueness into a 0..1 score,
        # using the additive weights defined by ZKDP SPEC v0.2.
        score = 0.0

        # Signal 2 — a value positioned after '=' or ':' is the strongest signal.
        if role == "VALUE" and value_pos:
            score += self.W_VALUE

        # Signal 1 — vocabulary the classifier does not recognise carries risk.
        if vocab in ("UNKNOWN", "MIXED"):
            score += self.W_UNKNOWN

        # Signal 3 — auth logs are dense with usernames, hosts, and credentials.
        if source == "AUTH":
            score += self.W_AUTH

        # Entropy — high-randomness strings look like keys / credentials / hashes.
        if self._entropy(token) > self.ENTROPY_BITS:
            score += self.W_ENTROPY

        # Uniqueness — a value seen exactly once is more likely an identifier than
        # a repeated common term.
        if count <= 1:
            score += self.W_UNIQUE

        return max(0.0, min(1.0, score))

    # ---------------------------------------------------------------- signals
    def _role_signal(self, token: str) -> str:
        # Signal 2 — classify a token's structural role. Recognised structural
        # tokens (CONTROL/METRIC/EVENT/KEY) are inherently low-risk; only an
        # unrecognised token is labelled VALUE.
        if CONTROL_RE.match(token):
            return "CONTROL"
        low = token.lower()
        if low in PROTOCOL_TOKENS:
            return "CONTROL"
        if METRIC_RE.match(token):
            return "METRIC"
        if low in EVENT_WORDS:
            return "EVENT"
        if low in KEY_NAMES:
            return "KEY"
        return "VALUE"

    def _vocab_signal(self, token: str, role: str) -> str:
        # Signal 1 — VOCAB_CLASS. A recognised structural role is inherently
        # SYSTEM. Otherwise split the token on separators and judge by how many
        # parts are known safe words: all known → SYSTEM, none → UNKNOWN, mix → MIXED.
        if role != "VALUE":
            return "SYSTEM"
        parts = [p for p in re.split(r'[_\-./]', token.lower()) if p]
        if not parts:
            return "UNKNOWN"
        known = sum(1 for p in parts if p in SAFE_VOCABULARY)
        if known == len(parts):
            return "SYSTEM"
        if known == 0:
            return "UNKNOWN"
        return "MIXED"

    def _classify_source(self, text: str) -> str:
        # Signal 3 — classify the log source from keyword signatures. Returns the
        # category with the most keyword hits, or UNKNOWN if nothing matches.
        low = text.lower()
        best, best_hits = "UNKNOWN", 0
        for category, keywords in SOURCE_SIGNATURES.items():
            hits = sum(1 for kw in keywords if kw in low)
            if hits > best_hits:
                best, best_hits = category, hits
        return best

    def _entropy(self, token: str) -> float:
        # Shannon entropy in bits per character (average bits per symbol). Random
        # high-entropy strings (keys, hashes) approach log2(alphabet); short or
        # repetitive strings stay low. Compared against the 3.5 bits/char threshold.
        n = len(token)
        if n < 2:
            return 0.0
        counts = {}
        for ch in token:
            counts[ch] = counts.get(ch, 0) + 1
        entropy = 0.0
        for c in counts.values():
            p = c / n
            entropy -= p * math.log2(p)
        return entropy

    # --------------------------------------------------------------- escalate
    def _escalate(self, token: str, source: str) -> str:
        # ESCALATE action — the score is >= 0.8, so the signals are jointly
        # suspicious. Defer to the local LLM auditor with a single binary question.
        # The model sees only the token and a coarse source label, never real
        # context. YES tokenizes. ANY failure (network, bad response, parse error)
        # or timeout tokenizes anyway — Layer 2 never leaks a suspicious value.
        # Only an explicit NO leaves the token in place.
        try:
            prompt = (
                "You are an infrastructure PII detector. Answer with exactly one "
                "word: YES if the TOKEN is a real identifier (hostname, username, "
                "IP, path, domain, key, secret, email), or NO if it is a generic "
                f"non-identifying word.\nSOURCE_CLASS={source}\nTOKEN={token}\n"
                "Answer:"
            )
            response = requests.post(
                OLLAMA_URL,
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
                timeout=OLLAMA_TIMEOUT,
            )
            if response.status_code != 200:
                return str(self.vault.tokenize(token))  # fail closed → tokenize
            verdict = response.json().get("response", "").strip().upper()
            if verdict.startswith("NO"):
                return token  # auditor cleared it — leave in place
            return str(self.vault.tokenize(token))  # YES or unclear → tokenize
        except Exception:
            # Network down, model missing, malformed JSON, timeout — fail closed.
            return str(self.vault.tokenize(token))
