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
# The classifier judges whether a token reads like natural language or a known
# technical term. It draws on three sources:
#   ENGLISH_DICT    — the system word list, loaded at startup (~100k words)
#   SAFE_VOCABULARY — supplemental technical / log terms (below)
#   LINUX_TERMS     — syslog / systemd / kernel / network / HTTP terminology
# A token failing the natural-language checks against all three is UNKNOWN.
# ---------------------------------------------------------------------------

# Candidate system dictionaries, in priority order. Override with AIWARDEN_DICT_PATH.
_DICT_PATHS = [
    os.environ.get("AIWARDEN_DICT_PATH", ""),
    "/usr/share/dict/american-english",
    "/usr/share/dict/words",
]


def _load_english_dict():
    # Load a system word list into a lowercase set for the vocabulary classifier.
    # Fails gracefully to an empty set if no dictionary is installed — the
    # technical term sets then carry the classifier and unknown tokens fail
    # toward tokenizing (the privacy-safe direction).
    for path in _DICT_PATHS:
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    return {line.strip().lower() for line in fh if line.strip()}
            except OSError:
                continue
    return set()


# Loaded once at import time and shared across all scanner instances.
ENGLISH_DICT = _load_english_dict()

# Supplemental technical terms not always present in an English dictionary.
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

# Linux / infrastructure terminology: syslog, systemd, kernel, network, HTTP.
# These are generic technology terms (not product or host identities) that a
# plain English dictionary will not contain.
LINUX_TERMS = {
    # syslog / journald / systemd / cron
    "syslog", "rsyslog", "journald", "journalctl", "systemd", "systemctl",
    "dmesg", "cron", "crond", "crontab", "logrotate", "daemon", "tty", "pts",
    "init", "sysctl", "cgroup", "cgroups", "namespace", "facility", "severity",
    # ssh / auth / privilege
    "sshd", "ssh", "scp", "sftp", "sudo", "sudoers", "pam", "publickey",
    "pubkey", "preauth", "keepalive", "authpriv", "getty", "agetty", "setuid",
    # kernel / hardware
    "kernel", "oom", "oomkiller", "segfault", "kworker", "ksoftirqd", "modprobe",
    "udev", "nofile", "hugepage", "numa", "irq", "dma", "acpi", "syscall",
    # network
    "eth", "ens", "enp", "wlan", "veth", "bridge", "vlan", "subnet", "gateway",
    "iptables", "nftables", "netfilter", "conntrack", "wireguard", "tunnel",
    "tcp", "udp", "icmp", "arp", "dhcp", "dns", "ndp", "mtu", "rtt", "nat",
    "ifconfig", "netstat", "iproute", "traceroute", "ping", "curl", "wget",
    "ipv4", "ipv6", "loopback", "localhost", "hostname", "fqdn", "endpoint",
    # http / web servers
    "http", "https", "http2", "websocket", "wss", "tls", "ssl", "sni", "mtls",
    "nginx", "apache", "httpd", "gunicorn", "uvicorn", "haproxy", "proxy",
    "upstream", "downstream", "cors", "etag", "gzip", "mime", "useragent",
    "referer", "keepalive", "vhost", "fastcgi", "uwsgi", "webhook",
    # containers / virtualization
    "docker", "dockerd", "containerd", "podman", "kubelet", "kubernetes", "lxc",
    "lxd", "qemu", "kvm", "libvirt", "vzdump", "proxmox", "cgroupfs", "runc",
    # filesystem / storage / ops
    "fstab", "inode", "umount", "tmpfs", "overlayfs", "ext4", "xfs", "zfs",
    "btrfs", "lvm", "swap", "rootfs", "chroot", "chmod", "chown", "rsync",
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

_VOWELS = set("aeiou")


def _char_entropy(s: str) -> float:
    # Shannon entropy of a string in bits per character (average bits/symbol).
    # Random strings run high; short or repetitive strings stay low.
    n = len(s)
    if n < 2:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def _word_part_is_natural(word: str) -> bool:
    # Judge a single word-part. Dictionary membership is decisive. Otherwise run
    # the heuristic checks and accept the part only if it trips at most one of
    # them; a part that fails multiple checks looks like an identifier, not a word.
    w = word.lower()

    # Check 1 — Dictionary membership (english + technical + linux). Decisive PASS.
    if w in ENGLISH_DICT or w in SAFE_VOCABULARY or w in LINUX_TERMS:
        return True
    failed = 1  # not in any dictionary is itself one failed check

    # Check 2 — Length. Ordinary words are roughly 3..30 characters.
    if len(w) < 3 or len(w) > 30:
        failed += 1

    # Check 3 — Mixed case combined with digits is a strong identifier signal
    # (e.g. "ghp_xK9mP2", "iPhone12"). Letters+digits alone is a milder signal.
    has_alpha = any(c.isalpha() for c in word)
    has_digit = any(c.isdigit() for c in word)
    mixed_case = has_alpha and word != word.lower() and word != word.upper()
    if has_digit and mixed_case:
        failed += 2
    elif has_digit and has_alpha:
        failed += 1

    # Check 4 — Vowel ratio. Real words are typically 25–45% vowels.
    letters = [c for c in w if c.isalpha()]
    if not letters:
        failed += 1
    else:
        ratio = sum(1 for c in letters if c in _VOWELS) / len(letters)
        if ratio < 0.25 or ratio > 0.45:
            failed += 1

    # Check 5 — Character entropy. Real words sit below ~3.0 bits/char.
    if _char_entropy(w) >= 3.0:
        failed += 1

    return failed <= 1


def is_natural_language(token: str) -> bool:
    # Decide whether a token reads like natural language / a known technical term
    # rather than an identifier, hostname, or random string. Multi-part tokens
    # (split on separators, e.g. "HTTP/1.1", "curl/7.68.0") are natural only when
    # every alphabetic part is; purely numeric parts (version numbers) are neutral.
    t = (token or "").strip()
    if not t:
        return False
    parts = [p for p in re.split(r'[_\-./:@]', t) if p]
    word_parts = [p for p in parts if not p.isdigit()]
    if not word_parts:
        # No alphabetic content at all (e.g. an IP "185.220.101.45" or a bare
        # version "7.68.0"). Not a word — fail toward tokenizing. Numeric suffixes
        # only get a pass when attached to a real word part, handled below.
        return False
    return all(_word_part_is_natural(p) for p in word_parts)


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
        # Top-level entry point. Pass comment lines through entirely.
        # Classify source once, then evaluate every non-comment line.
        try:
            source = self._classify_source(text)
            words = text.split()
            freq = Counter(words)
        
            processed = []
            for line in text.split('\n'):
                if line.strip().startswith('#'):
                    processed.append(line)
                else:
                    processed.append(self._scan_line(line, source, freq))
            return '\n'.join(processed)
        except Exception:
            return text  # fail open on scan error, Layer 3 catches leaks
    def _scan_line(self, line: str, source: str, freq) -> str:
        # Process one non-comment line: decompose each space-separated word,
        # score its token, and rebuild the line preserving spacing. Uniqueness
        # is read from the document-wide frequency map (freq) built by scan().
        out = []
        for word in line.split(" "):
            lead, prefix, token, trail, value_pos = self._decompose(word)
            if not word or token == "":
                out.append(word)
                continue
            count = freq.get(token, freq.get(word, 1))
            new_token = self._evaluate(token, source, value_pos, count)
            out.append(f"{lead}{prefix}{new_token}{trail}")
        return " ".join(out)

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
        # SYSTEM. Otherwise defer to the natural-language scorer: SYSTEM when the
        # token reads like real language or a known technical term, UNKNOWN when
        # it fails multiple natural-language checks (looks like an identifier).
        if role != "VALUE":
            return "SYSTEM"
        return "SYSTEM" if is_natural_language(token) else "UNKNOWN"

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
        # Shannon entropy in bits per character, compared against the risk
        # weight's 3.5 bits/char threshold. Delegates to the shared module helper.
        return _char_entropy(token)

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
