"""ZKDP Sequence Formula Language transformer.

Converts sanitized pipeline output into a SURPRISE packet — the primary
outbound transmission unit. Per SPEC.md, the packet describes divergence from
baseline (predicted P vs actual A for each observable) on a sigma-class
timeline, with a single magnitude that gates transmission. Wall-clock time
never appears in the packet; only sigma class and sequence position survive.

The transformer consumes text the four sanitization layers have already
cleaned and re-frames each line as an event/state/sigma triple. It never
tokenizes anything on its own — every real value should already be a vault
token by the time the text reaches this stage.
"""

import re
import threading
from datetime import datetime


# --- Event classification ---------------------------------------------------
# Ordered keyword table. First matching entry wins, so more specific event
# types (TRANSCODE, MEM) outrank generic fallbacks (ERROR / START). The
# taxonomy follows SPEC EVENT_TYPE values plus the user-defined extensions
# (IMPORT, ERROR). Lines that match nothing are tagged ANOMALY at the event
# level; that is distinct from the packet-level TYPE field.
EVENT_KEYWORDS = (
    ("BIND",       ("server", "listening", "addr=", "port=", "bound")),
    ("AUTH",       ("login", "authentication", "publickey", "password", "session")),
    ("TRANSCODE",  ("transcode", "codec", "ffmpeg", "convert")),
    ("STREAM",     ("stream", "request", "response", " get ", " post ", " put ")),
    ("SCAN",       ("scan", "index", "library")),
    ("MEM",        ("memory", "mem=", "usage", "limit")),
    ("THROTTLE",   ("throttle", "rate limit", "slow")),
    ("DB",         ("database", "query", " db=", " db ")),
    ("IMPORT",     ("import", "path=")),
    ("START",      ("started", "starting", "running")),
    ("STOP",       ("stopped", "stopping", "killed", "exit ")),
    ("CONNECT",    ("connected", "connection")),
    ("DISCONNECT", ("disconnected", "closed")),
    ("ERROR",      ("error", "failed", "exception")),
)

# --- State classification (SPEC STATE values: +1, -1, null, WARN) -----------
# Priority: -1 (failure) dominates WARN dominates +1. A line that mentions
# both "failed" and "completed" is treated as a failure — observed outcome
# trumps narrative phrasing.
POSITIVE_WORDS = ("succeeded", "accepted", " ok ", "healthy",
                  "started", "connected", "completed")
NEGATIVE_WORDS = ("failed", "error", "refused", "denied",
                  "killed", "timeout", "invalid")
WARN_WORDS     = ("warn", "high", "exceeded", "slow")

# --- Sigma classification ---------------------------------------------------
# SPEC defines exactly five classes for the rate at which events arrive.
# Sigma is derived from the delta between two consecutive event timestamps;
# the wall-clock value itself never enters the packet. The first event in a
# packet has no previous anchor and is reported as sigma-0 (instant from
# itself) so the SCALE array stays the same length as DIV.
_SIGMA_BUCKETS = (
    (1.0,      "sigma-0"),  # under 1 second        — instant
    (60.0,     "sigma-1"),  # under 1 minute        — rapid, seconds
    (86400.0,  "sigma-2"),  # under 1 day           — minutes to hours
    (604800.0, "sigma-3"),  # under 1 week          — hours to days
)
_SIGMA_OVERFLOW = "sigma-4"  # 1 week or more — days+ to weeks+

# --- Timestamp / token extraction -------------------------------------------
# Layer 1 protects date/time substrings from tokenization so the original
# format survives into the SFL stage. The captured value is used only to
# compute sigma class and is discarded afterwards — it never crosses into the
# packet payload.
_TS_RE = re.compile(
    r'(\d{4})[/-](\d{2})[/-](\d{2})[T ](\d{2}):(\d{2}):(\d{2})'
)
# A vault token is exactly 8 decimal digits (TokenVault generates from
# 10000000..99999999). The 4-digit year in the date prefix never collides
# with that shape, so a plain \b\d{8}\b is enough to find the service token.
_VAULT_TOKEN_RE = re.compile(r'\b\d{8}\b')


def _parse_timestamp(line):
    m = _TS_RE.search(line)
    if not m:
        return None
    try:
        return datetime(*(int(g) for g in m.groups()))
    except ValueError:
        return None


def _extract_service_token(line):
    # First vault-shaped token on the line identifies *which* observable the
    # event refers to. The identity behind the token stays vaulted locally;
    # only the token integer is transmitted. A line with no surviving token
    # (e.g. a pure date/time anchor) is reported with token=0 so the packet
    # shape stays uniform across all events.
    m = _VAULT_TOKEN_RE.search(line)
    return int(m.group(0)) if m else 0


def _sigma_from_delta(delta_seconds):
    if delta_seconds is None or delta_seconds < 0:
        return "sigma-0"
    for upper, label in _SIGMA_BUCKETS:
        if delta_seconds < upper:
            return label
    return _SIGMA_OVERFLOW


def _classify_event(line):
    # Pad the haystack so word-bounded keywords like " get " or " ok " match
    # at line start/end without a separate word-boundary regex per keyword.
    low = " " + line.lower() + " "
    for event_type, words in EVENT_KEYWORDS:
        if any(w in low for w in words):
            return event_type
    return "ANOMALY"


def _classify_state(line):
    low = " " + line.lower() + " "
    if any(w in low for w in NEGATIVE_WORDS):
        return "-1"
    if any(w in low for w in WARN_WORDS):
        return "WARN"
    if any(w in low for w in POSITIVE_WORDS):
        return "+1"
    return None


def _classify_packet(events, scale):
    # SPEC priorities, applied in order. The first rule that fires wins,
    # because the descriptions are not mutually exclusive on a real packet.
    fast = {"sigma-0", "sigma-1"}

    # CASCADE: multiple -1 observables whose temporal spacing is fast and
    # whose sequence positions are adjacent — a propagating dependency chain.
    neg_idx = [i for i, e in enumerate(events) if e["a"] == "-1"]
    if len(neg_idx) >= 2:
        for j in range(1, len(neg_idx)):
            if neg_idx[j] - neg_idx[j - 1] == 1 and scale[neg_idx[j]] in fast:
                return "CASCADE"

    # DRAIN: a finite-resource event (MEM/DISK) at WARN-or-worse — depletion
    # shape. The only packet type that fires before anything has failed.
    for e in events:
        if e["event"] in ("MEM", "DISK") and e["a"] in ("WARN", "-1"):
            return "DRAIN"

    # DRIFT: state changes spread across a slow sigma. No single step is
    # acute but the cumulative shape is.
    slow = {"sigma-3", "sigma-4"}
    if any(s in slow for s in scale) and len({e["a"] for e in events}) > 1:
        return "DRIFT"

    # SPIKE: single isolated divergence.
    if len(neg_idx) == 1:
        return "SPIKE"

    # ANOMALY: nothing else fits — unrecognized failure shape.
    return "ANOMALY"


def _magnitude(events):
    # Surprise magnitude = fraction of observation-weight that diverged from
    # baseline. -1 counts as a full divergence (1.0); WARN as half (0.5);
    # +1 and null contribute nothing. Range [0.0, 1.0]. Below the consumer's
    # configured threshold no packet should fire (handled by the caller).
    if not events:
        return 0.0
    weights = {"-1": 1.0, "WARN": 0.5, "+1": 0.0, None: 0.0}
    total = sum(weights.get(e["a"], 0.0) for e in events)
    return round(min(1.0, total / len(events)), 3)


class SFLTransformer:
    """Convert sanitized log text into a ZKDP SURPRISE packet.

    transform(text, vault) parses one or more sanitized lines, classifies
    each into an event-state-sigma triple, and returns a dict matching the
    SPEC.md SURPRISE grammar (lowercase JSON-friendly keys). The vault
    parameter is accepted for API symmetry with the sanitization pipeline;
    the transformer never tokenizes itself and never consults the vault to
    learn identities — only to verify what arrived as a token has the right
    shape, which the four earlier layers have already enforced.
    """

    # SEQ is a monotonic counter shared across every transformer instance —
    # SPEC: "Replaces all timestamps. Provides ordering without exposing
    # wall-clock time." Locked so concurrent callers cannot collide.
    _seq_lock = threading.Lock()
    _next_seq = 0

    @classmethod
    def _allocate_seq(cls):
        with cls._seq_lock:
            cls._next_seq += 1
            return cls._next_seq

    def transform(self, text, vault=None):
        if not text or not text.strip():
            return self._empty_packet()

        # Lines kept in arrival order so sequence position S(n) is exactly
        # the line's index in the input. Blank lines are skipped so they do
        # not introduce phantom events that distort sigma class or magnitude.
        lines = [ln for ln in text.split("\n") if ln.strip()]

        events = []
        scale = []
        prev_ts = None
        for i, line in enumerate(lines):
            ts = _parse_timestamp(line)
            delta = (ts - prev_ts).total_seconds() if (ts and prev_ts) else None
            scale.append(_sigma_from_delta(delta))

            events.append({
                "s":     i,
                "token": _extract_service_token(line),
                "event": _classify_event(line),
                # Baseline assumption is +1 (every observable should be
                # operating normally). Divergence drives MAG; without a real
                # baseline registry attached we treat +1 as the universal
                # prediction so every actual non-+1 reads as a divergence.
                "p":     "+1",
                "a":     _classify_state(line),
            })
            # Only advance the temporal anchor when this line carried a real
            # parseable timestamp; missing ones must not reset prev_ts to
            # None or sigma would collapse for the next anchored line.
            if ts is not None:
                prev_ts = ts

        return {
            "type":        "SURPRISE",
            "base":        "v1",
            "seq":         self._allocate_seq(),
            "packet_type": _classify_packet(events, scale),
            "mag":         _magnitude(events),
            "div":         events,
            "scale":       scale,
        }

    @classmethod
    def _empty_packet(cls):
        # An empty / whitespace-only input still produces a well-formed packet
        # so downstream gating logic never has to special-case None.
        return {
            "type":        "SURPRISE",
            "base":        "v1",
            "seq":         cls._allocate_seq(),
            "packet_type": "ANOMALY",
            "mag":         0.0,
            "div":         [],
            "scale":       [],
        }
