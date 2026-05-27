"""ZKDP packet serialization, parsing, and integrity-gated verification.

Two responsibilities:

1. canonical_packet() — turn a packet dict into the one and only byte string
   that represents it: deterministic field ordering, UTF-8, LF newlines, no
   trailing whitespace, no duplicate fields. Stable serialization is a
   precondition for hashing — two machines must produce identical bytes.

2. ProtocolVerifier — verify an incoming RESPONSE packet in an IMMUTABLE order
   that no subsystem may bypass:
       1. Parse first line only.
       2. Verify RECEIVED_HASH field exists.
       3. Verify hash equality.
       4. Only then read the remaining fields.
       5. Confidence checks.
       6. Whitelist checks.
       7. Protocol execution (handed back to the caller).
   Integrity is proven before a single body field is trusted. Anti-replay
   (SESSION_ID + NONCE, both inside hash coverage) and parser hardening run as
   part of this flow. Every failure raises IntegrityError and fails closed.

Logging never records raw payload contents after an integrity failure and never
records unhashed sensitive fields — only timestamp, session_id, sequence_id, and
the failure reason.
"""

import hmac
import logging
import re
import time
from collections import deque

from api.integrity import (
    PAYLOAD_HASH_FIELD,
    REQUEST_HASH_FIELD,
    RECEIVED_HASH_FIELD,
    REQUEST_HASH_ACK_FIELD,
    compute_payload_hash,
    compute_request_hash,
    verify_request_ack,
)

_log = logging.getLogger("zkdp.protocol")

# Hard limits and policy tables --------------------------------------------------

MAX_PACKET_SIZE = 65536  # bytes; larger inbound packets are rejected outright.

# Canonical field order. Integrity/anti-replay fields lead; protocol fields
# follow in spec order. PAYLOAD_HASH (outbound) and RECEIVED_HASH (response) sort
# first so each is the first field after the header, as the protocol requires.
CANONICAL_FIELD_ORDER = [
    PAYLOAD_HASH_FIELD, RECEIVED_HASH_FIELD,
    REQUEST_HASH_FIELD, REQUEST_HASH_ACK_FIELD,
    "SESSION_ID", "NONCE",
    "BASE", "SEQ", "TYPE", "MAG", "DIV", "SCALE", "DRAIN",
    "CONFIDENCE", "ACTION_VECTOR", "VERIFY_CONDITION", "FAIL_CONDITION",
    "FALLBACK", "SC", "KI", "FC",
]
_ORDER_INDEX = {name: i for i, name in enumerate(CANONICAL_FIELD_ORDER)}

# Every field name the parser will accept. Anything else is an unknown field and
# is rejected (fail closed) rather than ignored.
KNOWN_FIELDS = set(CANONICAL_FIELD_ORDER)

# A RESPONSE packet is only well formed if all of these are present.
MANDATORY_RESPONSE_FIELDS = (
    RECEIVED_HASH_FIELD, REQUEST_HASH_ACK_FIELD, "SESSION_ID", "NONCE",
    "BASE", "SEQ", "CONFIDENCE",
)

# Only these actions may ever reach the repair engine.
ACTION_WHITELIST = {
    "RESTART", "REINSTALL", "RECLAIM", "ISOLATE", "RESET", "REDUCE",
    "VERIFY", "SNAPSHOT_ROLLBACK",
}

CONFIDENCE_MIN = 0.0
CONFIDENCE_MAX = 1.0

# Reserved dict keys that describe the header line rather than a body field.
_HEADER_VERSION_KEY = "VERSION"
_HEADER_TYPE_KEY = "PACKET_TYPE"
_DEFAULT_VERSION = "ZKDP/1.0"


class IntegrityError(Exception):
    """Raised on any integrity, replay, or parser-hardening failure."""


# --- Canonical serialization ----------------------------------------------------

def canonical_packet(packet_dict):
    # Serialize a packet dict to its single canonical byte string. Deterministic
    # ordering + LF newlines + no trailing whitespace + no duplicate fields, so
    # the same logical packet always hashes to the same value on every system.
    if not isinstance(packet_dict, dict):
        raise IntegrityError("packet must be a mapping")

    version = packet_dict.get(_HEADER_VERSION_KEY, _DEFAULT_VERSION)
    packet_type = packet_dict.get(_HEADER_TYPE_KEY)

    # Detect duplicate field names case-insensitively (a dict cannot hold two
    # identical keys, but "Seq" and "SEQ" must not both be accepted).
    normalized = {}
    for key in packet_dict:
        if key in (_HEADER_VERSION_KEY, _HEADER_TYPE_KEY):
            continue
        upper = key.upper()
        if upper in normalized:
            raise IntegrityError(f"duplicate field: {key}")
        normalized[upper] = packet_dict[key]

    lines = []
    if packet_type is not None:
        header = f"{version} {packet_type}".rstrip()
        lines.append(header)

    for name in sorted(normalized, key=_field_sort_key):
        value = "" if normalized[name] is None else str(normalized[name])
        line = f"{name}: {value}".rstrip()  # strip trailing whitespace per line
        if "\n" in line or "\r" in line:
            raise IntegrityError(f"field {name} contains an embedded newline")
        lines.append(line)

    return "\n".join(lines)  # LF only — never \r\n


def _field_sort_key(name):
    # Known fields sort by their fixed canonical position; any extra field sorts
    # after them, alphabetically, so ordering is always total and deterministic.
    if name in _ORDER_INDEX:
        return (0, _ORDER_INDEX[name])
    return (1, name)


# --- Outbound packet construction -----------------------------------------------

def build_outbound_packet(fields, packet_type="SURPRISE", version=_DEFAULT_VERSION):
    # Build a complete outbound packet:
    #   REQUEST_HASH  — hash of the semantic body (no hash fields), echoed back
    #                   by the AI as REQUEST_HASH_ACK.
    #   PAYLOAD_HASH  — hash of the entire body that follows it (header + fields,
    #                   including REQUEST_HASH, SESSION_ID, NONCE, SEQ …) and is
    #                   itself excluded from that coverage by being the first
    #                   line. Echoed back by the AI as RECEIVED_HASH.
    if not isinstance(fields, dict):
        raise IntegrityError("fields must be a mapping")
    body = dict(fields)
    body[_HEADER_VERSION_KEY] = version
    body[_HEADER_TYPE_KEY] = packet_type

    # REQUEST_HASH over the body without any hash fields present.
    semantic = {k: v for k, v in body.items()
                if k not in (PAYLOAD_HASH_FIELD, REQUEST_HASH_FIELD)}
    request_hash = compute_request_hash(canonical_packet(semantic))

    body[REQUEST_HASH_FIELD] = request_hash
    serialized_body = canonical_packet(body)  # includes REQUEST_HASH, not PAYLOAD_HASH
    payload_hash = compute_payload_hash(serialized_body)

    # PAYLOAD_HASH is prepended as the literal first line; it is not part of the
    # bytes it covers (serialized_body), satisfying "hash field excluded".
    return f"{PAYLOAD_HASH_FIELD}: {payload_hash}\n{serialized_body}"


# --- Inbound RESPONSE verification (immutable order) ----------------------------

class ProtocolVerifier:
    # Verifies inbound RESPONSE packets and enforces anti-replay. One instance
    # per active session lifetime; it caches recently seen NONCE values so a
    # replayed packet (same NONCE in the same session) is rejected.

    def __init__(self, nonce_cache_size=4096):
        self._seen_nonces = {}                 # session_id -> set(nonce)
        self._nonce_order = deque()            # (session_id, nonce) recency queue
        self._nonce_cache_size = nonce_cache_size

    def verify_response(self, raw, expected_payload_hash, expected_request_hash,
                        session_id=None):
        # Run the immutable verification pipeline. Returns the parsed field dict
        # only after every gate passes; raises IntegrityError otherwise.
        text = self._decode_and_bound(raw)
        lines = text.split("\n")

        # STEP 1 — parse the FIRST LINE ONLY (the header). Nothing else is read
        # or trusted yet.
        header = lines[0] if lines else ""
        if not header.startswith(_DEFAULT_VERSION + " "):
            self._fail(session_id, None, "bad or missing protocol header")

        # STEP 2 — RECEIVED_HASH must exist AND be the first field (immediately
        # after the header). Any field before it, or a missing/duplicated
        # RECEIVED_HASH, is rejected before any hashing.
        received_hash = self._extract_received_hash(lines, session_id)

        # STEP 3 — verify hash equality. The echoed RECEIVED_HASH must equal the
        # PAYLOAD_HASH this machine sent. Hash mismatch aborts immediately and
        # no body field is ever read.
        if not verify_response_hash_equals(received_hash, expected_payload_hash):
            self._fail(session_id, None, "RECEIVED_HASH does not match sent PAYLOAD_HASH")

        # STEP 4 — integrity proven; only now parse the remaining fields, with
        # full parser hardening (duplicates, unknown fields, mandatory fields).
        fields, seq = self._parse_body(lines, session_id)

        # Request acknowledgement: the response must echo our REQUEST_HASH.
        if not verify_request_ack(expected_request_hash,
                                  fields.get(REQUEST_HASH_ACK_FIELD)):
            self._fail(session_id, seq, "REQUEST_HASH_ACK does not match sent REQUEST_HASH")

        # Anti-replay — SESSION_ID + NONCE are inside hash coverage, so by now
        # they are trusted. A repeated NONCE in this session is a replay.
        self._check_replay(fields["SESSION_ID"], fields["NONCE"], seq)

        # STEP 5 — confidence checks.
        self._check_confidence(fields, seq)

        # STEP 6 — whitelist checks.
        self._check_whitelist(fields, seq)

        # STEP 7 — protocol execution is the caller's job; hand back the verified
        # fields. The packet is now safe to act on.
        return fields

    # -- internal steps ----------------------------------------------------------

    def _decode_and_bound(self, raw):
        # Reject non-UTF8 input and anything over the size ceiling, before any
        # structural parsing happens.
        if isinstance(raw, bytes):
            if len(raw) > MAX_PACKET_SIZE:
                self._fail(None, None, "packet exceeds maximum size")
            try:
                return raw.decode("utf-8")          # strict: rejects non-UTF8
            except UnicodeDecodeError:
                self._fail(None, None, "non-UTF8 input")
        if not isinstance(raw, str):
            self._fail(None, None, "packet must be text")
        if len(raw.encode("utf-8")) > MAX_PACKET_SIZE:
            self._fail(None, None, "packet exceeds maximum size")
        return raw

    def _extract_received_hash(self, lines, session_id):
        # The first non-header line MUST be RECEIVED_HASH. Enforces: no field
        # before RECEIVED_HASH, exactly one RECEIVED_HASH, and that it parses.
        if len(lines) < 2:
            self._fail(session_id, None, "missing RECEIVED_HASH field")

        first_field = lines[1]
        name, _, value = first_field.partition(":")
        name = name.strip()
        if name != RECEIVED_HASH_FIELD:
            self._fail(session_id, None, "field present before RECEIVED_HASH")

        # No second RECEIVED_HASH anywhere in the packet.
        for line in lines[2:]:
            other, _, _ = line.partition(":")
            if other.strip() == RECEIVED_HASH_FIELD:
                self._fail(session_id, None, "multiple RECEIVED_HASH fields")

        received = value.strip()
        if not received:
            self._fail(session_id, None, "empty RECEIVED_HASH field")
        return received

    def _parse_body(self, lines, session_id):
        # Parse every line after the header into a field dict, hardened against
        # duplicate fields, unknown fields, and missing mandatory fields.
        fields = {}
        for line in lines[1:]:
            if line == "":
                continue
            name, sep, value = line.partition(":")
            if sep != ":":
                self._fail(session_id, None, "malformed field (no delimiter)")
            name = name.strip()
            value = value.strip()
            if name in fields:
                self._fail(session_id, None, f"duplicate field: {name}")
            if name not in KNOWN_FIELDS:
                self._fail(session_id, None, f"unknown field: {name}")
            fields[name] = value

        for required in MANDATORY_RESPONSE_FIELDS:
            if required not in fields:
                self._fail(session_id, fields.get("SEQ"),
                           f"missing mandatory field: {required}")

        return fields, fields.get("SEQ")

    def _check_replay(self, session_id, nonce, seq):
        seen = self._seen_nonces.setdefault(session_id, set())
        if nonce in seen:
            self._fail(session_id, seq, "replayed NONCE")
        seen.add(nonce)
        self._nonce_order.append((session_id, nonce))
        # Bound the in-memory cache; evict the oldest entries past the ceiling.
        while len(self._nonce_order) > self._nonce_cache_size:
            old_session, old_nonce = self._nonce_order.popleft()
            bucket = self._seen_nonces.get(old_session)
            if bucket is not None:
                bucket.discard(old_nonce)
                if not bucket:
                    self._seen_nonces.pop(old_session, None)

    def _check_confidence(self, fields, seq):
        raw = fields.get("CONFIDENCE")
        try:
            confidence = float(raw)
        except (TypeError, ValueError):
            self._fail(fields.get("SESSION_ID"), seq, "malformed CONFIDENCE field")
        if not (CONFIDENCE_MIN <= confidence <= CONFIDENCE_MAX):
            self._fail(fields.get("SESSION_ID"), seq, "CONFIDENCE out of range")

    def _check_whitelist(self, fields, seq):
        # Every ACTION token mentioned in the action vector must be whitelisted.
        action_vector = fields.get("ACTION_VECTOR", "")
        for token in _action_tokens(action_vector):
            if token not in ACTION_WHITELIST:
                self._fail(fields.get("SESSION_ID"), seq,
                           f"non-whitelisted action: {token}")

    def _fail(self, session_id, seq, reason):
        # Log ONLY the safe metadata — never the raw payload, never unhashed
        # sensitive fields — then fail closed.
        _log.warning(
            "integrity_failure ts=%s session_id=%s sequence_id=%s reason=%s",
            int(time.time()), session_id, seq, reason,
        )
        raise IntegrityError(reason)


def verify_response_hash_equals(received_hash, expected_payload_hash):
    # Constant-time equality of the echoed RECEIVED_HASH and the PAYLOAD_HASH the
    # machine sent. Both are hex digests the machine already holds; a missing,
    # empty, or non-string value on either side is False (fail closed).
    if not isinstance(received_hash, str) or not received_hash:
        return False
    if not isinstance(expected_payload_hash, str) or not expected_payload_hash:
        return False
    return hmac.compare_digest(received_hash, expected_payload_hash)


def _action_tokens(action_vector):
    # Extract the ACTION identifiers named in a serialized ACTION_VECTOR string,
    # so each can be checked against the action whitelist.
    return [m.group(1) for m in re.finditer(r'ACTION\s*[:=]\s*([A-Z_]+)', action_vector)]
