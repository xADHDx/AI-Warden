"""Request/response integrity verification for ZKDP packets.

Hashing is BLAKE3 over the EXACT raw UTF-8 bytes of the payload. There is no
whitespace normalization, no newline normalization, no trimming, and no encoding
conversion of any kind — the bytes are the contract. The hash is therefore
deterministic across systems, and any mutation after hashing invalidates the
packet. Protocol serialization uses LF newlines only (enforced in api.protocol),
so the bytes hashed here match the bytes on the wire.

The hash field itself is never part of the bytes it hashes: outbound packets
carry PAYLOAD_HASH as their first field, computed over the packet body that
follows it; responses echo it back as RECEIVED_HASH.
"""

import hmac

import blake3

# Field names (kept here so api.protocol and callers agree on the wire labels).
PAYLOAD_HASH_FIELD = "PAYLOAD_HASH"
RECEIVED_HASH_FIELD = "RECEIVED_HASH"
REQUEST_HASH_FIELD = "REQUEST_HASH"
REQUEST_HASH_ACK_FIELD = "REQUEST_HASH_ACK"


def compute_payload_hash(payload):
    # BLAKE3 over the exact UTF-8 bytes of payload. No normalization whatsoever.
    # Non-str input is rejected rather than coerced (fail closed; never guess the
    # caller's intended bytes).
    if not isinstance(payload, str):
        raise TypeError("payload must be str; exact UTF-8 bytes are hashed")
    return blake3.blake3(payload.encode("utf-8")).hexdigest()


def verify_response_hash(payload, received_hash):
    # True only when received_hash exactly equals the hash recomputed from the
    # exact bytes of payload. A missing, empty, or non-string hash is False
    # (fail closed). Comparison is constant-time to avoid a timing oracle.
    if not isinstance(payload, str):
        return False
    if not isinstance(received_hash, str) or not received_hash:
        return False
    return hmac.compare_digest(compute_payload_hash(payload), received_hash)


# --- Request integrity: the same primitive applied to the outbound request ----

def compute_request_hash(request_payload):
    # The request's stable integrity hash. The AI must echo it back verbatim as
    # REQUEST_HASH_ACK so the machine can prove the response answers THIS request.
    return compute_payload_hash(request_payload)


def verify_request_ack(sent_request_hash, ack_hash):
    # True only when the echoed REQUEST_HASH_ACK exactly equals the REQUEST_HASH
    # the machine sent. Anything else (missing, altered, wrong type) is False.
    if not isinstance(sent_request_hash, str) or not sent_request_hash:
        return False
    if not isinstance(ack_hash, str) or not ack_hash:
        return False
    return hmac.compare_digest(sent_request_hash, ack_hash)
