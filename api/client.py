"""ZKDP API client — two-channel transmission to the Claude diagnostic AI.

Channel B (CONTEXT) is sent first to establish ontology bindings (SC/KI/FC)
the AI uses to interpret Channel A's tokens. Channel A (SURPRISE) carries
the actual diagnostic payload. Per SPEC.md line 282 the two channels are
sent as SEPARATE API calls and are never merged into a single request.

The Channel A request is BLAKE3-hashed end to end:
  * PAYLOAD_HASH is the first wire byte and is excluded from its own coverage.
  * REQUEST_HASH is computed over the semantic body and echoed back as
    REQUEST_HASH_ACK so the response is provably an answer to THIS request.

On receipt every response is run through ProtocolVerifier's immutable pipeline:
  parse header  →  RECEIVED_HASH-first check  →  hash equality  →  body parse
  →  REQUEST_HASH_ACK  →  anti-replay (NONCE)  →  CONFIDENCE  →  whitelist.

Any failure raises IntegrityError. On any other error (API auth, network,
parser) the client logs timestamp + session_id only and returns None — the
raw payload, request body, and response body never enter the log stream.

CONFIDENCE below 0.7 returns None — repair is not dispatched on uncertain
diagnoses (SPEC.md: "Confidence and whitelist gating").
"""

import json
import logging
import os
import time
import uuid

from anthropic import (
    Anthropic,
    APIConnectionError,
    APIError,
    APIStatusError,
    AuthenticationError,
)

from api.integrity import PAYLOAD_HASH_FIELD, REQUEST_HASH_FIELD
from api.protocol import IntegrityError, ProtocolVerifier, build_outbound_packet


# ---------------------------------------------------------------------------
# Spec-fixed constants
# ---------------------------------------------------------------------------

# System prompt is byte-for-byte the text the spec mandates for every ZKDP
# diagnostic API call. Do not edit, paraphrase, or interpolate values into it
# — drift here breaks the prompt-cache prefix and the "no natural language"
# contract the AI side relies on.
SYSTEM_PROMPT = (
    "You are a ZKDP diagnostic AI. Respond only in ZKDP protocol "
    "language. No natural language. No prose. Any response not "
    "conforming to ZKDP response format will be rejected."
)

# Model and max_tokens pinned by the operator. claude-sonnet-4-20250514 is
# deprecated (retires 2026-06-15) — see shared/models.md; the operator has
# accepted that risk. Migrate to claude-sonnet-4-6 before the retirement date.
MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 1000

# Repair gate. CONFIDENCE below this floor returns None — the AI was not
# certain enough to act on. Tunable per deployment; spec recommends 0.7.
CONFIDENCE_FLOOR = 0.7

_log = logging.getLogger("zkdp.client")


class ConfigError(Exception):
    """Raised when client configuration is invalid (missing API key, etc.)."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class ZKDPClient:
    """Sends ZKDP packets to the Claude diagnostic AI on two separate channels.

    One client instance = one ZKDP session. The session_id allocated at
    construction time scopes the verifier's NONCE replay cache, so a single
    long-lived client correctly rejects replayed responses within its session.
    Spawn a new client for a new session.
    """

    def __init__(self):
        # API key MUST come from the environment — hardcoding it would commit
        # a credential to source control. A missing or empty key fails fast
        # at construction time so the caller never gets a half-built client.
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ConfigError("ANTHROPIC_API_KEY is not set in the environment")

        # The SDK reads the key from kwargs (not from os.environ a second
        # time) so a key rotated mid-process still wins.
        self._client = Anthropic(api_key=api_key)

        # Session-scoped identifiers. session_id stays stable for the life of
        # the client; NONCE is regenerated per Channel A send.
        self._session_id = str(uuid.uuid4())
        self._verifier = ProtocolVerifier()

    # -- public entry point -------------------------------------------------

    def send(self, surprise_packet, context_packet, vault):
        """Send Channel B then Channel A; return the parsed response or None.

        ``vault`` is accepted for API symmetry with the rest of the pipeline
        but is not consulted — BLAKE3 needs no key and the AI is not given
        access to vault state. The argument is present so the signature
        matches the sanitization-pipeline convention.

        Returns:
            dict with confidence, action_vector, verify_condition,
            fail_condition, fallback — only when the response verifies
            integrity AND confidence is at or above the floor.
            None when confidence is below the floor or any non-integrity
            error occurred (auth, network, parse).

        Raises:
            ConfigError — only from __init__; included here so callers know
                where it can surface.
            IntegrityError — when the response fails hash verification,
                anti-replay, the immutable parser, the confidence range
                check, or the action whitelist. Propagates unchanged; the
                verifier has already logged the safe metadata.
        """
        try:
            # Channel B first — CONTEXT packet, ontology bindings only. Spec
            # mandates this precede Channel A so the AI has the lookup
            # context ready before any SURPRISE is read.
            self._send_channel_b(context_packet)

            # Channel A — actual diagnostic payload, integrity-hashed.
            response_text, payload_hash, request_hash = (
                self._send_channel_a(surprise_packet)
            )

            # Immutable verification pipeline (see ProtocolVerifier docs):
            # header parse → RECEIVED_HASH first → hash equality → body
            # parse → ACK → anti-replay → confidence range → whitelist.
            fields = self._verifier.verify_response(
                response_text,
                payload_hash,
                request_hash,
                session_id=self._session_id,
            )

            # CONFIDENCE gate. The verifier already proved 0 ≤ value ≤ 1;
            # here we apply the repair floor. Below the floor we return
            # None so no action is dispatched.
            confidence = float(fields["CONFIDENCE"])
            if confidence < CONFIDENCE_FLOOR:
                self._log_low_confidence(confidence)
                return None

            return {
                "confidence":       confidence,
                "action_vector":    fields.get("ACTION_VECTOR", ""),
                "verify_condition": fields.get("VERIFY_CONDITION", ""),
                "fail_condition":   fields.get("FAIL_CONDITION", ""),
                "fallback":         fields.get("FALLBACK", ""),
            }

        except IntegrityError:
            # ProtocolVerifier._fail() has already emitted a structured log
            # line with timestamp / session_id / seq / reason and crucially
            # no payload bytes. Re-logging here risks accidentally widening
            # what we log — propagate the exception untouched.
            raise

        except AuthenticationError as e:
            # Bad / missing API key. The exception's repr can include URL
            # fragments — capture status code only.
            self._log_api_failure("authentication_error", getattr(e, "status_code", 401))
            return None

        except APIStatusError as e:
            # Any non-401 API status error. Log only the HTTP status; never
            # the message body, which may echo our payload.
            self._log_api_failure("api_status_error", e.status_code)
            return None

        except APIConnectionError:
            # Network problem reaching api.anthropic.com.
            self._log_api_failure("api_connection_error", None)
            return None

        except APIError:
            # Catch-all for any SDK-side API error not covered above.
            self._log_api_failure("api_error", None)
            return None

        except Exception as e:
            # Final defensive net. Log only the exception class name; do not
            # call str(e) — exception args sometimes contain payload echoes.
            self._log_api_failure(type(e).__name__, None)
            return None

    # -- channels -----------------------------------------------------------

    def _send_channel_b(self, context_packet):
        # Channel B is the ontology-only side channel. SC / KI / FC integers
        # mean nothing without the local Service Profile Registry; the AI
        # uses them to constrain its diagnostic search space without ever
        # seeing a real service name.
        fields = {
            "BASE": "v1",
            "SC":   int(context_packet.get("SC", 0)),
            "KI":   int(context_packet.get("KI", 0)),
            "FC":   int(context_packet.get("FC", 0)),
        }
        packet_text = build_outbound_packet(fields, packet_type="CONTEXT")
        # We fire Channel B and discard the response — it carries no
        # SURPRISE-shaped diagnosis, only an ontology acknowledgement, and
        # the spec does not require integrity verification on this channel.
        self._call_api(packet_text)

    def _send_channel_a(self, surprise_packet):
        # Map the SFL packet dict onto the canonical wire fields. DIV and
        # SCALE serialize as compact JSON so they survive transport intact
        # — canonical_packet() forbids embedded newlines, which Python's
        # default str() of a list with nested dicts would not produce, but
        # json.dumps is the unambiguous choice and round-trips losslessly.
        fields = {
            "SESSION_ID": self._session_id,
            "NONCE":      str(uuid.uuid4()),
            "BASE":       surprise_packet.get("base", "v1"),
            "SEQ":        str(surprise_packet.get("seq", 0)),
            "TYPE":       surprise_packet.get("packet_type", "ANOMALY"),
            "MAG":        str(surprise_packet.get("mag", 0.0)),
            "DIV":        json.dumps(surprise_packet.get("div", []), separators=(",", ":")),
            "SCALE":      json.dumps(surprise_packet.get("scale", []), separators=(",", ":")),
        }
        packet_text = build_outbound_packet(fields, packet_type="SURPRISE")

        # The verifier needs the exact hashes we sent so it can prove the
        # response answers THIS request. Extract them straight back out of
        # the bytes we are about to put on the wire — recomputing would be
        # both wasteful and an opportunity for drift.
        payload_hash = self._extract_first_line_value(packet_text, PAYLOAD_HASH_FIELD)
        request_hash = self._extract_field(packet_text, REQUEST_HASH_FIELD)

        response_text = self._call_api(packet_text)
        return response_text, payload_hash, request_hash

    # -- HTTP ---------------------------------------------------------------

    def _call_api(self, packet_text):
        # One messages.create call. No streaming (max_tokens 1000 is well
        # under the SDK's timeout threshold), no adaptive thinking (the
        # response shape is strict ZKDP — thinking blocks would clutter
        # parsing and waste tokens), no prompt caching (per-call payloads
        # differ on every request, breaking the prefix-match invariant).
        response = self._client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": packet_text}],
        )
        # Concatenate any text blocks (this prompt yields exactly one in
        # practice). Non-text blocks are silently dropped — they shouldn't
        # appear under this system prompt, and if they do the verifier
        # will reject the resulting string as malformed.
        return "".join(b.text for b in response.content if b.type == "text")

    # -- utilities ----------------------------------------------------------

    @staticmethod
    def _extract_first_line_value(packet_text, field_name):
        # First wire line of a packet built by build_outbound_packet() is
        # always "PAYLOAD_HASH: <hex>". Parsing that here keeps the client
        # from having to know the internal format of build_outbound_packet.
        first_line = packet_text.split("\n", 1)[0]
        prefix = f"{field_name}: "
        if not first_line.startswith(prefix):
            raise IntegrityError(f"outbound packet missing first-line {field_name}")
        return first_line[len(prefix):].strip()

    @staticmethod
    def _extract_field(packet_text, field_name):
        # Linear scan for the named field in the body. Fine for the small
        # field counts ZKDP packets carry; not worth indexing.
        prefix = f"{field_name}: "
        for line in packet_text.split("\n"):
            if line.startswith(prefix):
                return line[len(prefix):].strip()
        raise IntegrityError(f"outbound packet missing {field_name}")

    # -- safe logging -------------------------------------------------------

    def _log_api_failure(self, error_type, status_code):
        # Failure metadata is ts + session_id + error class + optional HTTP
        # status. Deliberately omits exception args, request body, response
        # body, headers, and URLs — any of those could echo the sanitized
        # payload back into a log destination.
        _log.warning(
            "api_failure ts=%s session_id=%s error=%s status=%s",
            int(time.time()), self._session_id, error_type, status_code,
        )

    def _log_low_confidence(self, confidence):
        # Confidence below the repair floor is a routine operational event,
        # not a failure. Log it at INFO with no payload context — the
        # CONFIDENCE value itself carries no PII.
        _log.info(
            "low_confidence ts=%s session_id=%s confidence=%.3f",
            int(time.time()), self._session_id, confidence,
        )
