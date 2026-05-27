"""Canary verification system for the AIWarden sanitization pipeline.

This module is a deliberately INDEPENDENT smoke test. Per the ZKDP spec the
canary code "shares nothing with sanitizer code": it imports nothing from
layer1/layer2/layer3 (or anywhere in sanitizer/) and reimplements none of their
detection logic. It only drives the layer objects it is handed and decides, by
plain substring search, whether a known piece of synthetic PII survived. That
independence is the whole point — a bug in a sanitizer layer cannot also hide
itself here, because the canary never asks a sanitizer "did you catch this?",
it checks the bytes that came out the other end.

A canary is considered CAUGHT when its sensitive needle no longer appears in the
payload after Layer 1 + Layer 2 tokenization, OR when Layer 3 refuses to certify
that payload as clean (fail-closed egress block). A canary LEAKS only if its
needle survives L1+L2 verbatim AND Layer 3 still declares the payload clean — at
which point the pipeline would have transmitted real-shaped PII, so the system
halts via CanaryFailure carrying the full per-layer trace.
"""

import base64


class CanaryFailure(Exception):
    """Raised when a synthetic PII canary survives the full pipeline.

    The message carries the exact value that leaked, the layer that was expected
    to catch it, and the payload as seen after each layer — so an operator can
    see precisely what escaped and where it should have been stopped.
    """


# --- Encoding helpers (generic, self-contained — no sanitizer code reused) ---

def _ipv4_to_int(ip):
    # Pack a dotted-quad string into its unsigned 32-bit integer form.
    a, b, c, d = (int(octet) for octet in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _percent_encode(text):
    # Percent-encode every byte (forces %xx even for digits and dots), so the
    # canary is a fully URL-encoded value the normalizer must decode.
    return "".join(f"%{byte:02X}" for byte in text.encode("ascii"))


def _wireguard_key():
    # A realistic 44-char base64 WireGuard public key (32 raw bytes). The bytes
    # are chosen to include non-printable values so the pipeline treats the key
    # as an opaque high-entropy secret rather than decodable text.
    raw = bytes((i * 53 + 7) & 0xFF for i in range(32))
    return base64.b64encode(raw).decode("ascii")


class CanarySystem:
    """Generates synthetic PII canaries and verifies the pipeline catches them.

    run(vault, l1, l2, l3) pushes each canary through the real L1 -> L2 -> L3
    pipeline and returns True only if every single canary is caught; the first
    leak raises CanaryFailure instead.
    """

    def __init__(self):
        self.canaries = self._build_canaries()

    # --------------------------------------------------------------- canaries
    def _build_canaries(self):
        # Each canary is a dict:
        #   name    — the PII class being probed
        #   payload — the exact string fed into the pipeline (PII in context)
        #   needle  — the sensitive substring that must NOT survive verbatim
        #   expect  — the layer expected to catch it (used only for reporting)
        # Encoded-IP canaries are derived from real IPs so the encodings are
        # exact; the normalizer in Layer 1 must decode them before regex runs.
        b64_ip = base64.b64encode(b"198.51.100.23").decode("ascii")
        hex_ip = f"0x{_ipv4_to_int('192.0.2.55'):08X}"
        dec_ip = str(_ipv4_to_int("198.18.7.9"))
        url_ip = _percent_encode("203.0.113.7")
        wg_key = _wireguard_key()
        jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJjYW5hcnkiOiJsZWFrMTIzNCJ9"
               ".s1gnatureCanaryXyz")

        canaries = []

        def add(name, payload, needle, expect):
            canaries.append(
                {"name": name, "payload": payload, "needle": needle, "expect": expect})

        add("IPv4", "client connected from 203.0.113.99 ok",
            "203.0.113.99", "L1")
        add("IPv6", "peer addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 up",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "L1")
        add("MAC address", "nic hwaddr 02:42:ac:11:00:fe online",
            "02:42:ac:11:00:fe", "L1")
        add("email", "owner=canary.user@canary-corp.example notified",
            "canary.user@canary-corp.example", "L1")
        add("Unix file path", "reading /var/canary/secret/canopy.key now",
            "/var/canary/secret/canopy.key", "L1")
        add("Windows path", r"open C:\Canary\Secrets\flag.txt failed",
            r"C:\Canary\Secrets\flag.txt", "L1")
        add("API key (sk-)", "auth sk-canaryAbc123Def456Ghi789Jkl used",
            "sk-canaryAbc123Def456Ghi789Jkl", "L1")
        add("JWT token", f"token={jwt} accepted", jwt, "L1")
        add("domain name", "lookup canary-host.internal.example.net resolved",
            "canary-host.internal.example.net", "L1")
        add("username in context", "login username=canaryadmin8842 ok",
            "canaryadmin8842", "L1")
        add("password in context", "db password=Canary!Secret#2026z set",
            "Canary!Secret#2026z", "L1")
        add("base64 encoded IP", f"data base64={b64_ip} blob", b64_ip, "L1")
        add("hex encoded IP", f"dst {hex_ip} routed", hex_ip, "L1")
        add("decimal encoded IP", f"dst {dec_ip} routed", dec_ip, "L1")
        add("URL encoded IP", f"redirect {url_ip} done", url_ip, "L1")
        add("private key header", "key -----BEGIN OPENSSH PRIVATE KEY----- dump",
            "-----BEGIN OPENSSH PRIVATE KEY-----", "L3")
        add("WireGuard public key", f"wg peer pubkey {wg_key} added", wg_key, "L1")
        add("webhook URL",
            "post https://hooks.canary.example/services/T00/B11/XyZsecretCanary done",
            "XyZsecretCanary", "L1")
        add("database connection string",
            "dsn postgresql://canaryuser:canaryDbPass4242@db.canary.example:5432/canarydb up",
            "canaryDbPass4242", "L2")
        add("bearer token", "header Bearer abcDEF123456canary7890tok sent",
            "abcDEF123456canary7890tok", "L1")

        return canaries

    # ------------------------------------------------------------------- run
    def run(self, vault, l1, l2, l3):
        # Drive every canary through the full pipeline. Return True only if all
        # are caught; raise CanaryFailure on the first one that leaks.
        for canary in self.canaries:
            result = self._verify(canary, l1, l2, l3)
            if result["leaked"]:
                raise CanaryFailure(self._describe_leak(result))
        return True

    def _verify(self, canary, l1, l2, l3):
        # Run one canary through L1 -> L2 -> L3 and attribute where it was caught.
        payload, needle = canary["payload"], canary["needle"]
        after_l1 = l1.sanitize(payload)
        after_l2 = l2.scan(after_l1)
        l3_clean, l3_reason = l3.check(after_l2)

        if needle not in after_l1:
            caught_by = "L1"            # tokenized by the regex layer
        elif needle not in after_l2:
            caught_by = "L2"            # tokenized by the context layer
        elif not l3_clean:
            caught_by = "L3"            # survived L1+L2 but egress refused it
        else:
            caught_by = None            # leaked all the way through

        return {
            "name": canary["name"],
            "needle": needle,
            "payload": payload,
            "expect": canary["expect"],
            "after_l1": after_l1,
            "after_l2": after_l2,
            "l3_clean": l3_clean,
            "l3_reason": l3_reason,
            "caught_by": caught_by,
            "leaked": caught_by is None,
        }

    def _describe_leak(self, r):
        # Exact details: what leaked, where it was expected to be caught, and the
        # payload as seen after each layer so the miss can be pinpointed.
        return (
            f"Canary LEAKED: [{r['name']}] value {r['needle']!r} survived the "
            f"full pipeline unsanitized.\n"
            f"  expected to be caught at: {r['expect']}\n"
            f"  layer that missed it    : L1, L2, and L3 (egress certified clean)\n"
            f"  payload                 : {r['payload']!r}\n"
            f"  after Layer 1           : {r['after_l1']!r}\n"
            f"  after Layer 2           : {r['after_l2']!r}\n"
            f"  Layer 3 verdict         : clean={r['l3_clean']} ({r['l3_reason']})"
        )
