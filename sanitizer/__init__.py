"""ZKDP sanitization pipeline orchestrator.

run_pipeline() executes the fixed, immutable sequence of integrity gates. The
order never changes and the system fails closed: any failure at any stage aborts
immediately, with no partial output, no retry, no recovery, no correction, no
inference, and no repair. The only successful exit is "every gate passed".
"""


class PipelineError(Exception):
    """Raised when an egress/proof gate aborts the pipeline (fail closed)."""


def run_pipeline(text, vault, l1, l2, l3, l4, canary):
    # IMMUTABLE ORDER. Do not reorder, skip, or insert recovery between steps.
    # Any exception raised by any step propagates unchanged — propagation IS the
    # fail-closed behaviour: no value is returned, so no partial output escapes.

    # 1. Canary verification. A failed canary halts the system with CanaryFailure,
    #    which is allowed to propagate untouched — the pipeline never swallows it.
    canary.run(vault, l1, l2, l3)

    # 2. Layer 1 — deterministic regex tokenizer (with encoding normalizer).
    text = l1.sanitize(text)

    # 3. Layer 2 — three-signal context sanitizer.
    text = l2.scan(text)

    # 4. Layer 3 — fail-closed egress leak check. Abort the moment it is not clean.
    l3_clean, l3_reason = l3.check(text)
    if not l3_clean:
        raise PipelineError(f"LAYER3_BLOCKED: {l3_reason}")

    # 5. Layer 4 — BLAKE3 proof verification. Abort if any value is unproven.
    l4_clean, l4_reason = l4.verify(text, vault)
    if not l4_clean:
        raise PipelineError(l4_reason)

    # 6. Every gate passed — and only now — return the sanitized payload.
    return text
