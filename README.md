# AIWarden

**Privacy-preserving AI-assisted infrastructure watchdog implementing the ZKDP protocol.**

Built by [xADHDx](https://github.com/xADHDx) in collaboration with Claude (Anthropic).

> ⚠️ This is a work in progress (no guarantees whatsoever). Core pipeline is functional and proven. Repair engine and watchdog daemon are not yet built. Community contributions welcome.

NOTE: I am a very new programmer — honestly, I don't know much about Python whatsoever, so this was a learning experience. I don't expect any profits ever. This project is always for the community, for everyone to use. I hope no companies are able to profit off it, which is why I chose the license I chose. Please help, and please play devil's advocate and criticize. I need that in order to produce worthwhile fixes and make this project something real and useful for everyone. Thank you.

---

## What It Does

AIWarden sits between your servers and external AI models. When something breaks, it collects logs, sanitizes all identifying information through a 4-layer pipeline, converts events into anonymous mathematical vectors using the ZKDP protocol, and sends them to Claude for diagnosis — without ever transmitting real IPs, hostnames, usernames, passwords, file paths, or most identifying information that most of us don't want our AI models having or sending anywhere externally.

Claude reasons over the math. Never the data.

---

## Proof of Concept

Live tested: a real Navidrome failure log was sanitized through the full pipeline and sent to Claude as a ZKDP packet. Claude correctly diagnosed a transcode dependency cascade and produced a structured repair plan — without knowing the software, IP addresses, or any identifying information.

---

## Architecture

### Sanitization Pipeline (built, tested)
- **Layer 1** — Regex tokenizer with encoding normalizer (URL, base64, hex, octal)
- **Layer 2** — Three-signal context sanitizer (vocabulary, role, source)
- **Layer 3** — Fail-closed egress leak check
- **Layer 4** — BLAKE3 checksum proof verification

### ZKDP Protocol (built, tested)
- **SFL Transformer** — converts sanitized logs to Sequence Formula Language event vectors
- **Packet Builder** — canonical ZKDP packet serialization with BLAKE3 integrity hashing
- **API Client** — two-channel transmission (Channel A: events, Channel B: anonymous context)
- **Integrity Verification** — RECEIVED_HASH verification, anti-replay nonce tracking

### Supporting Systems (built, tested)
- **Token Vault** — AES-256 encrypted, session-scoped, mutex-locked
- **Canary System** — 20/20 synthetic PII canaries verified before every live run
- **Service Profile Registry** — numeric ontology IDs, never transmitted

### Not Yet Built
- Repair engine
- Watchdog daemon
- Service profiles for common homelab apps (Jellyfin, Sonarr, Navidrome, etc.)

These will be built next.

---

## Privacy Model

Real values never leave the machine. Ever.

- All PII replaced with session-scoped random integer tokens before transmission
- Token vault never transmitted, AES-256 encrypted at rest
- Token mappings rotate every session — no cross-session correlation possible
- Claude responds exclusively in ZKDP protocol language — no natural language inference leakage
- Fail-closed on every layer — uncertainty aborts, never proceeds

Known limitation: structural event patterns in packets could theoretically fingerprint infrastructure topology over many sessions. See the ZKDP spec Known Attack Surfaces section.

---

## ZKDP Protocol

AIWarden is the reference implementation of ZKDP — Zero Knowledge Diagnostic Protocol.

Protocol specification: [github.com/xADHDx/ZKDP](https://github.com/xADHDx/ZKDP)

---

## Quick Start

```bash
git clone https://github.com/xADHDx/AI-Warden.git
cd AI-Warden
pip3 install anthropic blake3 cryptography --break-system-packages
export ANTHROPIC_API_KEY=your_key_here
PYTHONPATH=. python3 tools/diagnose.py /path/to/your/logfile.log
```

---

## Contributing

This project needs:
- Service profiles for common homelab apps
- Adversarial testing and edge case reports
- Repair engine implementation
- Watchdog daemon implementation
- Implementations of ZKDP in other languages
- Security review

Open an issue or submit a PR. Read the ZKDP spec first.

ZKDP Spec: https://github.com/xADHDx/ZKDP/blob/main/SPEC.md

---

## Authors

- **xADHDx** — architect, homelab engineer, project owner
- **Claude** (Anthropic) — AI pair programmer and co-designer

## License

AGPL-3.0 — see LICENSE