# AI-Warden

**Privacy-preserving homelab watchdog. Local AI sanitizes infrastructure data before external AI troubleshooting. Zero raw data leaves the network.**

Built by [xADHDx](https://github.com/xADHDx) in collaboration with Claude (Anthropic) — designed, architected, and coded together one step at a time.

## Architecture

- **Sanitizer** — 3-layer privacy filter (regex → local LLM → egress leak-check)
- **Watchdog** — monitors Proxmox LXC containers for failures and resource spikes
- **Repair Engine** — per-LXC targeted auto-repair scripts
- **API** — LAN-only FastAPI control layer for external tooling
- **Claude Integration** — sanitized logs sent to Claude API with persistent memory for AI-assisted troubleshooting

## Privacy Model

Raw infrastructure data never leaves the network. All outbound API calls are sanitized through three deterministic and AI-assisted layers before transmission. Claude only ever sees tokens — never real IPs, hostnames, domains, or credentials. The token vault never leaves the LAN. Network egress is locked to `api.anthropic.com` only.

## Authors

- **xADHDx** — architect, homelab engineer, project owner
- **Claude** (Anthropic) — AI pair programmer and co-designer

## License

AGPL-3.0 — see LICENSE
