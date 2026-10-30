# Changelog

## 1.0.0 (2026-10-30)
First public release.
- Detection across web (Caddy), SSH, firewall, home-device DNS (Pi-hole) and host/container connections, with
  coordinated-attack (swarm) detection.
- Local AI investigator (Ollama) with prompt-injection defences. It can only add or lengthen blocks.
- nftables firewall guard in its own container; domain watch for hijacking, defacement, certificates and
  look-alike domains.
- Careful learning from confirmed attackers and owner feedback.
- Postgres storage; accounts with admin/viewer roles, Argon2id, revocable sessions, lockouts and sign-in history.
- Dashboard with real URLs, a strict CSP, light and dark themes, and phone support.
- `setup.sh` reuses an Ollama that's already running; `deploy.sh` deploys only when all tests pass.
- 74 replay tests, including regression tests for every pre-release audit candidate (see SECURITY.md).
