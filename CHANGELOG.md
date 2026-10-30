# Changelog

## Unreleased
- `./setup.sh --import` now imports before Harrier starts. Before, Harrier began recording first and the
  importer skipped those tables, so most old history was left behind.
- Screenshots in the README, and `tools/demo_seed.py` to load the same demo data.

## 1.0.1 (2026-10-30)
- setup.sh now picks a model that fits your hardware (the template no longer forces an 8 GB model), accepts
  `HARRIER_MODEL=... ./setup.sh --yes`, and checks for curl and a reachable Docker before starting.
- New `tests/install_test.sh`: an end-to-end install test on a throwaway Docker-in-Docker machine, covering a fresh
  machine and one with an Ollama already running. It checks sign-in, containers, a real firewall block, the model,
  re-running setup and a restart (32 checks).

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
