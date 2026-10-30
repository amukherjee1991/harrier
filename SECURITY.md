# Security

## Reporting a vulnerability
Please report privately via GitHub's **Security → Report a vulnerability** on this repository rather than a public
issue. Include the version, what an attacker controls, and the smallest reproduction you have.

## Pre-release audit (v1.0.0)
Before release, Harrier was audited with Cloudflare's
[security-audit method](https://github.com/cloudflare/security-audit-skill) (standard profile).
All bounded local checks ran in a network-isolated, read-only Docker sandbox.

The run was **stopped early**, before independent verification of candidates, so it claims no confirmed
findings and no complete coverage. Every one of its 14 candidates was nonetheless fixed. Each has a regression
test in `tests/test_audit.py` that fails on the audited commit and passes on v1.0.0. The most important were:
- one oversized request could stall the detector (quadratic regex)
- devices on the LAN could forge their address via `X-Forwarded-For`
- forged or framed requests could get innocent visitors blocked
- the learning baseline could be poisoned
- viewers could read admin settings
- the domain watch followed redirects into the network
- `setup.sh` could skip password generation on a fresh install

Deferred to the next audit run: three deployment units, the coverage critics, and independent verification.

## Design rules worth knowing
- Traffic is evidence, never instructions. The AI can only add or lengthen blocks; unblocking, allowlisting and
  permanent blocks need a person.
- An address is blocked only for its own hostile activity. Text it could have been made to send (a cross-site
  request, a mistyped password) or patterns learned from other addresses never block on their own.
- Home, private and VPN ranges, your public IP and your allowlist are never blocked.
- Only the proxies you list in `TRUSTED_PROXIES` may report a client's address.
