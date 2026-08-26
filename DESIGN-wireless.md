# Ares wireless platform — design pointer

The full, canonical design is maintained in the **codex** repo so it sits alongside the other
constellation design notes (access-gateway, secrets-manager, observability) and stays under the
Codex session's coordination:

> **`~/Code/codex/docs/ares-wireless-pentest.md`**

It covers: the RF authorization boundary (why wireless ≠ wired scope), USB-WiFi-through-Docker
architecture (chipset choice, host-kernel driver reality, why a laptop node not the QNAP),
the passive/active capability tiers, and the findings transport (Hermes for events + Apollo for
captures, never raw frames).

Keep this file as a pointer only — do not fork the design here; update the codex doc and let it
remain the single source of truth. When ares-service starts real implementation, code-level
notes (module layout, the scope-guard implementation, the findings-schema JSON) can live here;
the *architecture* stays in codex.

## Ethic (restated because it's load-bearing, not boilerplate)

Authorized-only, own-network testing. Passive by default, keeping only own-BSSID data. Active
tier allowlist-gated and off by default. A dedicated test SSID + throwaway clients is the
intended proving ground so nothing runs against the household or the neighbors. See the codex
doc's "RF authorization boundary" section for the full reasoning.
