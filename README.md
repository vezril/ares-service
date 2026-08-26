# ares-service

**Ares — the constellation's wireless pentest platform.** A self-hosted, authorized-only
WiFi-Pineapple clone for Calvin's own network: USB WiFi antennas passed through to Docker,
survey + own-network audit, findings surfaced to the constellation. Replaces a flaky Hak5
WiFi Pineapple.

> **The canonical design lives in the codex repo: `docs/ares-wireless-pentest.md`.** Read it
> first — this README is the project seed; that doc is the source of truth.

## The one rule that shapes everything

**Radio doesn't honor an IP allowlist.** Monitor mode hears every network in range (neighbors
included); active frames (deauth, evil-twin, karma) radiate to all devices in range. So the
scope guard is **BSSID/MAC-based**, and:

- **Passive is the default.** Capture broadly at the antenna, but **keep only Calvin's own
  BSSIDs** — discard third-party frames. No standing log of neighbors' devices (that's
  people-tracking; off by default, scoped + retention-bounded if ever on).
- **Active is allowlist-gated, default OFF.** Every active action asserts its target BSSID is
  on the own-network allowlist first, one confirmation per run. Deauth/interception against
  gear you don't own is illegal; own-devices-only is the safe harbor.
- **Test-bed, not the household net.** The clean setup is a dedicated test SSID + throwaway
  client devices, RF-isolated where possible.

This is ethical, authorized security testing of the operator's own infrastructure. It is not a
general attack tool and the scope guard is not optional decoration.

## Architecture (see the design doc for detail)

- **Host = a laptop node, NOT the QNAP.** The WiFi driver runs in the host kernel; mainline
  Linux on a laptop has `ath9k_htc` in-tree, the NAS likely doesn't, and you don't want a
  privileged host-network container on the box that holds everything.
- **Adapter chipset is decision #1** — monitor mode + injection. Favor in-kernel AR9271
  (Alfa AWUS036NHA) or MT7612U over out-of-tree RTL8812AU (DKMS pain).
- **Container:** USB passthrough + `NET_ADMIN`/`NET_RAW` + host network. Toolbox is
  off-the-shelf (aircrack-ng, hcxtools, bettercap, hostapd, kismet); Ares' own code is the
  scope guard, findings schema, orchestration.
- **Findings:** discrete events → **Hermes** (`security.wifi.finding`, JSON + Apollo blob
  ref); raw pcaps/handshakes → **Apollo** (content-addressed); never raw RF frames on the bus.

## Status

Seeded 2026-08-26; design decisions locked (see the codex design doc's "Decisions" section):
- **Adapter:** Hak5 AC USB → **RTL8812AU** (DKMS driver `aircrack-ng/rtl8812au`).
- **Host:** a dedicated **Debian/Ubuntu LTS box** (smooth DKMS path), NOT the QNAP. Kali as the
  container base image for the preloaded toolbox.
- **Scope:** **all tiers in v1** — passive survey/audit built first, active (evil-twin/deauth)
  layered on, allowlist-gated + default-OFF.
- **Own-network identity:** SSID `Experimental Neutron`, **configurable**. SSID is the config
  handle; BSSID is the trust anchor (SSID is spoofable) — `ares scope discover` resolves the
  named SSID → own-BSSID allowlist for confirmation.

Ready for a dedicated Ares build session to start (passive survey first).

## Constellation conventions

Owned/coordinated per `codex/docs/session-coordination.md`. Deploys are the Codex session's
(pin-first, mirrored-values helm) — though Ares likely runs as Docker Compose on a laptop node,
not k8s, given the USB/privileged needs. Brand mark: crimson Ares (`codex/docs/brand/ares.png`).
