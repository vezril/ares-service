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

Scaffolded 2026-08-26 (Python 3.12 + uv): scope guard, findings schema, passive survey pipeline,
CLI, and the Docker/Compose surface. Passive tier is wired end-to-end (offline via `--from-csv`);
the active tier's gate is scaffolded but transmission is intentionally not wired yet.

## Development

Python 3.12 + [uv](https://docs.astral.sh/uv/). The scope guard (`src/ares/scope.py`) is the
load-bearing safety boundary — it gets the hardest tests.

```bash
uv sync                          # install deps
uv run ruff check . && uv run ruff format --check .
uv run mypy                      # strict
uv run pytest                    # 34 tests, scope/config/survey covered
```

Try it offline (no radio needed) against a sample airodump CSV:

```bash
cp scope.example.toml scope.local.toml    # then pin your own_bssids
uv run ares survey -c scope.local.toml --from-csv path/to/airodump-01.csv
```

Serve the HTTP surface the [ares-ui](../ares-ui) console reads (`/health`, `/scope`, SSE
`/stream`) — mock survey by default, so it runs with no radio:

```bash
uv run ares serve            # http://127.0.0.1:8087  (loopback; the console's BFF reaches it)
uv run ares serve --live     # real monitor-mode sweeps through the scope guard (needs hardware)
```

The stream emits the ares-ui wire contract exactly (own-scope detail + foreign aggregate only).
Point ares-ui at it with `ARES_ENDPOINT=http://127.0.0.1:8087` + `ARES_LIVE_STREAM=1`.

Layout: `scope.py` (BSSID/MAC guard, fails closed) · `config.py` (scope TOML) · `survey.py`
(parse airodump → keep own detail, aggregate foreign) · `discover.py` (`scope discover`) ·
`radio/` (iw enumeration + mode state machine + pool) · `http/` (the `ares serve` ASGI surface:
wire contract, mock/live survey sources, Starlette app) · `monitor.py` (the thin hardware
boundary — airmon/airodump) · `transport/` (Hermes findings + Apollo captures, no-op when
unconfigured) · `cli.py` (the `ares` command).

Live capture and the Docker image (`Dockerfile`, `docker-compose.yml`) need the RTL8812AU driver
in the **host** kernel and the adapter in monitor mode — the host prep step (see AGENTS.md).

## Constellation conventions

Owned/coordinated per `codex/docs/session-coordination.md`. Deploys are the Codex session's
(pin-first, mirrored-values helm) — though Ares likely runs as Docker Compose on a laptop node,
not k8s, given the USB/privileged needs. Brand mark: crimson Ares (`codex/docs/brand/ares.png`).
