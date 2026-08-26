"""Monitor-mode + capture — the thin hardware boundary.

Everything that actually shells out to the radio lives here so the rest of the
package stays pure and testable. These wrap the off-the-shelf toolbox
(airmon-ng, airodump-ng) shipped in the Kali-base image; Ares' value is the
scope guard around them, not reimplementing them.
"""

from __future__ import annotations

import contextlib
import subprocess
import tempfile
from pathlib import Path


class MonitorError(RuntimeError):
    """A monitor-mode / capture operation failed at the hardware boundary."""


def _run(cmd: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
    except FileNotFoundError as e:
        raise MonitorError(
            f"tool not found: {cmd[0]} (is this running in the toolbox image?)"
        ) from e
    except subprocess.CalledProcessError as e:
        raise MonitorError(f"{cmd[0]} failed: {e.stderr.strip() or e}") from e
    except subprocess.TimeoutExpired as e:
        raise MonitorError(f"{cmd[0]} timed out after {timeout}s") from e


def enable_monitor(interface: str) -> str:
    """Put ``interface`` into monitor mode; return the monitor interface name.

    airmon-ng typically produces ``<iface>mon`` or renames in place. We return
    the configured name and let the caller confirm with ``iw dev``.
    """
    _run(["airmon-ng", "start", interface])
    return interface


def disable_monitor(interface: str) -> None:
    _run(["airmon-ng", "stop", interface])


def capture_airodump_csv(interface: str, seconds: float, *, channel: int | None = None) -> str:
    """Run a passive airodump-ng sweep and return its CSV output.

    Read-only: no ``--write-interval`` injection, no active options. Writes to a
    scratch prefix, reads the ``-01.csv`` product back, and cleans up.
    """
    with tempfile.TemporaryDirectory(prefix="ares-survey-") as tmp:
        prefix = Path(tmp) / "sweep"
        cmd = [
            "airodump-ng",
            "--output-format",
            "csv",
            "--write",
            str(prefix),
            "--write-interval",
            "1",
        ]
        if channel is not None:
            cmd += ["--channel", str(channel)]
        cmd.append(interface)
        # airodump runs until killed; bound it by the sweep duration. A timeout
        # (surfaced as MonitorError) is the expected stop condition for a timed
        # sweep, so suppress it and fall through to reading the CSV it wrote.
        with contextlib.suppress(MonitorError):
            _run(cmd, timeout=seconds)
        csv_path = prefix.with_name("sweep-01.csv")
        if not csv_path.exists():
            raise MonitorError(
                f"airodump produced no CSV at {csv_path} — is {interface} in monitor mode?"
            )
        return csv_path.read_text()


def capture_pmkid(interface: str, bssid: str, seconds: float) -> Path:
    """Capture a PMKID for ``bssid`` with hcxdumptool; return the pcapng path.

    Clientless (no deauth) — hcxdumptool asks the AP for its PMKID directly. The
    caller (``ares.audit``) has already asserted ``bssid`` is own-scope; this
    boundary only runs the tool. The returned file lives in the caller's captures
    dir and is theirs to hash/store.
    """
    out = _captures_dir() / f"pmkid-{_safe(bssid)}.pcapng"
    cmd = [
        "hcxdumptool",
        "-i",
        interface,
        "--filterlist_ap",
        bssid,
        "--filtermode",
        "2",  # capture only the listed AP
        "-w",
        str(out),
    ]
    with contextlib.suppress(MonitorError):
        _run(cmd, timeout=seconds)
    if not out.exists():
        raise MonitorError(f"hcxdumptool produced no capture at {out}")
    return out


def capture_handshake(interface: str, bssid: str, channel: int, seconds: float) -> Path:
    """Passively capture a WPA handshake for ``bssid`` with airodump-ng.

    No deauth is sent — this waits for a client to (re)associate naturally, which
    keeps the audit passive. Forcing a handshake with a deauth would radiate and
    belongs to the active tier, not here. Returns the ``.cap`` path.
    """
    with tempfile.TemporaryDirectory(prefix="ares-hs-") as tmp:
        prefix = Path(tmp) / "hs"
        cmd = [
            "airodump-ng",
            "--bssid",
            bssid,
            "--channel",
            str(channel),
            "--write",
            str(prefix),
            "--output-format",
            "cap",
            interface,
        ]
        with contextlib.suppress(MonitorError):
            _run(cmd, timeout=seconds)
        cap = prefix.with_name("hs-01.cap")
        if not cap.exists():
            raise MonitorError(f"airodump produced no capture at {cap}")
        out = _captures_dir() / f"handshake-{_safe(bssid)}.cap"
        out.write_bytes(cap.read_bytes())
        return out


def run_aircrack(capture: Path, wordlist: Path) -> str:
    """Run ``aircrack-ng`` on a capture against a wordlist; return its stdout.

    Offline compute, not a radio op, but it's still the same tool-subprocess
    boundary — the pure output parser lives in :func:`ares.audit.parse_aircrack`.
    """
    result = _run(["aircrack-ng", "-w", str(wordlist), str(capture)])
    return result.stdout


def _captures_dir() -> Path:
    d = Path("captures")
    d.mkdir(exist_ok=True)
    return d


def _safe(bssid: str) -> str:
    return bssid.replace(":", "")
