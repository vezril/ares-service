"""Radio enumeration — real ``iw`` on Linux, a mock pool everywhere else.

The parsers (:func:`parse_iw_dev`, :func:`parse_supported_modes`) are pure over
command output so they are tested without a radio; :class:`LinuxRadioProvider`
shells out and :class:`MockRadioProvider` returns a representative fixture, so
the whole stack runs on a dev machine (mirrors the survey pipeline's split).
"""

from __future__ import annotations

import platform
import re
import subprocess
from pathlib import Path
from typing import Protocol

from ares.radio.types import RadioCapabilities, RadioInfo


class RadioProvider(Protocol):
    name: str

    def enumerate(self) -> list[RadioInfo]: ...


# --- pure parsers (portable from shodan's linux-provider) --------------------

_PHY_RE = re.compile(r"^phy#(\d+)")
_IFACE_RE = re.compile(r"^\s*Interface\s+(\S+)")


def parse_iw_dev(output: str) -> list[tuple[str, str]]:
    """Parse ``iw dev`` into ``(interface_id, phy)`` pairs."""
    pairs: list[tuple[str, str]] = []
    current_phy = ""
    for line in output.splitlines():
        phy = _PHY_RE.match(line)
        if phy:
            current_phy = f"phy{phy.group(1)}"
            continue
        iface = _IFACE_RE.match(line)
        if iface and current_phy:
            pairs.append((iface.group(1), current_phy))
    return pairs


def parse_supported_modes(output: str) -> set[str]:
    """Parse the ``Supported interface modes:`` bullet list from ``iw phy info``."""
    modes: set[str] = set()
    in_section = False
    for line in output.splitlines():
        if "Supported interface modes:" in line:
            in_section = True
            continue
        if not in_section:
            continue
        bullet = re.match(r"^\s*\*\s*(\S+)", line)
        if bullet:
            modes.add(bullet.group(1))
        elif line.strip():
            break  # next section reached
    return modes


def capabilities_from_modes(modes: set[str]) -> RadioCapabilities:
    """Map ``iw`` supported modes to Ares capabilities.

    ``iw`` does not report injection directly; infer it from monitor support (the
    same inference shodan used — injection-capable chipsets are the monitor ones).
    """
    monitor = "monitor" in modes
    return RadioCapabilities(monitor=monitor, injection=monitor, ap="AP" in modes)


# --- providers ----------------------------------------------------------------


def _run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


class LinuxRadioProvider:
    name = "linux"

    def enumerate(self) -> list[RadioInfo]:
        radios: list[RadioInfo] = []
        for iface, phy in parse_iw_dev(_run(["iw", "dev"])):
            modes = parse_supported_modes(_run(["iw", "phy", phy, "info"]))
            radios.append(
                RadioInfo(
                    id=iface,
                    phy=phy,
                    driver=self._driver(iface),
                    chipset=None,
                    capabilities=capabilities_from_modes(modes),
                )
            )
        return radios

    @staticmethod
    def _driver(iface: str) -> str:
        try:
            return Path(f"/sys/class/net/{iface}/device/driver").resolve().name
        except OSError:
            return "unknown"


# A representative pool for hardware-free dev: the RTL8812AU (Ares' actual Hak5
# "AC" adapter — dual-band monitor + injection, no reliable AP) plus an in-kernel
# AR9271 (2.4GHz monitor + injection + AP) — two radios, enough for evil twin.
_MOCK_RADIOS = [
    RadioInfo(
        id="wlan0",
        phy="phy0",
        driver="88XXau",
        chipset="Realtek RTL8812AU (Hak5 AC)",
        capabilities=RadioCapabilities(monitor=True, injection=True, ap=False),
    ),
    RadioInfo(
        id="wlan1",
        phy="phy1",
        driver="ath9k_htc",
        chipset="Atheros AR9271",
        capabilities=RadioCapabilities(monitor=True, injection=True, ap=True),
    ),
]


class MockRadioProvider:
    name = "mock"

    def __init__(self, radios: list[RadioInfo] | None = None) -> None:
        self._radios = radios if radios is not None else _MOCK_RADIOS

    def enumerate(self) -> list[RadioInfo]:
        return list(self._radios)


def select_provider(system: str | None = None) -> RadioProvider:
    """Real radios on Linux; the mock pool elsewhere (the radio layer is
    Linux-only, so a dev host runs against a representative fixture)."""
    return LinuxRadioProvider() if (system or platform.system()) == "Linux" else MockRadioProvider()
