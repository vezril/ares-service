"""Passive survey — the default, read-only recon tier.

The pipeline is deliberately split so the safety-relevant part is pure and
testable without hardware:

1. A monitor-mode tool (airodump-ng) writes a CSV of what the radio heard.
2. :func:`parse_airodump_csv` turns that into ``AccessPoint`` / ``Client`` lists.
3. :func:`build_survey` applies the scope guard: own BSSIDs keep full detail;
   everything foreign collapses to aggregate counts (no per-device foreign log).

Only step 1 touches hardware. Steps 2 and 3 are pure functions over strings.
"""

from __future__ import annotations

import csv
import io
from collections import Counter

from pydantic import BaseModel, ConfigDict, Field

from ares.models import AccessPoint, Client, Scope, Security
from ares.scope import ScopeGuard

_SECURITY_MAP = {
    "WPA3": Security.WPA3,
    "WPA2": Security.WPA2,
    "WPA": Security.WPA,
    "WEP": Security.WEP,
    "OPN": Security.OPEN,
}


def _parse_security(privacy: str) -> Security:
    p = privacy.upper()
    for token, sec in _SECURITY_MAP.items():
        if token in p:
            return sec
    return Security.UNKNOWN


def _int_or_none(value: str) -> int | None:
    value = value.strip()
    try:
        return int(value)
    except ValueError:
        return None


def parse_airodump_csv(text: str) -> tuple[list[AccessPoint], list[Client]]:
    """Parse airodump-ng ``-w ... --output-format csv`` output.

    The format is two CSV sections separated by a blank line: APs, then clients
    (``Station MAC``). Scope defaults to FOREIGN here; :func:`build_survey`
    reclassifies against the guard.
    """
    lines = text.splitlines()
    try:
        split = lines.index("", 1)
    except ValueError:
        split = len(lines)
    ap_block = "\n".join(lines[:split])
    client_block = "\n".join(lines[split + 1 :])

    aps: list[AccessPoint] = []
    for row in csv.reader(io.StringIO(ap_block)):
        if not row or row[0].strip() == "BSSID" or len(row) < 14:
            continue
        try:
            ssid = row[13].strip()
            aps.append(
                AccessPoint(
                    bssid=row[0].strip(),
                    ssid=ssid or None,
                    channel=_int_or_none(row[3]),
                    signal_dbm=_int_or_none(row[8]),
                    security=_parse_security(row[5]),
                    scope=Scope.FOREIGN,
                )
            )
        except ValueError:
            continue  # unparseable BSSID row — skip, don't crash the survey

    clients: list[Client] = []
    for row in csv.reader(io.StringIO(client_block)):
        if not row or row[0].strip() == "Station MAC" or len(row) < 6:
            continue
        try:
            assoc = row[5].strip()
            clients.append(
                Client(
                    mac=row[0].strip(),
                    associated_bssid=assoc
                    if assoc and "not associated" not in assoc.lower()
                    else None,
                    signal_dbm=_int_or_none(row[3]),
                    scope=Scope.FOREIGN,
                )
            )
        except ValueError:
            continue

    return aps, clients


class SurveyResult(BaseModel):
    """What a survey keeps. Own scope gets detail; foreign gets counts only."""

    model_config = ConfigDict(frozen=True)

    own_aps: list[AccessPoint] = Field(default_factory=list)
    own_clients: list[Client] = Field(default_factory=list)
    foreign_ap_count: int = 0
    foreign_client_count: int = 0
    foreign_ssids_spoofing_own: list[str] = Field(default_factory=list)
    channels_seen: dict[int, int] = Field(default_factory=dict)


def build_survey(
    aps: list[AccessPoint],
    clients: list[Client],
    guard: ScopeGuard,
    own_ssids: list[str] | None = None,
) -> SurveyResult:
    """Apply the scope guard: retain own-BSSID detail, aggregate foreign.

    A foreign AP broadcasting one of ``own_ssids`` (a name we own) is flagged as
    a possible rogue/evil-twin — the one thing we surface about foreign gear,
    because it is an attack on us, not surveillance of a neighbor.
    """
    own_names = {s.casefold() for s in (own_ssids or [])}

    own_aps = [
        ap.model_copy(update={"scope": Scope.OWN}) for ap in aps if guard.is_own_bssid(ap.bssid)
    ]
    own_clients = [
        c.model_copy(update={"scope": Scope.OWN}) for c in clients if guard.is_own_client(c.mac)
    ]

    foreign_aps = [ap for ap in aps if not guard.is_own_bssid(ap.bssid)]
    foreign_clients = [c for c in clients if not guard.is_own_client(c.mac)]

    spoofing = sorted(
        {ap.ssid for ap in foreign_aps if ap.ssid is not None and ap.ssid.casefold() in own_names}
    )

    channels = Counter(ap.channel for ap in own_aps if ap.channel is not None)

    return SurveyResult(
        own_aps=own_aps,
        own_clients=own_clients,
        foreign_ap_count=len(foreign_aps),
        foreign_client_count=len(foreign_clients),
        foreign_ssids_spoofing_own=spoofing,
        channels_seen=dict(channels),
    )
