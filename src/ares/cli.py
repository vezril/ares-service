"""``ares`` command-line entrypoint.

Subcommands mirror the capability tiers:

* ``ares scope`` — show config / discover own-BSSID candidates (passive).
* ``ares survey`` — passive monitor sweep, own-scope detail + foreign counts.
* ``ares audit`` — own-network passphrase/handshake audit (passive, own-scope).
* ``ares active`` — allowlist-gated, default-OFF radiating actions.

Passive commands run standalone with no transport configured. Active commands
route through the scope guard and refuse anything off the own-network allowlist.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

import typer

from ares import __version__
from ares.config import DEFAULT_CONFIG_PATH, ScopeConfig
from ares.discover import find_candidates
from ares.models import Finding, Severity
from ares.radio import RadioPool, select_provider
from ares.scope import ScopeError, ScopeGuard
from ares.survey import build_survey, parse_airodump_csv
from ares.transport.hermes import HermesClient

app = typer.Typer(
    name="ares",
    help="Authorized-only wireless pentest platform. Passive by default, own network only.",
    no_args_is_help=True,
)
scope_app = typer.Typer(
    name="scope", help="Inspect and populate the own-network scope.", no_args_is_help=True
)
active_app = typer.Typer(
    name="active", help="Allowlist-gated radiating actions (default OFF).", no_args_is_help=True
)
app.add_typer(scope_app)
app.add_typer(active_app)

ConfigOpt = Annotated[Path, typer.Option("--config", "-c", help="Scope config TOML path.")]


def _load(config_path: Path) -> tuple[ScopeConfig, ScopeGuard]:
    cfg = ScopeConfig.load(config_path)
    return cfg, ScopeGuard(cfg)


@app.callback()
def _root() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")


@app.command()
def version() -> None:
    """Print the Ares version."""
    typer.echo(f"ares {__version__}")


@app.command()
def radios() -> None:
    """List WiFi adapters and their monitor/injection/AP capabilities + mode.

    Real ``iw`` enumeration on Linux; a representative mock pool elsewhere, so it
    runs on a dev machine. Answers "which adapter can do monitor mode?".
    """
    reports = RadioPool(select_provider()).list()
    if not reports:
        typer.secho(
            "No WiFi radios found (is the adapter plugged in and driver loaded?)",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(code=1)
    for r in reports:
        caps = ",".join(
            name
            for name, on in (
                ("monitor", r.capabilities.monitor),
                ("inject", r.capabilities.injection),
                ("ap", r.capabilities.ap),
            )
            if on
        )
        chipset = f" [{r.chipset}]" if r.chipset else ""
        typer.echo(f"{r.id} ({r.phy}, {r.driver}){chipset}  caps={caps or 'none'}  mode={r.mode}")


@scope_app.command("show")
def scope_show(config: ConfigOpt = DEFAULT_CONFIG_PATH) -> None:
    """Show the resolved scope: own SSIDs, pinned BSSIDs, active-tier state."""
    cfg, guard = _load(config)
    typer.echo(f"own_ssids:        {', '.join(cfg.own_ssids)}")
    typer.echo(f"own_bssids:       {len(guard.own_bssids)} pinned")
    for b in sorted(guard.own_bssids):
        typer.echo(f"  - {b}")
    typer.echo(f"own_client_macs:  {len(cfg.own_client_macs)}")
    typer.echo(f"active tier:      {'ENABLED' if cfg.active.enabled else 'disabled (default)'}")


@scope_app.command("discover")
def scope_discover(
    config: ConfigOpt = DEFAULT_CONFIG_PATH,
    csv_file: Annotated[
        Path | None,
        typer.Option("--from-csv", help="Parse an airodump CSV instead of live capture."),
    ] = None,
    seconds: Annotated[float, typer.Option(help="Live sweep duration.")] = 20.0,
) -> None:
    """Find BSSIDs broadcasting an own SSID → candidates to confirm and pin.

    Candidates are never auto-trusted (a spoofer broadcasts your SSID too). Copy
    the ones you recognize into ``own_bssids`` yourself.
    """
    cfg, _ = _load(config)
    if csv_file is not None:
        aps, _clients = parse_airodump_csv(csv_file.read_text())
    else:
        from ares.monitor import capture_airodump_csv

        aps, _clients = parse_airodump_csv(capture_airodump_csv(cfg.interface, seconds))

    result = find_candidates(aps, cfg.own_ssids, [str(b) for b in cfg.own_bssids])
    if not result.candidates:
        typer.echo("No new candidate BSSIDs for the configured SSID(s).")
        raise typer.Exit()
    typer.echo("Candidate own-BSSIDs (confirm before pinning into own_bssids):")
    for c in result.candidates:
        typer.echo(f"  {c.bssid}  ssid={c.ssid!r} ch={c.channel} signal={c.signal_dbm}dBm")


@app.command()
def survey(
    config: ConfigOpt = DEFAULT_CONFIG_PATH,
    csv_file: Annotated[
        Path | None,
        typer.Option("--from-csv", help="Parse an airodump CSV instead of live capture."),
    ] = None,
    seconds: Annotated[float, typer.Option(help="Live sweep duration.")] = 30.0,
    emit: Annotated[bool, typer.Option(help="Emit a finding to Hermes if configured.")] = False,
) -> None:
    """Passive monitor sweep: own-scope detail, foreign aggregate counts only."""
    cfg, guard = _load(config)
    if csv_file is not None:
        aps, clients = parse_airodump_csv(csv_file.read_text())
    else:
        from ares.monitor import capture_airodump_csv

        aps, clients = parse_airodump_csv(capture_airodump_csv(cfg.interface, seconds))

    result = build_survey(aps, clients, guard, cfg.own_ssids)
    typer.echo(f"own APs:          {len(result.own_aps)}")
    for ap in result.own_aps:
        typer.echo(
            f"  {ap.bssid}  ssid={ap.ssid!r} ch={ap.channel} sec={ap.security} {ap.signal_dbm}dBm"
        )
    typer.echo(f"own clients:      {len(result.own_clients)}")
    typer.echo(f"foreign APs:      {result.foreign_ap_count} (count only — not logged)")
    typer.echo(f"foreign clients:  {result.foreign_client_count} (count only — not logged)")
    if result.foreign_ssids_spoofing_own:
        typer.secho(
            f"ROGUE: foreign AP(s) broadcasting your SSID: {result.foreign_ssids_spoofing_own}",
            fg=typer.colors.RED,
        )

    if emit:
        finding = Finding(
            kind="survey_completed",
            severity=(Severity.HIGH if result.foreign_ssids_spoofing_own else Severity.INFO),
            summary=f"Survey: {len(result.own_aps)} own AP(s), {result.foreign_ap_count} foreign",
            detail={"foreign_ap_count": str(result.foreign_ap_count)},
        )
        client = HermesClient(cfg.transport.hermes_base_url, cfg.transport.timeout_seconds)
        sent = client.emit(finding)
        typer.echo(
            "finding emitted to Hermes" if sent else "finding logged (Hermes not configured)"
        )


@app.command()
def serve(
    config: ConfigOpt = DEFAULT_CONFIG_PATH,
    host: Annotated[
        str, typer.Option(help="Bind address. Loopback by default — internal service.")
    ] = "127.0.0.1",
    port: Annotated[
        int, typer.Option(help="Bind port (ares-ui's ARES_ENDPOINT default is 8087).")
    ] = 8087,
    live: Annotated[
        bool, typer.Option(help="Serve a real monitor-mode survey (needs hardware).")
    ] = False,
) -> None:
    """Serve the HTTP surface the console reads: /health, /scope, SSE /stream.

    Mock survey by default so it runs with no radio; --live runs real sweeps
    through the scope guard. Bound to loopback — the console's BFF is the only
    intended client, never the browser directly.
    """
    import uvicorn

    from ares.http.app import create_app
    from ares.http.source import LiveSurveySource, MockSurveySource, SurveySource

    cfg = ScopeConfig.load(config) if config.exists() else ScopeConfig()

    source: SurveySource
    if live:
        live_source = LiveSurveySource(ScopeGuard(cfg), cfg.interface)
        live_source.set_own_ssids(cfg.own_ssids)
        source = live_source
        typer.secho(f"serving LIVE survey on {cfg.interface}", fg=typer.colors.YELLOW)
    else:
        source = MockSurveySource()
        typer.echo("serving MOCK survey (no radio) — pass --live for real sweeps")

    typer.echo(f"Ares HTTP surface on http://{host}:{port}  (/health /scope /stream)")
    uvicorn.run(create_app(source, cfg), host=host, port=port, log_level="warning")


@app.command()
def audit(
    bssid: Annotated[str, typer.Argument(help="Own-network BSSID to audit.")],
    config: ConfigOpt = DEFAULT_CONFIG_PATH,
    wordlist: Annotated[Path, typer.Option(help="Wordlist for the offline crack.")] = Path(
        "/usr/share/wordlists/rockyou.txt"
    ),
    from_capture: Annotated[
        Path | None,
        typer.Option("--from-capture", help="Crack an existing capture instead of capturing live."),
    ] = None,
    pmkid: Annotated[
        bool, typer.Option(help="Capture a PMKID (clientless) vs. a handshake.")
    ] = True,
    channel: Annotated[int, typer.Option(help="Channel for live handshake capture.")] = 6,
    seconds: Annotated[float, typer.Option(help="Live capture duration.")] = 60.0,
    emit: Annotated[bool, typer.Option(help="Emit a finding to Hermes if configured.")] = False,
) -> None:
    """Own-network passphrase audit (passive, own-scope): capture a handshake/PMKID
    for YOUR OWN AP and test its passphrase offline against a wordlist.

    Refuses any BSSID not on the own-network allowlist. The cracked key (if any)
    stays local — it is never placed on the emitted finding.
    """
    from ares.audit import AuditReport, assert_auditable, parse_aircrack, to_finding

    cfg, guard = _load(config)
    try:
        assert_auditable(guard, bssid)
    except ScopeError as e:
        typer.secho(f"REFUSED: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    from ares.monitor import capture_handshake, capture_pmkid, run_aircrack
    from ares.transport.apollo import ApolloClient

    if from_capture is not None:
        capture = from_capture
        captured_pmkid = captured_hs = False  # provided offline; kind unknown
    elif pmkid:
        capture = capture_pmkid(cfg.interface, bssid, seconds)
        captured_pmkid, captured_hs = True, False
    else:
        capture = capture_handshake(cfg.interface, bssid, channel, seconds)
        captured_pmkid, captured_hs = False, True

    if not wordlist.exists():
        typer.secho(f"wordlist not found: {wordlist}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    passphrase = parse_aircrack(run_aircrack(capture, wordlist), str(wordlist))

    apollo = ApolloClient(cfg.transport.apollo_base_url, cfg.transport.timeout_seconds)
    capture_ref = apollo.put_capture(capture)

    report = AuditReport(
        bssid=bssid,
        handshake_captured=captured_hs,
        pmkid_captured=captured_pmkid,
        passphrase=passphrase,
        capture_ref=capture_ref,
    )
    if passphrase.cracked:
        typer.secho(
            f"WEAK: {bssid} passphrase cracked with {wordlist.name} — change it.",
            fg=typer.colors.RED,
        )
    else:
        typer.secho(f"OK: {bssid} passphrase held against {wordlist.name}.", fg=typer.colors.GREEN)

    if emit:
        client = HermesClient(cfg.transport.hermes_base_url, cfg.transport.timeout_seconds)
        sent = client.emit(to_finding(report))
        typer.echo(
            "finding emitted to Hermes" if sent else "finding logged (Hermes not configured)"
        )


@active_app.command("deauth")
def active_deauth(
    target_bssid: Annotated[str, typer.Argument(help="Own-network BSSID to test.")],
    config: ConfigOpt = DEFAULT_CONFIG_PATH,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm this radiating run.")] = False,
) -> None:
    """Deauth-resilience test against your OWN BSSID. Allowlist-gated, default OFF.

    This scaffolds the gate, not the attack: the guard is enforced and the run is
    confirmed, but transmission is intentionally not wired until the active tier
    is built on the proven passive base against a dedicated test AP.
    """
    _cfg, guard = _load(config)
    try:
        guard.assert_active_allowed(target_bssid)
    except ScopeError as e:
        typer.secho(f"REFUSED: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    if guard.requires_confirmation() and not yes:
        typer.secho(
            f"About to run an ACTIVE deauth test against {target_bssid}. This radiates to every "
            "device in range. Re-run with --yes to confirm.",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(code=1)

    typer.secho(
        f"[scaffold] scope + confirmation passed for {target_bssid}; transmission not yet wired.",
        fg=typer.colors.YELLOW,
    )
