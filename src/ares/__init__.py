"""Ares — authorized-only wireless pentest platform.

Passive by default, scope guard always, own network only. The scope guard
(``ares.scope``) is the load-bearing safety boundary — radio cannot honor an IP
allowlist, so scope is enforced on BSSID/MAC for storage (passive) and emission
(active). See AGENTS.md and the codex design doc.
"""

__version__ = "0.1.0"
