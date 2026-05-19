"""Rich UI helpers shared by CLI commands."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from forensicagent.scanner.types import Evidence, Inventory

_console = Console()


def console() -> Console:
    return _console


def render_inventory(inv: Inventory) -> Table:
    table = Table(
        title=f"Evidence inventory - {inv.scan_root}",
        title_style="bold cyan",
        show_lines=False,
    )
    table.add_column("type", style="bold")
    table.add_column("file", overflow="fold")
    table.add_column("size", justify="right")
    table.add_column("by", justify="center")
    table.add_column("platform")
    table.add_column("conf", justify="right")

    for e in inv.evidence_list:
        table.add_row(
            _type_style(e),
            e.path,
            _human_size(e.size_bytes),
            e.detected_by,
            e.platform_hint,
            f"{e.confidence:.2f}",
        )
    return table


def _type_style(e: Evidence) -> str:
    if e.evidence_type == "unknown":
        return f"[dim]{e.evidence_type}[/]"
    return f"[green]{e.evidence_type}[/]"


def _human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(n)
    for u in units:
        if size < 1024 or u == units[-1]:
            return f"{size:.1f}{u}" if u != "B" else f"{int(size)}B"
        size /= 1024
    return f"{n}B"
