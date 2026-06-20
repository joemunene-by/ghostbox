"""Console rendering of a Report using rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ghostbox.report import Report
from ghostbox.utils import human_size

_BAND_STYLE = {"clean": "green", "suspicious": "yellow", "malicious": "red"}


def render_console(report: Report, console: Console) -> None:
    """Render a full report to the given console."""
    if report.error:
        console.print(
            Panel(
                Text(report.error, style="red"),
                title=f"ghostbox: {report.path}",
                border_style="red",
            )
        )
        return

    _render_header(report, console)
    _render_identity(report, console)
    _render_structure(report, console)
    _render_capabilities(report, console)
    _render_iocs(report, console)
    _render_yara(report, console)
    _render_score(report, console)
    _render_warnings(report, console)


def _render_header(report: Report, console: Console) -> None:
    style = _BAND_STYLE.get(report.band, "white")
    title = Text("ghostbox static analysis", style="bold")
    sub = Text(f"{report.path}  ({human_size(report.size)})", style=style)
    console.print(Panel(sub, title=title, border_style=style))


def _render_identity(report: Report, console: Console) -> None:
    h = report.get("hashing", {})
    f = report.get("filetype", {})
    table = Table(title="Identity", show_header=False, expand=False)
    table.add_column("k", style="cyan", no_wrap=True)
    table.add_column("v")
    table.add_row("type", str(f.get("description", "unknown")))
    table.add_row("size", human_size(report.size))
    table.add_row("md5", str(h.get("md5", "")))
    table.add_row("sha1", str(h.get("sha1", "")))
    table.add_row("sha256", str(h.get("sha256", "")))
    console.print(table)


def _render_structure(report: Report, console: Console) -> None:
    pe = report.get("pe")
    elf = report.get("elf")
    ent = report.get("entropy", {})

    if isinstance(pe, dict) and "error" not in pe:
        table = Table(title=f"PE structure ({pe.get('backend')})")
        table.add_column("section", style="cyan")
        table.add_column("vaddr", justify="right")
        table.add_column("vsize", justify="right")
        table.add_column("raw", justify="right")
        table.add_column("entropy", justify="right")
        for s in pe.get("sections", []):
            table.add_row(
                str(s.get("name")),
                hex(s.get("virtual_address", 0)),
                str(s.get("virtual_size", 0)),
                str(s.get("raw_size", 0)),
                f"{s.get('entropy', 0):.3f}",
            )
        console.print(table)
        susp = pe.get("suspicious_imports", [])
        if susp:
            it = Table(title="Suspicious imports")
            it.add_column("dll", style="cyan")
            it.add_column("function", style="red")
            it.add_column("reason")
            for row in susp[:30]:
                it.add_row(row["dll"], row["function"], row["reason"])
            console.print(it)

    if isinstance(elf, dict) and "error" not in elf:
        table = Table(title=f"ELF structure ({elf.get('backend')})")
        table.add_column("info", style="cyan")
        table.add_column("value")
        table.add_row("class", str(elf.get("class")))
        table.add_row("machine", str(elf.get("machine")))
        table.add_row("type", str(elf.get("type")))
        table.add_row("entry", hex(elf.get("entry_point", 0)))
        table.add_row("sections", str(len(elf.get("sections", []))))
        console.print(table)

    if isinstance(ent, dict):
        line = Text()
        line.append("overall entropy: ", style="cyan")
        line.append(f"{ent.get('overall', 0):.3f}")
        if ent.get("packers"):
            line.append("   packers: ", style="cyan")
            line.append(", ".join(ent["packers"]), style="red")
        console.print(line)


def _render_capabilities(report: Report, console: Console) -> None:
    caps = report.get("capabilities", {})
    tags = caps.get("tags", []) if isinstance(caps, dict) else []
    if not tags:
        return
    table = Table(title="Capabilities")
    table.add_column("tag", style="magenta")
    table.add_column("weight", justify="right")
    table.add_column("evidence")
    for t in tags:
        table.add_row(t["tag"], str(t["weight"]), ", ".join(t["evidence"]))
    console.print(table)


def _render_iocs(report: Report, console: Console) -> None:
    section = report.get("strings_ioc", {})
    iocs = section.get("iocs", {}) if isinstance(section, dict) else {}
    rows = [(k, v) for k, v in iocs.items() if v]
    if not rows:
        return
    table = Table(title="IOCs")
    table.add_column("kind", style="cyan")
    table.add_column("values")
    for kind, values in rows:
        table.add_row(kind, "\n".join(values[:20]))
    console.print(table)


def _render_yara(report: Report, console: Console) -> None:
    y = report.get("yara", {})
    if not isinstance(y, dict):
        return
    if not y.get("enabled"):
        return
    matches = y.get("matches", [])
    if not matches:
        console.print(Text("YARA: no matches", style="green"))
        return
    table = Table(title="YARA matches")
    table.add_column("rule", style="red")
    table.add_column("tags")
    for m in matches:
        table.add_row(m["rule"], ", ".join(m.get("tags", [])))
    console.print(table)


def _render_score(report: Report, console: Console) -> None:
    style = _BAND_STYLE.get(report.band, "white")
    table = Table(title="Threat score", show_header=False)
    table.add_column("k", style="cyan")
    table.add_column("v")
    table.add_row("score", Text(f"{report.score}/100", style=f"bold {style}"))
    table.add_row("band", Text(report.band.upper(), style=f"bold {style}"))
    console.print(table)

    if report.signals:
        st = Table(title="Contributing signals")
        st.add_column("signal", style="cyan")
        st.add_column("weight", justify="right")
        st.add_column("detail")
        for s in sorted(report.signals, key=lambda x: -x.weight):
            st.add_row(s.name, str(s.weight), s.detail)
        console.print(st)


def _render_warnings(report: Report, console: Console) -> None:
    if report.warnings:
        console.print(Panel("\n".join(report.warnings), title="Warnings", border_style="yellow"))
