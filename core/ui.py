# core/ui.py
import os
import re as _re
import sys
from contextlib import contextmanager

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    from rich import box

    HAS_RICH = True
except Exception:
    HAS_RICH = False


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_console = None
NO_COLOR = False
QUIET = False
VERBOSE = False


class _PlainStatus:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def init(no_color=False, quiet=False, verbose=False, width=None):
    global _console, NO_COLOR, QUIET, VERBOSE
    QUIET = quiet
    VERBOSE = verbose
    NO_COLOR = (
        no_color
        or bool(os.environ.get("NO_COLOR"))
        or not sys.stdout.isatty()
    )
    if HAS_RICH and not NO_COLOR:
        kwargs = {"highlight": False, "soft_wrap": True}
        if width:
            kwargs["width"] = width
        _console = Console(**kwargs)
    else:
        _console = None


def _strip_markup(text):
    return _re.sub(r"\[/?.*?\]", "", text)


def _plain_print(msg=""):
    print(msg, flush=True)


def _print(renderable, **kwargs):
    if QUIET:
        return
    if _console is not None:
        _console.print(renderable, **kwargs)
    else:
        if isinstance(renderable, str):
            _plain_print(renderable)
        else:
            _plain_print(getattr(renderable, "plain_text", ""))


@contextmanager
def status(message):
    if _console is not None:
        with _console.status(f"[bold cyan]{message}[/bold cyan]", spinner="dots"):
            yield
    else:
        if not QUIET:
            print(f"[*] {message}", flush=True)
        yield


def ok(msg):
    if _console is not None:
        _print(f"[bold green][+][/bold green] {msg}")
    else:
        print("[+] " + msg)


def info(msg):
    if _console is not None:
        _print(f"[bold cyan][*][/bold cyan] {msg}")
    else:
        print("[*] " + msg)


def warn(msg):
    if _console is not None:
        _print(f"[bold yellow][!][/bold yellow] {msg}")
    else:
        print("[!] " + msg)


def err(msg):
    if _console is not None:
        _print(f"[bold red][x][/bold red] {msg}", file=sys.stderr)
    else:
        print("[x] " + msg, file=sys.stderr, flush=True)


def dim(msg):
    if not VERBOSE:
        return
    if _console is not None:
        _print(f"[dim]{msg}[/dim]")
    else:
        print(msg)


def sub(msg):
    if QUIET:
        return
    if _console is not None:
        _print(f"  [green]>[/green] {msg}")
    else:
        print(f"  > {msg}")


def raw(text):
    """Print pre-formatted text; markup honored only when rich is active."""
    if QUIET:
        return
    if _console is not None:
        _print(text)
    else:
        print(_strip_markup(text))


def result_line(kind, msg):
    mapping = {
        "ok": ok,
        "info": info,
        "warn": warn,
        "dim": dim,
    }
    fn = mapping.get(kind, info)
    fn(msg)


def rule(title="", style="cyan"):
    if QUIET:
        return
    if _console is not None:
        if title:
            _console.rule(f"[bold {style}]{title}[/bold {style}]", style=style)
        else:
            _console.rule(characters="─", style=style)
    else:
        line = "─" * 8
        header = f"{line} {title} " + line if title else line * 3
        print()
        print(header)


def panel(lines, title=None, border_style="cyan"):
    if QUIET:
        return
    body = "\n".join(lines)
    if _console is not None:
        text = Text.from_markup(body)
        _print(Panel(text, title=title, border_style=border_style, box=box.ROUNDED))
    else:
        lines = [_strip_markup(l) for l in lines]
        width = max([len(l) for l in lines] or [20]) + 4
        if title:
            print(f"┌─ {title} ".ljust(width, "─") + "┐")
        else:
            print("┌" + "─" * (width - 2) + "┐")
        for l in lines:
            print("│ " + l.ljust(width - 4) + " │")
        print("└" + "─" * (width - 2) + "┘")


def table(title, columns, rows, styles=None):
    if QUIET:
        return
    styles = styles or {}
    if _console is not None:
        t = Table(title=title, box=box.SIMPLE_HEAVY, title_style="bold cyan")
        for col in columns:
            t.add_column(col, style=styles.get(col))
        for row in rows:
            cells = []
            for c in row:
                if isinstance(c, Text):
                    cells.append(c)
                else:
                    cells.append(Text.from_markup(str(c)))
            t.add_row(*cells)
        _print(t)
    else:
        if title:
            print(f"\n{title}")
        widths = []
        for i, col in enumerate(columns):
            w = len(col)
            for row in rows:
                cell = row[i]
                plain = getattr(cell, "plain", str(cell))
                w = max(w, len(plain))
            widths.append(w)
        header = "  ".join(col.ljust(widths[i]) for i, col in enumerate(columns))
        print(header)
        print("  ".join("-" * widths[i] for i in range(len(columns))))
        for row in rows:
            cells = []
            for i, c in enumerate(row):
                plain = getattr(c, "plain", str(c))
                cells.append(plain.ljust(widths[i]))
            print("  ".join(cells))


BANNER_ART = r"""[bold blue]
 __      __                .__         .__  __
/  \    /  \_____  _______ |  |   ____ |__|/  |_
\   \/\/   /\__  \ \____ \|  |  /  _ \|  \   __\
 \        /  / __ \|  |_> >  |_(  <_> )  ||  |
  \__/\  /  (____  /   __/|____/\____/|__||__|
       \/        \/|__|
[/bold blue]"""


def banner(version):
    if QUIET:
        return
    if _console is not None:
        _print(BANNER_ART)
        _print(
            f"      [bold magenta]Wpsploit[/bold magenta] [dim]v{version}[/dim]"
            " — WordPress Recon & Attack-Surface Mapper\n"
        )
    else:
        art = BANNER_ART.replace("[bold blue]", "").replace("[/bold blue]", "")
        print(art)
        print(f"      Wpsploit v{version} - WordPress Recon & Attack-Surface Mapper\n")


def severity_text(sev):
    colors = {
        "critical": ("bold red", "CRIT"),
        "high": ("red", "HIGH"),
        "medium": ("yellow", "MED "),
        "low": ("blue", "LOW "),
        "info": ("cyan", "INFO"),
    }
    style, label = colors.get(sev, ("white", sev.upper()))
    if _console is not None:
        return Text(label.strip(), style=style)
    return label.strip()


def findings_table(findings):
    rows = []
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 99))
    for f in ordered:
        sev = severity_text(f.get("severity", "info"))
        title = str(f.get("title", ""))
        detail = str(f.get("detail", ""))
        module = str(f.get("module", ""))
        if _console is not None:
            d = Text(detail, style="dim") if detail else Text("")
            rows.append([sev, module, title, d])
        else:
            rows.append([sev, module, title, detail])
    table(
        "Findings",
        ["Severity", "Module", "Issue", "Detail"],
        rows,
    )


def risk_summary(score, grade, counts):
    counts_str = "  ".join(f"{k}:{v}" for k, v in counts.items() if v)
    grade_colors = {"A": "green", "B": "cyan", "C": "yellow", "D": "yellow", "F": "red"}
    color = grade_colors.get(grade, "white")
    lines = [
        f"[bold]Risk Score:[/bold] [{color}]{score}/100 ({grade})[/{color}]",
    ]
    if counts_str:
        lines.append(f"[dim]{counts_str}[/dim]")
    panel(lines, title="Risk Assessment", border_style=color)


def next_steps(suggestions):
    if not suggestions:
        return
    lines = ["[bold]Suggested next steps[/bold]"]
    for s in suggestions:
        lines.append(f"  • {s}")
    panel(lines, border_style="magenta")
