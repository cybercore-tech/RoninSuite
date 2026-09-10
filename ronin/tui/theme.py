"""CYBERCORE / CYBERGRID palette for the RoninSuite TUI.

    blue  #00BFFF     purple #B026FF     cyan #00FFFF     base #06080D
"""
from __future__ import annotations

from textual.theme import Theme

BLUE = "#00BFFF"
PURPLE = "#B026FF"
CYAN = "#00FFFF"
BASE = "#06080D"
GRID = "#0e1726"

CYBERCORE = Theme(
    name="cybercore",
    primary=BLUE,
    secondary=PURPLE,
    accent=CYAN,
    foreground="#c9dbec",
    background=BASE,
    surface="#0a0f1a",
    panel="#0d1424",
    success="#00ffa3",
    warning="#ffcf3f",
    error="#ff3b6b",
    dark=True,
    variables={
        "border": f"{BLUE} 45%",
        "border-blurred": "#16233a",
        "block-cursor-foreground": BASE,
        "block-cursor-background": CYAN,
        "block-cursor-text-style": "bold",
        "block-hover-background": f"{BLUE} 12%",
        "footer-key-foreground": CYAN,
        "footer-description-foreground": "#8fb3cc",
        "footer-background": "#080c15",
        "datatable--header-cursor-background": PURPLE,
        "datatable--header-background": "#0b1220",
        "datatable--header-foreground": CYAN,
        "datatable--cursor-background": f"{BLUE} 25%",
        "datatable--cursor-foreground": CYAN,
        "datatable--hover-background": f"{BLUE} 10%",
        "input-selection-background": f"{PURPLE} 40%",
        "input-cursor-background": CYAN,
        "scrollbar": "#0d1424",
        "scrollbar-hover": BLUE,
        "scrollbar-active": PURPLE,
        "button-focus-text-style": "bold",
    },
)

# cyberpunk wordmark - ANSI Shadow "RONIN", cyan→magenta gradient, with a
# glitch strip + SUITE line under it.
_RONIN = [
    "██████╗  ██████╗ ███╗   ██╗██╗███╗   ██╗",
    "██╔══██╗██╔═══██╗████╗  ██║██║████╗  ██║",
    "██████╔╝██║   ██║██╔██╗ ██║██║██╔██╗ ██║",
    "██╔══██╗██║   ██║██║╚██╗██║██║██║╚██╗██║",
    "██║  ██║╚██████╔╝██║ ╚████║██║██║ ╚████║",
    "╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝",
]
_GRAD = [CYAN, CYAN, "#3ad0ff", BLUE, "#8a4dff", PURPLE]
BANNER = "\n".join(f"[{_GRAD[i]}]{ln}[/]" for i, ln in enumerate(_RONIN)) + (
    f"\n[{BLUE}]▟▙▂▂▂▂▂▂▂▂▂▂▂▂▂[/]"
    f"[{PURPLE}]  S U I T E  [/]"
    f"[{BLUE}]▂▂▂▂▂▂▂▂▂▂▂▂▂▙▟[/]"
)

SEV_STYLE = {
    "critical": "bold #ff3b6b",
    "high": "#ff7a45",
    "medium": "#ffcf3f",
    "low": CYAN,
    "info": "#5f7a92",
}
STATUS_STYLE = {
    "open": "#ff7a45",
    "in_progress": "#ffcf3f",
    "fixed": CYAN,
    "accepted": "#8fb3cc",
    "closed": "#00ffa3",
}
