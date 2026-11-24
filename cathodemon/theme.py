"""Toxic-green-on-black palette, fonts and ttk styling for the Tkinter UI.

Standard library only. Fonts are ones Windows ships with; on other systems
apply_theme() swaps in fonts that exist there.
"""
from __future__ import annotations

import tkinter.font as tkfont
from tkinter import ttk

COLORS = {
    # surfaces
    "bg": "#070F0B",          # window background, near-black with a green tint
    "sidebar": "#040A07",
    "panel": "#0C1712",       # cards
    "panel_hi": "#12211A",    # hovered card, selected item
    "input": "#08120E",       # text fields
    "line": "#1A2E25",        # borders
    "line_hi": "#2D4D3D",     # focused border
    "sel": "#1E3A2B",         # selected text
    # accent: toxic green
    "green": "#7CFF3A",
    "green_bright": "#B6FF7C",
    "green_dim": "#3E8F2B",
    "ink": "#04160A",         # text on green buttons
    # meaning
    "cyan": "#2BD9B4",        # information
    "amber": "#FFC542",       # medium risk
    "yellow": "#E8F35C",      # low risk
    "red": "#FF5A6A",         # high risk
    # text
    "text": "#E3F6EA",
    "muted": "#8AA898",
    "faint": "#5C786A",
}

SANS = "Segoe UI"
HEAD = "Bahnschrift"
MONO = "Cascadia Mono"

FONTS = {
    "base": (SANS, 10),
    "small": (SANS, 9),
    "small_bold": (SANS, 9, "bold"),
    "tag": (HEAD, 9, "bold"),
    "bold": (SANS, 10, "bold"),
    "big": (SANS, 12),
    "button": (SANS, 10, "bold"),
    "h1": (HEAD, 22, "bold"),
    "h2": (HEAD, 14, "bold"),
    "title": (HEAD, 11, "bold"),
    "nav": (HEAD, 12),
    "score": (HEAD, 36, "bold"),
    "band": (HEAD, 16, "bold"),
    "mono": (MONO, 10),
    "mono_small": (MONO, 9),
    "mono_big": (MONO, 14),
    "banner": (MONO, 9),
}

_SEV = {"high": "red", "medium": "amber", "low": "yellow", "good": "green", "info": "cyan"}
_BAND = {
    "TRUSTED": "green", "LIKELY OK": "green", "CAUTION": "amber", "SUSPICIOUS": "amber",
    "DANGER": "red", "QUESTIONABLE": "yellow", "LOW RISK": "green", "LOOKS CLEAN": "green",
    "at risk": "red", "room to improve": "amber", "solid habits": "green",
}


def sev_color(sev):
    return COLORS.get(_SEV.get(sev, "text"), COLORS["text"])


def band_color(band):
    return COLORS.get(_BAND.get(band, "green"), COLORS["green"])


def _pick_fonts(root):
    """Use Windows' fonts where they exist, otherwise close equivalents."""
    families = set(tkfont.families(root))

    def first(*names):
        return next((n for n in names if n in families), names[-1])

    sans = first(SANS, "Helvetica Neue", "Helvetica", "DejaVu Sans", "TkDefaultFont")
    head = first(HEAD, "DIN Alternate", "Arial Narrow", sans)
    mono = first(MONO, "Consolas", "Menlo", "DejaVu Sans Mono", "TkFixedFont")
    swap = {SANS: sans, HEAD: head, MONO: mono}
    for key, spec in FONTS.items():
        FONTS[key] = (swap.get(spec[0], spec[0]),) + tuple(spec[1:])


def apply_theme(root):
    _pick_fonts(root)
    c = COLORS
    root.configure(bg=c["bg"])
    root.option_add("*TCombobox*Listbox.background", c["panel_hi"])
    root.option_add("*TCombobox*Listbox.foreground", c["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", c["green_dim"])
    root.option_add("*TCombobox*Listbox.selectForeground", c["text"])
    root.option_add("*TCombobox*Listbox.font", FONTS["base"])
    root.option_add("*TCombobox*Listbox.relief", "flat")

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    # The clam theme draws light grey borders and shrinks the selected tab, so
    # every border colour and the selected padding are set here.
    style.configure("TNotebook", background=c["bg"], borderwidth=0, tabmargins=(0, 0, 0, 0),
                    bordercolor=c["line"], lightcolor=c["panel"], darkcolor=c["panel"])
    style.configure("TNotebook.Tab", background=c["bg"], foreground=c["muted"], padding=(16, 9),
                    font=FONTS["button"], borderwidth=0, bordercolor=c["line"],
                    lightcolor=c["bg"], darkcolor=c["bg"])
    style.map("TNotebook.Tab",
              padding=[("selected", (16, 9))],
              expand=[("selected", (0, 0, 0, 0))],
              background=[("selected", c["panel"]), ("active", c["panel_hi"])],
              lightcolor=[("selected", c["panel"]), ("active", c["panel_hi"])],
              foreground=[("selected", c["green"]), ("active", c["text"])])

    style.configure("Treeview", background=c["input"], fieldbackground=c["input"],
                    foreground=c["text"], borderwidth=0, font=FONTS["mono_small"], rowheight=24,
                    bordercolor=c["line"], lightcolor=c["input"], darkcolor=c["input"])
    style.configure("Treeview.Heading", background=c["panel_hi"], foreground=c["muted"],
                    font=FONTS["small"], borderwidth=0, relief="flat", padding=(6, 5),
                    bordercolor=c["line"], lightcolor=c["panel_hi"], darkcolor=c["panel_hi"])
    style.map("Treeview", background=[("selected", c["sel"])], foreground=[("selected", c["text"])])
    style.map("Treeview.Heading", background=[("active", c["panel_hi"])])

    style.configure("TCombobox", fieldbackground=c["input"], background=c["panel_hi"],
                    foreground=c["text"], arrowcolor=c["green"], bordercolor=c["line"],
                    lightcolor=c["line"], darkcolor=c["line"], borderwidth=1, padding=6)
    style.map("TCombobox",
              fieldbackground=[("readonly", c["input"]), ("disabled", c["bg"])],
              foreground=[("readonly", c["text"]), ("disabled", c["faint"])],
              selectbackground=[("readonly", c["input"])],
              selectforeground=[("readonly", c["text"])],
              bordercolor=[("focus", c["line_hi"])],
              arrowcolor=[("disabled", c["faint"])])

    for orient in ("Vertical", "Horizontal"):
        style.configure(f"{orient}.TScrollbar", background=c["line"], troughcolor=c["bg"],
                        borderwidth=0, arrowcolor=c["muted"], gripcount=0,
                        bordercolor=c["bg"], lightcolor=c["line"], darkcolor=c["line"])
        style.map(f"{orient}.TScrollbar", background=[("active", c["line_hi"])])
