"""Base view: a scrollable page with a header, plus notify/copy helpers."""
from __future__ import annotations

import tkinter as tk
from pathlib import Path

from ..theme import COLORS, FONTS
from ..widgets import ScrollFrame, h1, lab, muted

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
PADX = 32


class BaseView(tk.Frame):
    def __init__(self, app, master):
        super().__init__(master, bg=COLORS["bg"])
        self.app = app
        scroll = ScrollFrame(self)
        scroll.pack(fill="both", expand=True)
        self.content = scroll.inner

    def header(self, title_text, subtitle, tag=None):
        top = tk.Frame(self.content, bg=COLORS["bg"])
        top.pack(fill="x", padx=PADX, pady=(28, 14))
        if tag:
            lab(top, tag.upper(), fg=COLORS["green"], font=FONTS["tag"]).pack(fill="x")
        h1(top, title_text).pack(fill="x", pady=(2, 6))
        muted(top, subtitle).pack(fill="x")

    def add(self, widget, pady=8):
        widget.pack(fill="x", padx=PADX, pady=pady)
        return widget

    def spacer(self, height=24):
        tk.Frame(self.content, bg=COLORS["bg"], height=height).pack(fill="x")

    def notify(self, msg):
        self.app.notify(msg)

    def copy(self, text):
        self.app.copy(text)
