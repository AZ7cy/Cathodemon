"""Home: block-letter banner, one card per tool, and what the app saves."""
from __future__ import annotations

import tkinter as tk

from ..core import blocklist, securemsg
from ..theme import COLORS, FONTS
from ..widgets import Panel, lab, load_logo, muted, small
from . import banner as block_letters
from .base import BaseView, PADX

_BANNER = block_letters.render("Cathodemon")

_CARDS = [
    ("\u2709", "Mail", "mail", "Lock and sign messages with your own keys, and check whether an "
                                "email is a scam."),
    ("\u25ce", "Recon", "recon", "Paste a website address and get a plain-language safety report."),
    ("\u26bf", "Vault", "vault", "Test a password, make a strong passphrase and check your "
                                  "password habits."),
    ("\u2630", "Chronicle", "chronicle", "Turn computer logs into a plain story of who tried to "
                                         "get in, and when."),
    ("\u29bf", "DNS Shield", "dns", "Block ads, trackers and fake websites for every device in "
                                     "your home."),
]


class DashboardView(BaseView):
    def __init__(self, app, master):
        super().__init__(app, master)
        top = tk.Frame(self.content, bg=COLORS["bg"])
        top.pack(fill="x", padx=PADX, pady=(32, 8))
        self._logo = load_logo(self, 2)  # ~256px; kept as an attribute so Tk won't drop it
        if self._logo is not None:
            tk.Label(top, image=self._logo, bg=COLORS["bg"]).pack(anchor="w")
        else:
            lab(top, _BANNER, fg=COLORS["green"], font=FONTS["banner"]).pack(anchor="w")
        lab(top, "A home security suite. Old tech, modern problems.", fg=COLORS["text"],
            font=FONTS["h2"]).pack(anchor="w", pady=(14, 4))
        muted(top, "Pick a tool to start. Everything runs on this computer, and the code is built "
                   "from scratch on the Python standard library.").pack(fill="x")

        grid = tk.Frame(self.content, bg=COLORS["bg"])
        grid.pack(fill="x", padx=PADX, pady=(12, 0))
        grid.columnconfigure(0, weight=1, uniform="card")
        grid.columnconfigure(1, weight=1, uniform="card")
        for i, (glyph, name, key, desc) in enumerate(_CARDS):
            self._card(grid, glyph, name, key, desc).grid(row=i // 2, column=i % 2, sticky="nsew",
                                                          padx=(0, 8) if i % 2 == 0 else (8, 0), pady=8)

        saved = self.add(Panel(self.content, "What Cathodemon saves on this computer"), pady=(16, 8))
        for line in [
            f"Mail: your identity and contacts, in {securemsg.KEYRING_PATH}. Private keys are "
            f"locked with your passphrase.",
            f"DNS Shield: your own block and allow lists, in {blocklist.USER_DIR}.",
            "Nothing else. Vault answers, passwords you test, logs you paste and DNS Shield's "
            "activity are kept in memory and gone when you close the app.",
        ]:
            muted(saved.body, "\u2022  " + line).pack(fill="x", pady=2)
        self.spacer()

    def _card(self, parent, glyph, name, key, desc):
        card = tk.Frame(parent, bg=COLORS["panel"], highlightthickness=1,
                        highlightbackground=COLORS["line"], cursor="hand2")
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="both", expand=True, padx=20, pady=18)
        head = tk.Frame(inner, bg=COLORS["panel"])
        head.pack(fill="x")
        lab(head, glyph, fg=COLORS["green"], font=FONTS["h2"]).pack(side="left", padx=(0, 10))
        lab(head, name, fg=COLORS["text"], font=FONTS["h2"]).pack(side="left")
        lab(head, "Open \u2192", fg=COLORS["faint"], font=FONTS["small_bold"]).pack(side="right")
        muted(inner, desc).pack(fill="x", pady=(8, 0))

        def paint(hover):
            card.configure(highlightbackground=COLORS["green_dim"] if hover else COLORS["line"])

        widgets = [card, inner, head] + list(inner.winfo_children()) + list(head.winfo_children())
        for w in widgets:
            w.bind("<Button-1>", lambda _e: self.app.navigate(key))
            w.bind("<Enter>", lambda _e: paint(True), add="+")
            w.bind("<Leave>", lambda _e: paint(False), add="+")
        return card
