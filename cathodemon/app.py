"""Cathodemon main window: sidebar navigation, swappable views and a status bar."""
from __future__ import annotations

import tkinter as tk

from .theme import COLORS, FONTS, apply_theme
from .widgets import load_logo
from .ui.dashboard import DashboardView
from .ui.mail_view import MailView
from .ui.recon_view import ReconView
from .ui.vault_view import VaultView
from .ui.chronicle_view import ChronicleView
from .ui.dns_view import DnsView

_SPECS = [
    ("home", "\u2302", "Home", DashboardView),
    ("mail", "\u2709", "Mail", MailView),
    ("recon", "\u25ce", "Recon", ReconView),
    ("vault", "\u26bf", "Vault", VaultView),
    ("chronicle", "\u2630", "Chronicle", ChronicleView),
    ("dns", "\u29bf", "DNS Shield", DnsView),
]


class _NavItem(tk.Frame):
    def __init__(self, master, icon, label, command):
        super().__init__(master, bg=COLORS["sidebar"], cursor="hand2")
        self.active = False
        self.bar = tk.Frame(self, bg=COLORS["sidebar"], width=4)
        self.bar.pack(side="left", fill="y")
        self.icon = tk.Label(self, text=icon, bg=COLORS["sidebar"], fg=COLORS["muted"],
                             font=FONTS["nav"], width=2)
        self.icon.pack(side="left", padx=(14, 6), pady=9)
        self.text = tk.Label(self, text=label, bg=COLORS["sidebar"], fg=COLORS["muted"],
                             font=FONTS["nav"], anchor="w")
        self.text.pack(side="left", fill="x", expand=True)
        for w in (self, self.icon, self.text):
            w.bind("<Button-1>", lambda _e: command())
            w.bind("<Enter>", lambda _e: self._paint(hover=True))
            w.bind("<Leave>", lambda _e: self._paint())

    def set_active(self, value):
        self.active = value
        self._paint()

    def _paint(self, hover=False):
        if self.active:
            bg, fg, bar = COLORS["panel"], COLORS["green"], COLORS["green"]
        elif hover:
            bg, fg, bar = COLORS["panel"], COLORS["text"], COLORS["panel"]
        else:
            bg, fg, bar = COLORS["sidebar"], COLORS["muted"], COLORS["sidebar"]
        for w in (self, self.icon, self.text):
            w.configure(bg=bg)
        self.icon.configure(fg=fg)
        self.text.configure(fg=fg)
        self.bar.configure(bg=bar)


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Cathodemon \u2014 home security suite")
        # Fit small or scaled screens (a 1920x1080 laptop at 125% is 1536x864):
        # leave room for the title bar and the taskbar so the status bar shows.
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        width, height = min(1220, sw - 60), min(840, sh - 140)
        root.geometry(f"{width}x{height}+{max(0, (sw - width) // 2)}+20")
        root.minsize(min(980, width), min(640, height))
        apply_theme(root)

        self._icon = load_logo(root, 16)  # window and taskbar icon; kept referenced
        if self._icon is not None:
            try:
                root.iconphoto(True, self._icon)
            except tk.TclError:
                pass

        self.status = tk.Label(root, text="ready", bg=COLORS["sidebar"], fg=COLORS["faint"],
                               font=FONTS["small"], anchor="w", padx=14, pady=5)
        self.status.pack(side="bottom", fill="x")

        container = tk.Frame(root, bg=COLORS["bg"])
        container.pack(side="top", fill="both", expand=True)

        sidebar = tk.Frame(container, bg=COLORS["sidebar"], width=214)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Frame(container, bg=COLORS["line"], width=1).pack(side="left", fill="y")

        brand = tk.Frame(sidebar, bg=COLORS["sidebar"])
        brand.pack(fill="x", padx=18, pady=(22, 26))
        tk.Label(brand, text="CATHODEMON", bg=COLORS["sidebar"], fg=COLORS["green"],
                 font=FONTS["h2"], anchor="w").pack(fill="x")
        tk.Label(brand, text="home security suite", bg=COLORS["sidebar"], fg=COLORS["faint"],
                 font=FONTS["small"], anchor="w").pack(fill="x")

        self.body = tk.Frame(container, bg=COLORS["bg"])
        self.body.pack(side="left", fill="both", expand=True)
        self.body.grid_rowconfigure(0, weight=1)
        self.body.grid_columnconfigure(0, weight=1)

        self.nav = {}
        self.views = {}
        for key, icon, label, cls in _SPECS:
            item = _NavItem(sidebar, icon, label, lambda k=key: self.navigate(k))
            item.pack(fill="x")
            self.nav[key] = item
            view = cls(self, self.body)
            view.grid(row=0, column=0, sticky="nsew")
            self.views[key] = view

        tk.Label(sidebar, text="old tech,\nmodern problems", bg=COLORS["sidebar"],
                 fg=COLORS["faint"], font=FONTS["small"], justify="left",
                 anchor="w").pack(side="bottom", fill="x", padx=18, pady=16)

        self._status_after = None
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.navigate("home")

    def navigate(self, key):
        self.views[key].tkraise()
        for k, item in self.nav.items():
            item.set_active(k == key)

    def close(self):
        """Stop background services (the DNS server) before the window goes away."""
        for view in self.views.values():
            stop = getattr(view, "shutdown", None)
            if stop:
                try:
                    stop()
                except Exception:  # noqa: BLE001 - closing must always succeed
                    pass
        self.root.destroy()

    def notify(self, msg):
        self.status.configure(text=msg, fg=COLORS["text"])
        if self._status_after:
            self.root.after_cancel(self._status_after)
        self._status_after = self.root.after(
            4000, lambda: self.status.configure(text="ready", fg=COLORS["faint"]))

    def copy(self, text):
        if not text:
            self.notify("Nothing to copy")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.notify("Copied to clipboard")
