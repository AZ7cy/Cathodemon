"""DNS Shield view: run Cathodemon's own DNS server, which blocks ads, trackers
and fake look-alike websites for every device on the home network."""
from __future__ import annotations

import os
import time
import tkinter as tk
from tkinter import ttk

from ..core import blocklist, dnswire
from ..core.resolver import shared_resolver
from ..core.sinkhole import Shield, lan_ip
from ..theme import COLORS, FONTS
from ..widgets import (Collapsible, Panel, button, check, entry, lab, muted, note, set_text,
                       small, steps, text_box)
from ..workers import run_async
from .base import BaseView

RESULT_NAMES = {"blocked": "blocked", "allowed": "allowed", "local": "answered here",
                "refused": "refused"}


def _busy_port_hint():
    if os.name == "nt":
        return ("Another program on this computer is already using that port, often a hotspot, "
                "a VPN or another DNS server. Close it, or try a different port to test.")
    return ("On Linux, port 53 needs root, so start Cathodemon with sudo, and systemd-resolved "
            "may already be using the port. Or try a different port to test.")


def _flow_box(parent, heading, text, color_key="line"):
    box = tk.Frame(parent, bg=COLORS["panel_hi"], highlightthickness=1,
                   highlightbackground=COLORS[color_key])
    lab(box, heading, fg=COLORS["green"], font=FONTS["tag"], bg=COLORS["panel_hi"]).pack(fill="x", padx=12, pady=(10, 2))
    lab(box, text, bg=COLORS["panel_hi"], wrap="auto").pack(fill="x", padx=12, pady=(0, 10))
    return box


class DnsView(BaseView):
    def __init__(self, app, master):
        super().__init__(app, master)
        self.shield = None
        self._shown = 0
        self.header("DNS Shield", "Stops ads, trackers and fake websites on every device in your "
                    "home, including phones and smart TVs, without installing anything on them.",
                    tag="network ad and scam blocker")
        self._how_it_works()
        self._controls()
        self._tester()
        self._activity()
        self._setup_steps()
        self._rules()
        self.spacer()

    # ---------------------------------------------------------------- explanation
    def _how_it_works(self):
        p = self.add(Panel(self.content, "How it works"))
        muted(p.body, "Before a phone, laptop or TV opens a website or an app, it asks a DNS server "
                      "for the site's address, the way you'd look up a number in a phone book. "
                      "DNS Shield is a DNS server that runs on this computer. Your devices ask it "
                      "instead, and for ads, trackers and fake look-alike sites it gives no real "
                      "address, so they never load. Everything else is looked up as normal, "
                      "directly from the internet's own DNS servers.").pack(fill="x")
        flow = tk.Frame(p.body, bg=COLORS["panel"])
        flow.pack(fill="x", pady=(14, 0))
        for col in (0, 2, 4):
            flow.columnconfigure(col, weight=1, uniform="flow")
        boxes = [
            ("1. A device asks", "\"Where is ads.example.com?\""),
            ("2. DNS Shield checks", "Is it an ad, a tracker or a fake site?"),
            ("3. It answers", "Blocked: the ad doesn't load. Allowed: the site opens as usual."),
        ]
        for i, (heading, text) in enumerate(boxes):
            _flow_box(flow, heading, text).grid(row=0, column=i * 2, sticky="nsew")
            if i < 2:
                lab(flow, "\u2192", fg=COLORS["green"], font=FONTS["h2"]).grid(row=0, column=i * 2 + 1, padx=8)

    # ---------------------------------------------------------------- on / off
    def _controls(self):
        p = self.add(Panel(self.content, "Turn it on"))
        row = tk.Frame(p.body, bg=COLORS["panel"])
        row.pack(fill="x")
        self.state_lbl = lab(row, "\u25cb  Off", fg=COLORS["muted"], font=FONTS["band"])
        self.state_lbl.pack(side="left")
        self.toggle_btn = button(row, "Start DNS Shield", self.toggle, "primary")
        self.toggle_btn.pack(side="right")
        self.status = muted(p.body, "Not answering any devices yet.")
        self.status.pack(fill="x", pady=(8, 0))

        adv = Collapsible(p.body, "Advanced settings")
        adv.pack(fill="x", pady=(12, 0))
        grid = tk.Frame(adv.body, bg=COLORS["panel"])
        grid.pack(fill="x")
        lab(grid, "Listen on").grid(row=0, column=0, sticky="w", pady=4)
        self.host = entry(grid, width=18)
        self.host.insert(0, "0.0.0.0")
        self.host.grid(row=0, column=1, sticky="w", padx=10, ipady=4)
        small(grid, "0.0.0.0 means every network this computer is on.", wrap=None).grid(row=0, column=2, sticky="w")
        lab(grid, "Port").grid(row=1, column=0, sticky="w", pady=4)
        self.port = entry(grid, width=18)
        self.port.insert(0, "53")
        self.port.grid(row=1, column=1, sticky="w", padx=10, ipady=4)
        small(grid, "Devices always use 53. Change it only to test.", wrap=None).grid(row=1, column=2, sticky="w")
        self.smart = tk.BooleanVar(value=True)
        self.local_only = tk.BooleanVar(value=True)
        check(adv.body, "Block fake look-alike websites, such as ebonm4rsh.example pretending to "
                        "be a bank, even if they're not on a list", self.smart).pack(fill="x", pady=(10, 2))
        check(adv.body, "Only answer devices on my home network (recommended)", self.local_only).pack(fill="x")

    def toggle(self):
        if self.shield and self.shield.running:
            self.stop()
        else:
            self.start()

    def start(self):
        try:
            port = int(self.port.get().strip())
            if not 0 <= port <= 65535:
                raise ValueError
        except ValueError:
            self.notify("The port must be a number from 0 to 65535")
            return
        host = self.host.get().strip() or "0.0.0.0"
        rules = blocklist.load_rules(smart=self.smart.get())
        self.shield = Shield(rules, host=host, port=port, local_only=self.local_only.get())
        try:
            self.shield.start()
        except OSError as exc:
            self.shield = None
            self.state_lbl.configure(text="\u2718  Couldn't start", fg=COLORS["red"])
            self.status.configure(text=f"Port {port} on {host} isn't available ({exc}). {_busy_port_hint()}",
                                  fg=COLORS["red"])
            return
        where = lan_ip() if host in ("0.0.0.0", "") else host
        self.state_lbl.configure(text="\u25cf  On", fg=COLORS["green"])
        self.status.configure(text=f"Answering devices that use {where} as their DNS server "
                                   f"(port {self.shield.port}). To protect your whole home, see "
                                   f"\"Protect every device\" below.", fg=COLORS["muted"])
        self.toggle_btn.configure(text="Stop DNS Shield")
        self._shown = 0
        self.after(1000, self._refresh)
        self.notify("DNS Shield is on")

    def stop(self):
        if self.shield:
            self.shield.stop()
        self.state_lbl.configure(text="\u25cb  Off", fg=COLORS["muted"])
        self.status.configure(text="Not answering any devices.", fg=COLORS["muted"])
        self.toggle_btn.configure(text="Start DNS Shield")
        self.notify("DNS Shield is off")

    def shutdown(self):
        if self.shield and self.shield.running:
            self.shield.stop()

    # ---------------------------------------------------------------- tester
    def _tester(self):
        p = self.add(Panel(self.content, "Check a website",
                           "Type a website address to see whether DNS Shield would block it, "
                           "and why. Works even while DNS Shield is off."))
        row = tk.Frame(p.body, bg=COLORS["panel"])
        row.pack(fill="x")
        self.test_entry = entry(row)
        self.test_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.test_entry.bind("<Return>", lambda _e: self.test_domain())
        button(row, "Check", self.test_domain, "primary").pack(side="left", padx=(10, 0))
        self.test_out = lab(p.body, "", wrap="auto")
        self.test_out.pack(fill="x", pady=(10, 0))

    def test_domain(self):
        name = self.test_entry.get().strip().lower().rstrip(".")
        for prefix in ("https://", "http://"):
            if name.startswith(prefix):
                name = name[len(prefix):]
        name = name.split("/")[0]
        if not name:
            return
        rules = self.shield.rules if self.shield else blocklist.load_rules(smart=self.smart.get())
        action, why = rules.decide(name)
        if action == "block":
            self.test_out.configure(text=f"\u2718  {name} would be blocked: {why}.", fg=COLORS["red"])
        elif action == "local":
            self.test_out.configure(text=f"\u25cf  {name} is a name on your home network: {why}.",
                                    fg=COLORS["cyan"])
        else:
            self.test_out.configure(text=f"\u2714  {name} would be allowed. Looking it up\u2026",
                                    fg=COLORS["green"])
            run_async(self, lambda: shared_resolver().resolve(name, dnswire.A),
                      lambda ans: self._show_lookup(name, why, ans))

    def _show_lookup(self, name, why, ans):
        ips = [rr.value for rr in ans.records if rr.rtype == dnswire.A]
        if ips:
            detail = "its address is " + ", ".join(ips)
        elif ans.rcode == dnswire.NXDOMAIN:
            detail = "but that website doesn't exist"
        else:
            detail = "but it has no address right now"
        extra = f" ({why})" if why else ""
        self.test_out.configure(text=f"\u2714  {name} would be allowed{extra}, and {detail}.",
                                fg=COLORS["green"])

    # ---------------------------------------------------------------- activity
    def _activity(self):
        p = self.add(Panel(self.content, "Activity", "Every lookup your devices made while DNS "
                           "Shield was on. It's kept in memory only and cleared when you close "
                           "the app."))
        self.stats_lbl = lab(p.body, "Turn DNS Shield on to see lookups here.", fg=COLORS["muted"])
        self.stats_lbl.pack(fill="x")
        self.top_lbl = muted(p.body, "")
        self.top_lbl.pack(fill="x", pady=(4, 8))
        cols = [("Time", 80), ("Device", 120), ("Website", 260), ("Type", 60), ("Result", 110), ("Why", 300)]
        self.log = ttk.Treeview(p.body, columns=[c for c, _w in cols], show="headings", height=10)
        for name, width in cols:
            self.log.heading(name, text=name, anchor="w")
            self.log.column(name, width=width, anchor="w", stretch=name in ("Website", "Why"))
        self.log.tag_configure("blocked", foreground=COLORS["red"])
        self.log.tag_configure("allowed", foreground=COLORS["text"])
        self.log.tag_configure("local", foreground=COLORS["cyan"])
        self.log.tag_configure("refused", foreground=COLORS["amber"])
        self.log.pack(fill="x")

    def _refresh(self):
        if not (self.shield and self.shield.running):
            return
        self.render_stats(self.shield.stats())
        self.after(1000, self._refresh)

    def render_stats(self, st):
        minutes = int(st["uptime"] // 60)
        self.stats_lbl.configure(
            text=f"{st['queries']} lookups   \u00b7   {st['blocked']} blocked "
                 f"({st['blocked_pct']:.0f}%)   \u00b7   {st['local']} answered here   \u00b7   "
                 f"on for {minutes} min", fg=COLORS["text"])
        if st["top_blocked"]:
            self.top_lbl.configure(text="Blocked most often: " + ", ".join(
                f"{name} ({count})" for name, count in st["top_blocked"][:5]))
        new = st["queries"] - self._shown
        if new > 0:
            for item in reversed(st["recent"][:min(new, 200)]):
                self.log.insert("", 0, tags=(item["action"],), values=(
                    time.strftime("%H:%M:%S", time.localtime(item["time"])), item["client"],
                    item["name"], item["type"], RESULT_NAMES.get(item["action"], item["action"]),
                    item["reason"]))
            for old in self.log.get_children()[200:]:
                self.log.delete(old)
            self._shown = st["queries"]

    # ---------------------------------------------------------------- setup
    def _setup_steps(self):
        p = self.add(Panel(self.content, "Protect every device in your home",
                           "Right now only devices you point at DNS Shield use it. To cover "
                           "everything at once, change one setting on your router."))
        steps(p.body, [
            "Run DNS Shield on a computer that stays on. This one works, or an always-on computer "
            "such as a Raspberry Pi, where \"cdm shield\" runs it without the window.",
            "Open your router's settings page. It's usually http://192.168.1.1 or "
            "http://192.168.0.1, and the password is often on a sticker on the router.",
            f"Find the DNS setting, usually under LAN or DHCP, and enter this computer's address: "
            f"{lan_ip()}. Leave the second DNS box empty, or devices will sometimes skip DNS "
            f"Shield. Also reserve that address for this computer (often called \"DHCP "
            f"reservation\" or \"static lease\") so the router never gives it a new one. Save.",
            "Turn Wi-Fi off and on again on a phone, then open a few websites on it. Its lookups "
            "appear under \"Activity\" above, and the ads are gone.",
        ]).pack(fill="x")
        note(p.body, "If DNS Shield stops or this computer turns off, devices on your network can't "
                     "open websites until it's back. To undo everything, set the router's DNS "
                     "setting back to automatic.", "amber").pack(fill="x", pady=(12, 0))

    # ---------------------------------------------------------------- rules
    def _rules(self):
        p = self.add(Panel(self.content, "Your own block and allow lists"))
        lists = Collapsible(p.body, "Edit the lists")
        lists.pack(fill="x")
        muted(lists.body, "One website per line. Blocking a website also blocks everything under "
                          "it, so blocking example.com blocks ads.example.com too. The allow list "
                          "wins over every block, including look-alike blocking.").pack(fill="x")
        cols = tk.Frame(lists.body, bg=COLORS["panel"])
        cols.pack(fill="x", pady=(10, 0))
        cols.columnconfigure(0, weight=1, uniform="lists")
        cols.columnconfigure(1, weight=1, uniform="lists")
        lab(cols, "Also block", fg=COLORS["muted"], font=FONTS["small_bold"]).grid(row=0, column=0, sticky="w")
        lab(cols, "Always allow", fg=COLORS["muted"], font=FONTS["small_bold"]).grid(row=0, column=1, sticky="w", padx=(12, 0))
        self.block_box = text_box(cols, height=6, mono=True)
        self.block_box.grid(row=1, column=0, sticky="nsew", pady=(4, 0))
        self.allow_box = text_box(cols, height=6, mono=True)
        self.allow_box.grid(row=1, column=1, sticky="nsew", padx=(12, 0), pady=(4, 0))
        block_text, allow_text = blocklist.read_user_lists()
        set_text(self.block_box, block_text)
        set_text(self.allow_box, allow_text)
        row = tk.Frame(lists.body, bg=COLORS["panel"])
        row.pack(fill="x", pady=(12, 0))
        button(row, "Save lists", self.save_rules, "primary").pack(side="left")
        self.rules_out = muted(row, "", wrap=None)
        self.rules_out.pack(side="left", padx=12)
        small(p.body, f"Cathodemon's own list blocks {len(blocklist.load_rules().builtin)} ad, "
                      f"tracker and telemetry domains. Your lists are saved on this computer in "
                      f"{blocklist.USER_BLOCK_PATH} and {blocklist.USER_ALLOW_PATH.name}.").pack(fill="x", pady=(10, 0))

    def save_rules(self):
        blocklist.save_user_lists(self.block_box.get("1.0", "end"), self.allow_box.get("1.0", "end"))
        rules = blocklist.load_rules(smart=self.smart.get())
        if self.shield:
            self.shield.rules = rules  # takes effect on the next lookup
        self.rules_out.configure(text=f"Saved: {len(rules.user_block)} blocked, {len(rules.allow)} allowed.")
        self.notify("Lists saved")
