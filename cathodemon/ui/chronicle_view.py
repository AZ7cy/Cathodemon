"""Chronicle view: turn raw logs into a plain story of what happened."""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from ..core import logstory
from ..theme import COLORS, FONTS
from ..widgets import (Collapsible, Panel, button, clear, finding, lab, muted, note, set_text,
                       steps, text_box)
from .base import BaseView, EXAMPLES

# Friendlier names for the log sources and outcomes Chronicle understands.
SOURCE_NAMES = {"ssh": "sign-in (SSH)", "sudo": "admin command", "auth": "sign-in session",
                "web": "website", "firewall": "firewall", "syslog": "system"}
OUTCOME_NAMES = {"success": "succeeded", "failure": "failed", "blocked": "blocked", "info": "info"}
_OUTCOME_COLOR = {"success": COLORS["green"], "failure": COLORS["amber"],
                  "blocked": COLORS["yellow"], "info": COLORS["muted"]}


def _stat(parent, value, label):
    box = tk.Frame(parent, bg=COLORS["panel_hi"])
    value_lbl = lab(box, value, fg=COLORS["green"], font=FONTS["h2"], bg=COLORS["panel_hi"])
    value_lbl.pack(fill="x", padx=14, pady=(10, 0))
    lab(box, label, fg=COLORS["muted"], font=FONTS["small"], bg=COLORS["panel_hi"]).pack(fill="x", padx=14, pady=(0, 10))
    return box, value_lbl


class ChronicleView(BaseView):
    def __init__(self, app, master):
        super().__init__(app, master)
        self.last = None
        self.header("Chronicle", "Computers keep logs: one line of text for every sign-in, website "
                    "request or blocked connection. Chronicle reads those lines and tells you in "
                    "plain words who tried to get in, what they did and when.",
                    tag="logs into a story")

        how = self.add(Panel(self.content, "How to use it"))
        steps(how.body, [
            "Click \"Try the sample\" to see a made-up break-in, or paste your own logs below, or "
            "open a log file.",
            "Click \"Build the story\".",
            "Read \"What happened\" first. \"Suspicious activity\" explains each attack, and "
            "\"Every event\" lists each log line in time order.",
        ]).pack(fill="x")
        where = Collapsible(how.body, "Where do I find logs?")
        where.pack(fill="x", pady=(12, 0))
        for line in [
            "Linux computers, servers and Raspberry Pis keep sign-ins in /var/log/auth.log, website "
            "visits in /var/log/nginx/access.log or /var/log/apache2/access.log, and firewall "
            "blocks in /var/log/ufw.log.",
            "Many routers and network storage boxes (NAS) can download their logs from their "
            "settings page.",
            "Chronicle understands SSH sign-ins, sudo admin commands, Nginx and Apache website "
            "logs, and iptables or UFW firewall logs. Windows Event Viewer logs aren't supported.",
        ]:
            muted(where.body, "\u2022  " + line).pack(fill="x", pady=2)

        inp = self.add(Panel(self.content, "Logs"))
        self.logs = text_box(inp.body, height=10, mono=True, wrap="none")
        self.logs.pack(fill="x")
        row = tk.Frame(inp.body, bg=COLORS["panel"])
        row.pack(fill="x", pady=(12, 0))
        button(row, "Build the story", self._run, "primary").pack(side="left")
        button(row, "Try the sample", self._load_sample).pack(side="left", padx=8)
        button(row, "Open a log file", self._load_file).pack(side="left")
        button(row, "Clear", self._clear, "ghost").pack(side="left", padx=8)
        note(inp.body, "Logs you paste stay on this computer. Nothing is saved unless you click "
                       "\"Export report\".", "green").pack(fill="x", pady=(12, 0))

        self.results = tk.Frame(self.content, bg=COLORS["bg"])
        stats = tk.Frame(self.results, bg=COLORS["bg"])
        stats.pack(fill="x", pady=8)
        for col in range(4):
            stats.columnconfigure(col, weight=1, uniform="stat")
        boxes = [_stat(stats, "\u2014", label) for label in
                 ("log lines read", "suspicious activities", "people or addresses", "time span")]
        for col, (box, _v) in enumerate(boxes):
            box.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 0))
        self.stat_lines, self.stat_incidents, self.stat_actors, self.stat_span = (v for _b, v in boxes)

        sp = Panel(self.results, "What happened")
        sp.pack(fill="x", pady=8)
        self.story = text_box(sp.body, height=9, readonly=True)
        self.story.pack(fill="x")
        self.story.bind("<Configure>", lambda _e: self._fit_story())
        row = tk.Frame(sp.body, bg=COLORS["panel"])
        row.pack(fill="x", pady=(12, 0))
        button(row, "Copy the story", lambda: self.copy(self.story.get("1.0", "end").strip())).pack(side="left")
        button(row, "Export report", self._export).pack(side="left", padx=8)

        ip = Panel(self.results, "Suspicious activity")
        ip.pack(fill="x", pady=8)
        self.incidents = tk.Frame(ip.body, bg=COLORS["panel"])
        self.incidents.pack(fill="x")

        ap = Panel(self.results, "Who was involved",
                   "Each IP address or user name that shows up in the logs.")
        ap.pack(fill="x", pady=8)
        self.actors = self._tree(ap.body, [("Who", 170), ("Events", 70), ("Failed or blocked", 130),
                                           ("Succeeded", 90), ("Seen in", 260)], height=6)

        tp = Panel(self.results, "Every event", "Each log line Chronicle understood, oldest first.")
        tp.pack(fill="x", pady=8)
        self.timeline = self._tree(tp.body, [("Time", 150), ("Type", 120), ("Who", 140),
                                             ("What happened", 380), ("Result", 90)], height=14)
        for outcome, color in _OUTCOME_COLOR.items():
            self.timeline.tag_configure(outcome, foreground=color)
        self.spacer()

    def _fit_story(self):
        """Make the story box tall enough for the whole story at its current
        width, so it never hides text behind a second scroll bar."""
        if self.story.winfo_width() < 50:  # not laid out yet; <Configure> calls again
            return
        n = self.story.count("1.0", "end", "update", "displaylines")
        n = n[0] if isinstance(n, tuple) else n
        if n and int(self.story.cget("height")) != n:
            self.story.configure(height=n)

    def _tree(self, parent, columns, height):
        names = [c for c, _w in columns]
        tree = ttk.Treeview(parent, columns=names, show="headings", height=height)
        for name, width in columns:
            tree.heading(name, text=name, anchor="w")
            tree.column(name, width=width, anchor="w", stretch=name in ("What happened", "Seen in"))
        tree.pack(fill="x")
        return tree

    # ------------------------------------------------------------------ input
    def _load_file(self):
        path = filedialog.askopenfilename(title="Open a log file",
                                          filetypes=[("Logs", "*.log *.txt"), ("All files", "*.*")])
        if path:
            try:
                set_text(self.logs, Path(path).read_text(encoding="utf-8", errors="replace"))
                self.notify(f"Opened {Path(path).name}")
            except OSError as e:
                self.notify(f"Couldn't read the file: {e}")

    def _load_sample(self):
        try:
            set_text(self.logs, (EXAMPLES / "sample-incident.log").read_text(encoding="utf-8"))
            self._run()
        except OSError:
            self.notify("The sample file is missing")

    def _clear(self):
        set_text(self.logs, "")
        self.results.pack_forget()
        self.last = None

    def _run(self):
        text = self.logs.get("1.0", "end")
        if not text.strip():
            self.notify("Paste some logs first, or click \"Try the sample\"")
            return
        r = logstory.analyze_logs(text)
        self.last = r
        if not r["summary"]["parsed"]:
            self.notify("Chronicle didn't recognise any of these lines as logs")
            return
        self._render(r)

    # ------------------------------------------------------------------ output
    def _render(self, r):
        s = r["summary"]
        self.stat_lines.configure(text=f"{s['parsed']} of {s['total_lines']}")
        self.stat_incidents.configure(text=str(len(r["incidents"])),
                                      fg=COLORS["red"] if r["incidents"] else COLORS["green"])
        self.stat_actors.configure(text=str(len(r["actors"])))
        start, end = s["time_range"]["start"], s["time_range"]["end"]
        span = logstory.duration(end - start) if start and end else "unknown"
        self.stat_span.configure(text=span)
        set_text(self.story, r["story"])
        self._fit_story()

        tz = s.get("zone")  # the logs' own time zone, so times match the pasted lines
        clear(self.incidents)
        if not r["incidents"]:
            muted(self.incidents, "Nothing suspicious stood out.").pack(fill="x")
        for inc in r["incidents"]:
            when = logstory.fmt(inc["when"], tz) if inc.get("when") else None
            finding(self.incidents, inc["severity"], inc["title"], inc["narrative"],
                    source=when).pack(fill="x", pady=3)

        for tree in (self.actors, self.timeline):
            tree.delete(*tree.get_children())
        for a in r["actors"]:
            seen = ", ".join(SOURCE_NAMES.get(src, src) for src in a["sources"])
            self.actors.insert("", "end", values=(a["id"], a["events"], a["failures"], a["successes"], seen))
        self.timeline.heading("Time", text=f"Time ({tz})" if tz else "Time")
        for ev in r["timeline"][:500]:
            outcome = ev.get("outcome", "info")
            self.timeline.insert("", "end", tags=(outcome,), values=(
                logstory.fmt(ev.get("ts"), tz), SOURCE_NAMES.get(ev["source"], ev["source"]),
                ev.get("ip") or ev.get("user") or "-", ev.get("action", ""),
                OUTCOME_NAMES.get(outcome, outcome)))
        self.results.pack(fill="x", padx=32)

    def _export(self):
        if not self.last:
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            initialfile="cathodemon-incident-report.txt",
                                            filetypes=[("Text", "*.txt")])
        if not path:
            return
        try:
            Path(path).write_text(self._report_text(self.last), encoding="utf-8")
            self.notify(f"Saved {Path(path).name}")
        except OSError as e:
            self.notify(f"Couldn't save: {e}")

    def _report_text(self, r):
        lines = ["CATHODEMON - INCIDENT REPORT", "=" * 60, "", "SUMMARY"]
        s = r["summary"]
        tz = s.get("zone")
        lines.append(f"  Lines read   : {s['parsed']} of {s['total_lines']} ({s['unparsed']} not recognised)")
        rng = (f"{logstory.fmt(s['time_range']['start'], tz)} -> {logstory.fmt(s['time_range']['end'], tz)}"
               f"{' ' + str(tz) if tz else ''}" if s["time_range"]["start"] else "n/a")
        lines.append(f"  Time window  : {rng}")
        lines.append("  Sources      : " + ", ".join(f"{SOURCE_NAMES.get(k, k)} ({v})"
                                                     for k, v in s["by_source"].items()))
        lines += ["", "WHAT HAPPENED", "", r["story"], "", "SUSPICIOUS ACTIVITY", ""]
        if not r["incidents"]:
            lines.append("  (nothing suspicious stood out)")
        for n, i in enumerate(r["incidents"], 1):
            when = f" @ {logstory.fmt(i['when'], tz)}" if i.get("when") else ""
            lines.append(f"  {n}. [{i['severity'].upper()}] {i['title']}{when}")
            lines.append(f"     {i['narrative']}")
        lines += ["", "EVERY EVENT", ""]
        for ev in r["timeline"]:
            lines.append(f"  {logstory.fmt(ev.get('ts'), tz):<20} {SOURCE_NAMES.get(ev['source'], ev['source']):<16} "
                         f"{(ev.get('ip') or ev.get('user') or '-'):<16} "
                         f"{OUTCOME_NAMES.get(ev.get('outcome', ''), ''):<10} {ev.get('action', '')}")
        return "\n".join(lines)
