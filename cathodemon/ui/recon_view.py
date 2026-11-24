"""Recon view: a plain-language safety report for a website address."""
from __future__ import annotations

import tkinter as tk

from ..core import reputation
from ..theme import COLORS, FONTS, band_color
from ..widgets import (Collapsible, Panel, ScoreGauge, button, chip, clear, entry, finding,
                       lab, muted, set_text, small, text_box)
from ..workers import run_async
from .base import BaseView, PADX

# Demo targets with no real company's trademark: example.com is reserved for
# documentation, and ".example" names can never be registered by anyone.
# Ebonmarsh is a made-up bank. The third sample swaps the "a" for a Cyrillic
# "\u0430" that looks identical (a homograph attack).
_SAMPLES = ["example.com", "ebonm4rsh.example", "ebonm\u0430rsh.example",
            "ebonmarsh-secure-login.example"]


def _pad(label, width):
    return (label + " " * width)[:width]


def _fmt_cert(c):
    if not c:
        return "no usable certificate on port 443"
    return "\n".join([f"{_pad('subject', 12)}: {c.get('subject') or '-'}",
                      f"{_pad('issuer', 12)}: {c.get('issuer') or '-'}",
                      f"{_pad('valid from', 12)}: {c.get('valid_from') or '-'}",
                      f"{_pad('valid to', 12)}: {c.get('valid_to') or '-'}",
                      f"{_pad('age', 12)}: {c.get('age_days')} days",
                      f"{_pad('expires in', 12)}: {c.get('days_until_expiry')} days",
                      f"{_pad('sha256', 12)}: {(c.get('fingerprint256') or '')[:47] or '-'}"])


def _fmt_dns(d):
    lines = []

    def lst(label, arr):
        if arr:
            joiner = "\n" + " " * 8
            lines.append(f"{_pad(label, 6)}: {joiner.join(arr)}")

    lst("A", [f"{r['address']}  (ttl {r['ttl']}s)" for r in d.get("A", [])])
    lst("AAAA", [r["address"] for r in d.get("AAAA", [])])
    lst("MX", [f"{r['priority']}  {r['exchange']}" for r in d.get("MX", [])])
    lst("NS", d.get("NS", []))
    lines.append(f"{_pad('SPF', 6)}: {d.get('SPF') or '- (none)'}")
    lines.append(f"{_pad('DMARC', 6)}: {d.get('DMARC') or '- (none)'}")
    lst("CAA", [f"{r['flags']} {r['tag']} {r['value']}" for r in d.get("CAA", [])])
    lst("TXT", d.get("TXT", []))
    return "\n".join(lines) or "no records resolved"


class ReconView(BaseView):
    def __init__(self, app, master):
        super().__init__(app, master)
        self.header("Recon", "Paste a website address before you trust it. Recon checks its "
                    "security certificate, its DNS settings, and whether its name is a "
                    "look-alike of a real brand, then explains what it found in plain words.",
                    tag="website safety report")

        form = self.add(Panel(self.content, "Check a website"))
        row = tk.Frame(form.body, bg=COLORS["panel"])
        row.pack(fill="x")
        self.target = entry(row)
        self.target.pack(side="left", fill="x", expand=True, ipady=6)
        self.target.bind("<Return>", lambda _e: self._scan())
        self.scan_btn = button(row, "Check", self._scan, "primary")
        self.scan_btn.pack(side="left", padx=(10, 0))
        chips = tk.Frame(form.body, bg=COLORS["panel"])
        chips.pack(fill="x", pady=(12, 0))
        small(chips, "Try one:", wrap=None).pack(side="left", padx=(0, 8))
        for s in _SAMPLES:
            chip(chips, s, lambda t=s: self._scan(t)).pack(side="left", padx=3)
        self.status = muted(form.body, "")
        self.status.pack(fill="x", pady=(10, 0))
        small(form.body, "Recon asks the internet's DNS servers and the website itself. It doesn't "
                         "save what you check.").pack(fill="x", pady=(6, 0))

        self.results = tk.Frame(self.content, bg=COLORS["bg"])
        gp = Panel(self.results)
        gp.pack(fill="x", pady=8)
        self.gauge = ScoreGauge(gp.body)
        self.gauge.pack(fill="x")
        self.headline = muted(gp.body, "")
        self.headline.pack(fill="x", pady=(10, 0))

        fp = Panel(self.results, "What Recon found")
        fp.pack(fill="x", pady=8)
        self.findings = tk.Frame(fp.body, bg=COLORS["panel"])
        self.findings.pack(fill="x")

        tech = Panel(self.results, "Technical details")
        tech.pack(fill="x", pady=8)
        more = Collapsible(tech.body, "Show the certificate and DNS records")
        more.pack(fill="x")
        lab(more.body, "Security certificate", fg=COLORS["muted"], font=FONTS["small_bold"]).pack(fill="x")
        self.cert = text_box(more.body, height=8, readonly=True, mono=True, wrap="none")
        self.cert.pack(fill="x", pady=(4, 12))
        lab(more.body, "DNS records", fg=COLORS["muted"], font=FONTS["small_bold"]).pack(fill="x")
        self.dns = text_box(more.body, height=10, readonly=True, mono=True, wrap="none")
        self.dns.pack(fill="x", pady=(4, 0))
        self.spacer()

    def _scan(self, target=None):
        target = target if isinstance(target, str) and target else self.target.get().strip()
        if not target:
            self.notify("Enter a domain or URL")
            return
        self.target.delete(0, "end")
        self.target.insert(0, target)
        self.scan_btn.configure(state="disabled")
        self.status.configure(text="Checking. Asking DNS servers and reading the certificate\u2026")
        run_async(self, lambda: reputation.build_report(target), self._render, self._error)

    def _error(self, msg):
        self.scan_btn.configure(state="normal")
        self.status.configure(text="")
        self.notify(msg)

    def _render(self, r):
        self.scan_btn.configure(state="normal")
        self.status.configure(text="")
        color = band_color(r["verdict"]["band"])
        self.gauge.set(r["score"], r["verdict"]["band"], r["verdict"]["blurb"], color)
        counts = r.get("counts", {})
        names = {"high": "serious", "medium": "worth a look", "low": "minor", "good": "good sign",
                 "info": "note"}
        parts = [f"{counts[s]} {names[s]}" for s in names if counts.get(s)]
        self.headline.configure(text=f"{r['target']}{r['path'] or ''}   \u00b7   " + ",  ".join(parts))

        clear(self.findings)
        if not r["findings"]:
            muted(self.findings, "Nothing worrying turned up.").pack(fill="x")
        for f in r["findings"]:
            finding(self.findings, f["severity"], f["title"], f["detail"],
                    source=f.get("source")).pack(fill="x", pady=3)

        set_text(self.cert, _fmt_cert(r["data"]["certificate"]))
        set_text(self.dns, _fmt_dns(r["data"]["dns"]))
        self.results.pack(fill="x", padx=PADX)
