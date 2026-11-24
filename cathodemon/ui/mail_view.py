"""Mail view: keys and contacts, write a locked message, read one, and a scam check."""
from __future__ import annotations

import re
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from ..core import phishing, securemsg
from ..theme import COLORS, FONTS, band_color
from ..widgets import (Collapsible, Panel, ScoreGauge, button, check, clear, entry, finding,
                       lab, muted, note, set_text, small, steps, text_box)
from ..workers import run_async
from .base import BaseView, EXAMPLES

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SIGN_LEVELS = {"valid": ("good", "\u2714 The signature is valid"),
                "invalid": ("high", "\u2718 The signature doesn't match"),
                "none": ("medium", "\u26a0 This message isn't signed"),
                "unverified": ("info", "\u2026 Signed, but not checked")}
TAB_KEYS, TAB_WRITE, TAB_READ, TAB_SCAM = 0, 1, 2, 3


def _combo(parent):
    c = ttk.Combobox(parent, state="readonly", font=FONTS["base"])
    c._map = {}
    return c


def _fill(combo, pairs, placeholder=None):
    labels = ([placeholder] if placeholder else []) + [p[0] for p in pairs]
    combo._map = {p[0]: p[1] for p in pairs}
    if placeholder:
        combo._map[placeholder] = None
    combo["values"] = labels
    combo.set(labels[0] if labels else "")


def _data(combo):
    return combo._map.get(combo.get())


def _label(rec, me=False):
    return f"{rec['name']} <{rec['email']}>" + ("  (me)" if me else "")


def _field(parent, label_text):
    label = lab(parent, label_text, fg=COLORS["muted"], font=FONTS["small_bold"])
    label.pack(fill="x", pady=(12, 4))
    return label


class MailView(BaseView):
    def __init__(self, app, master):
        super().__init__(app, master)
        self.keyring = securemsg.load_keyring()
        self.header("Mail", "Lock a message so only the person you choose can read it, sign it so "
                    "they know it really came from you, and check whether an email is a scam.",
                    tag="locked messages")
        self.nb = ttk.Notebook(self.content)
        self.add(self.nb)
        self.nb.add(self._keys_tab(), text="Keys")
        self.nb.add(self._write_tab(), text="Write")
        self.nb.add(self._read_tab(), text="Read")
        self.nb.add(self._scam_tab(), text="Scam check")
        self.spacer()
        self._refresh()

    def _tab(self):
        return tk.Frame(self.nb, bg=COLORS["bg"])

    def go_to_keys(self, focus=None):
        self.nb.select(TAB_KEYS)
        if focus is not None:
            focus.focus_set()

    # ============================================================ Keys
    def _keys_tab(self):
        tab = self._tab()
        how = Panel(tab, "How locked mail works")
        how.pack(fill="x", pady=(14, 8))
        steps(how.body, [
            "Create your identity once. It makes two keys: a public key you can give to anyone, "
            "and a private key that stays on this computer, locked with your passphrase.",
            "Swap public keys with the people you write to. Send them yours with \"Copy my public "
            "key\", and add theirs under \"Add someone's key\".",
            "In Write, choose who the message is for. Cathodemon locks it with their public key, "
            "so only their private key can open it. Paste the locked text into any email or chat.",
        ]).pack(fill="x")

        me = Panel(tab, "You")
        me.pack(fill="x", pady=8)
        self.identities_box = tk.Frame(me.body, bg=COLORS["panel"])
        self.identities_box.pack(fill="x")
        self.create = Collapsible(me.body, "Create an identity")
        self.create.pack(fill="x", pady=(10, 0))
        form = self.create.body
        _field(form, "Your name")
        self.g_name = entry(form)
        self.g_name.pack(fill="x", ipady=5)
        _field(form, "Your email")
        self.g_email = entry(form)
        self.g_email.pack(fill="x", ipady=5)
        _field(form, "Passphrase (protects your private key; pick a long one you'll remember)")
        self.g_pass = entry(form, show="\u2022")
        self.g_pass.pack(fill="x", ipady=5)
        _field(form, "Type the passphrase again")
        self.g_pass2 = entry(form, show="\u2022")
        self.g_pass2.pack(fill="x", ipady=5)
        self.g_btn = button(form, "Create my keys", self._generate, "primary")
        self.g_btn.pack(anchor="w", pady=(14, 0))
        self.g_status = muted(form, "")
        self.g_status.pack(fill="x", pady=(8, 0))

        add = Panel(tab, "Add someone's key",
                    "Ask the person to click \"Copy my public key\" in their Cathodemon and send "
                    "you the text. Paste it here. You can also paste a private key backup of your "
                    "own to restore it.")
        add.pack(fill="x", pady=8)
        self.imp_text = text_box(add.body, height=5, mono=True)
        self.imp_text.pack(fill="x")
        button(add.body, "Add key", self._import, "primary").pack(anchor="w", pady=(12, 0))
        self.imp_status = muted(add.body, "")
        self.imp_status.pack(fill="x", pady=(8, 0))

        people = Panel(tab, "People you can write to")
        people.pack(fill="x", pady=8)
        self.contacts_box = tk.Frame(people.body, bg=COLORS["panel"])
        self.contacts_box.pack(fill="x")
        small(tab, f"Saved on this computer in {securemsg.KEYRING_PATH}. Private keys are stored "
                   f"locked with your passphrase.").pack(fill="x", pady=(8, 4))
        return tab

    def _generate(self):
        name, email = self.g_name.get().strip(), self.g_email.get().strip()
        p1, p2 = self.g_pass.get(), self.g_pass2.get()
        if not name or not email:
            self.notify("Enter your name and email"); return
        if not _EMAIL_RE.match(email):
            self.notify("That email address doesn't look right"); return
        if len(p1) < 8:
            self.notify("Use a passphrase of at least 8 characters"); return
        if p1 != p2:
            self.notify("The two passphrases don't match"); return
        self.g_btn.configure(state="disabled")
        self.g_status.configure(text="Making your keys. This takes a few seconds\u2026")
        run_async(self, lambda: securemsg.generate_identity(name, email, p1),
                  self._gen_done, self._gen_err)

    def _gen_done(self, ident):
        self.g_btn.configure(state="normal")
        if any(i["fingerprint"] == ident["fingerprint"] for i in self.keyring["identities"]):
            self.g_status.configure(text="That identity already exists."); return
        self.keyring["identities"].append({k: ident[k] for k in
                                           ("fingerprint", "name", "email", "created", "public", "private")})
        securemsg.save_keyring(self.keyring)
        self.g_status.configure(text="\u2714 Your keys are ready. Back up your private key somewhere safe.")
        for f in (self.g_name, self.g_email, self.g_pass, self.g_pass2):
            f.delete(0, "end")
        self.notify("Identity created")
        self._refresh()

    def _gen_err(self, msg):
        self.g_btn.configure(state="normal")
        self.g_status.configure(text=f"Couldn't create the keys: {msg}")

    def _import(self):
        text = self.imp_text.get("1.0", "end").strip()
        if not text:
            self.notify("Paste a key first"); return
        try:
            meta = securemsg.key_meta(text)
        except Exception:  # noqa: BLE001 - any parse problem means "not a key"
            self.imp_status.configure(text="That isn't a Cathodemon key. Ask for the text that "
                                           "\"Copy my public key\" gives."); return
        if meta["is_private"]:
            if any(i["fingerprint"] == meta["fingerprint"] for i in self.keyring["identities"]):
                self.imp_status.configure(text="You already have that identity."); return
            self.keyring["identities"].append({"fingerprint": meta["fingerprint"], "name": meta["name"],
                "email": meta["email"], "created": meta["created"], "public": meta["public_armored"],
                "private": text})
            self.imp_status.configure(text=f"\u2714 Restored your identity, {meta['name']}.")
        else:
            if any(c["fingerprint"] == meta["fingerprint"] for c in self.keyring["contacts"]):
                self.imp_status.configure(text=f"{meta['name']} is already in your contacts."); return
            self.keyring["contacts"].append({"fingerprint": meta["fingerprint"], "name": meta["name"],
                "email": meta["email"], "public": text})
            self.imp_status.configure(text=f"\u2714 Added {meta['name']}. You can now write to them.")
        securemsg.save_keyring(self.keyring)
        set_text(self.imp_text, "")
        self.notify("Key added")
        self._refresh()

    def _person_card(self, parent, rec, is_identity):
        card = tk.Frame(parent, bg=COLORS["panel_hi"])
        inner = tk.Frame(card, bg=COLORS["panel_hi"])
        inner.pack(fill="x", padx=14, pady=10)
        lab(inner, f"{rec['name']}  <{rec['email']}>", font=FONTS["bold"], bg=COLORS["panel_hi"]).pack(fill="x")
        lab(inner, "Fingerprint  " + securemsg.format_fingerprint(rec["fingerprint"]),
            fg=COLORS["faint"], font=FONTS["mono_small"], bg=COLORS["panel_hi"]).pack(fill="x", pady=(2, 8))
        row = tk.Frame(inner, bg=COLORS["panel_hi"])
        row.pack(fill="x")
        button(row, "Copy my public key" if is_identity else "Copy their public key",
               lambda: self.copy(rec["public"])).pack(side="left")
        if is_identity:
            button(row, "Back up private key",
                   lambda: self._save(rec["private"], f"{rec['email']}-PRIVATE.asc")).pack(side="left", padx=8)
        button(row, "Remove", lambda: self._remove("identities" if is_identity else "contacts",
                                                   rec["fingerprint"]), "danger").pack(side="right")
        return card

    def _remove(self, bucket, fp):
        self.keyring[bucket] = [x for x in self.keyring[bucket] if x["fingerprint"] != fp]
        securemsg.save_keyring(self.keyring)
        self.notify("Removed")
        self._refresh()

    def _save(self, text, suggested):
        path = filedialog.asksaveasfilename(initialfile=suggested, defaultextension=".asc",
                                            filetypes=[("Key", "*.asc"), ("All", "*.*")])
        if path:
            try:
                Path(path).write_text(text, encoding="utf-8")
                self.notify(f"Saved {Path(path).name}")
            except OSError as e:
                self.notify(f"Couldn't save: {e}")

    # ============================================================ Write
    def _write_tab(self):
        tab = self._tab()
        p = Panel(tab, "Write a locked message")
        p.pack(fill="x", pady=(14, 8))
        self.need_identity = note(p.body, "Create your identity first, in Keys. You need it to "
                                          "sign what you send.", "amber")
        self.need_identity_btn = button(p.body, "Go to Keys", lambda: self.go_to_keys(self.g_name))
        self.from_label = _field(p.body, "From")
        self.c_from = _combo(p.body)
        self.c_from.pack(fill="x")
        _field(p.body, "To")
        self.c_to = _combo(p.body)
        self.c_to.pack(fill="x")
        self.to_hint = tk.Frame(p.body, bg=COLORS["panel"])
        note(self.to_hint, "You haven't added anyone yet, so the only person you can write to is "
                           "yourself. To write to someone, add their public key first.").pack(fill="x")
        button(self.to_hint, "Add someone's key", lambda: self.go_to_keys(self.imp_text)).pack(anchor="w", pady=(8, 0))
        self.to_hint.pack(fill="x", pady=(8, 0))
        self.c_signonly = tk.BooleanVar(value=False)
        check(p.body, "Sign only, don't lock (for messages anyone may read, like a public "
                      "announcement)", self.c_signonly, self._toggle_signonly).pack(fill="x", pady=(12, 0))
        _field(p.body, "Message")
        self.c_body = text_box(p.body, height=7)
        self.c_body.pack(fill="x")
        _field(p.body, "Your passphrase")
        self.c_pass = entry(p.body, show="\u2022")
        self.c_pass.pack(fill="x", ipady=5)
        row = tk.Frame(p.body, bg=COLORS["panel"])
        row.pack(fill="x", pady=(14, 0))
        self.c_btn = button(row, "Lock and sign", self._compose, "primary")
        self.c_btn.pack(side="left")
        button(row, "Clear", self._compose_clear, "ghost").pack(side="left", padx=8)

        self.c_outwrap = Panel(tab, "Done. Copy all of this into your email or chat")
        self.c_out = text_box(self.c_outwrap.body, height=10, readonly=True, mono=True)
        self.c_out.pack(fill="x")
        row = tk.Frame(self.c_outwrap.body, bg=COLORS["panel"])
        row.pack(fill="x", pady=(12, 0))
        button(row, "Copy", lambda: self.copy(self.c_out.get("1.0", "end").strip()), "primary").pack(side="left")
        button(row, "Save as file", lambda: self._save(self.c_out.get("1.0", "end").strip(),
                                                       "message.asc")).pack(side="left", padx=8)
        return tab

    def _toggle_signonly(self):
        locked = not self.c_signonly.get()
        self.c_to.configure(state="readonly" if locked else "disabled")
        self.c_btn.configure(text="Lock and sign" if locked else "Sign")

    def _compose_clear(self):
        set_text(self.c_body, "")
        self.c_pass.delete(0, "end")
        self.c_outwrap.pack_forget()

    def _compose(self):
        ident = self._by_fp(_data(self.c_from), "identities")
        if not ident:
            self.notify("Create your identity first, in Keys"); return
        body = self.c_body.get("1.0", "end").rstrip("\n")
        if not body.strip():
            self.notify("Write a message first"); return
        try:
            if self.c_signonly.get():
                out = securemsg.sign_only(ident, body, self.c_pass.get())
            else:
                recip = self._by_fp(_data(self.c_to))
                if not recip:
                    self.notify("Choose who the message is for"); return
                out = securemsg.encrypt_and_sign(ident, recip["public"], body, self.c_pass.get())
        except ValueError as e:
            self.notify(str(e)); return
        set_text(self.c_out, out)
        self.c_outwrap.pack(fill="x", pady=8)
        self.notify("Signed" if self.c_signonly.get() else "Locked and signed")

    # ============================================================ Read
    def _read_tab(self):
        tab = self._tab()
        p = Panel(tab, "Open a message", "Paste a locked or signed message you received.")
        p.pack(fill="x", pady=(14, 8))
        self.r_in = text_box(p.body, height=8, mono=True)
        self.r_in.pack(fill="x")
        _field(p.body, "Open it as")
        self.r_id = _combo(p.body)
        self.r_id.pack(fill="x")
        _field(p.body, "Who sent it? (to check the signature)")
        self.r_sender = _combo(p.body)
        self.r_sender.pack(fill="x")
        _field(p.body, "Your passphrase (only needed for locked messages)")
        self.r_pass = entry(p.body, show="\u2022")
        self.r_pass.pack(fill="x", ipady=5)
        button(p.body, "Open", self._read, "primary").pack(anchor="w", pady=(14, 0))

        self.r_outwrap = Panel(tab, "The message")
        self.r_verdict = tk.Frame(self.r_outwrap.body, bg=COLORS["panel"])
        self.r_verdict.pack(fill="x")
        self.r_out = text_box(self.r_outwrap.body, height=8, readonly=True)
        self.r_out.pack(fill="x", pady=(12, 0))
        return tab

    def _read(self):
        text = self.r_in.get("1.0", "end").strip()
        if not text:
            self.notify("Paste a message first"); return
        sender = self._by_fp(_data(self.r_sender)) if _data(self.r_sender) else None
        ident = self._by_fp(_data(self.r_id), "identities")
        if "CATHODEMON MESSAGE" in text and not ident:
            self.notify("Create or restore the identity this message was locked for"); return
        try:
            res = securemsg.decrypt_and_verify(
                text, ident or {}, self.r_pass.get(),
                sender["public"] if sender else None,
                {"name": sender["name"], "email": sender["email"]} if sender else None)
        except ValueError as e:
            self.notify(str(e)); return
        clear(self.r_verdict)
        sev, head = _SIGN_LEVELS[res["verdict"]["level"]]
        finding(self.r_verdict, sev, head, res["verdict"]["text"]).pack(fill="x")
        set_text(self.r_out, res["text"])
        self.r_outwrap.pack(fill="x", pady=8)
        self.notify("Message opened")

    # ============================================================ Scam check
    def _scam_tab(self):
        tab = self._tab()
        p = Panel(tab, "Is this email a scam?",
                  "Paste the whole email. For the best result include the headers: in most email "
                  "apps, choose \"Show original\" or \"View source\". The check runs on this "
                  "computer and nothing is sent anywhere.")
        p.pack(fill="x", pady=(14, 8))
        self.p_in = text_box(p.body, height=10, mono=True)
        self.p_in.pack(fill="x")
        row = tk.Frame(p.body, bg=COLORS["panel"])
        row.pack(fill="x", pady=(12, 0))
        button(row, "Check it", self._analyze, "primary").pack(side="left")
        button(row, "Try a sample scam", self._load_phish, "ghost").pack(side="left", padx=8)

        self.p_outwrap = Panel(tab, "Result")
        self.p_gauge = ScoreGauge(self.p_outwrap.body)
        self.p_gauge.pack(fill="x")
        self.p_meta = muted(self.p_outwrap.body, "")
        self.p_meta.pack(fill="x", pady=(12, 0))
        self.p_reasons = tk.Frame(self.p_outwrap.body, bg=COLORS["panel"])
        self.p_reasons.pack(fill="x", pady=(10, 0))
        return tab

    def _load_phish(self):
        try:
            set_text(self.p_in, (EXAMPLES / "sample-phish.eml").read_text(encoding="utf-8"))
        except OSError:
            self.notify("The sample file is missing")

    def _analyze(self):
        text = self.p_in.get("1.0", "end")
        if not text.strip():
            self.notify("Paste an email first"); return
        r = phishing.analyze_email(text)
        color = band_color(r["verdict"]["band"])
        self.p_gauge.set(r["score"], r["verdict"]["band"], r["verdict"]["blurb"], color)
        s = r["sender"]
        if s:
            sender_txt = f"From {s['display'] or ''} <{s['from'] or '?'}>"
            if s.get("reply_to"):
                sender_txt += f", replies go to {s['reply_to']}"
        else:
            sender_txt = "No headers found, so the sender couldn't be checked."
        self.p_meta.configure(text=f"{sender_txt}.  {r['stats']['link_count']} link(s), "
                                   f"{r['stats']['reason_count']} warning sign(s).")
        clear(self.p_reasons)
        if not r["reasons"]:
            finding(self.p_reasons, "good", "No common scam signs found",
                    "Still be careful with links and attachments you didn't expect.").pack(fill="x")
        for x in r["reasons"]:
            finding(self.p_reasons, x["severity"], x["title"], x["detail"], x.get("evidence")).pack(fill="x", pady=3)
        self.p_outwrap.pack(fill="x", pady=8)

    # ============================================================ shared
    def _by_fp(self, fp, bucket=None):
        if not fp:
            return None
        for b in ([bucket] if bucket else ["identities", "contacts"]):
            for rec in self.keyring[b]:
                if rec["fingerprint"] == fp:
                    return rec
        return None

    def _refresh(self):
        ids, contacts = self.keyring["identities"], self.keyring["contacts"]
        clear(self.identities_box)
        if not ids:
            muted(self.identities_box, "You haven't created your identity yet.").pack(fill="x")
        for rec in ids:
            self._person_card(self.identities_box, rec, True).pack(fill="x", pady=4)
        self.create.set_open(not ids)
        clear(self.contacts_box)
        if not contacts:
            muted(self.contacts_box, "Nobody yet. Add someone's key above to write to them.").pack(fill="x")
        for rec in contacts:
            self._person_card(self.contacts_box, rec, False).pack(fill="x", pady=4)

        my_pairs = [(_label(i), i["fingerprint"]) for i in ids]
        to_pairs = ([(_label(c), c["fingerprint"]) for c in contacts]
                    + [(_label(i, me=True), i["fingerprint"]) for i in ids])
        _fill(self.c_from, my_pairs)
        _fill(self.c_to, to_pairs)
        _fill(self.r_id, my_pairs)
        _fill(self.r_sender, to_pairs, "I don't know, skip the check")

        if ids:
            self.need_identity.pack_forget()
            self.need_identity_btn.pack_forget()
        else:
            self.need_identity.pack(fill="x", before=self.from_label)
            self.need_identity_btn.pack(anchor="w", pady=(8, 0), before=self.from_label)
        if contacts:
            self.to_hint.pack_forget()
        else:
            self.to_hint.pack(fill="x", pady=(8, 0), after=self.c_to)
