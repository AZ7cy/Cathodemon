"""Vault view: password strength, offline leak check, passphrases and a habits check.

Nothing on this page is written to disk or sent anywhere. Passwords and quiz
answers live only in this window's memory.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..core import leaks, passwords
from ..theme import COLORS, FONTS
from ..widgets import (Meter, Panel, button, check, clear, entry, h2, lab, muted, note,
                       set_text, small, text_box)
from .base import BaseView

_STRENGTH_COLOR = [COLORS["red"], COLORS["red"], COLORS["amber"], COLORS["green"], COLORS["green_bright"]]
_SEPARATORS = {"hyphen  -": "-", "dot  .": ".", "underscore  _": "_"}
_LEAK_LOOK = {"leaked": ("\u2718", "red"), "pattern": ("\u26a0", "amber"), "clear": ("\u2714", "green")}

QUIZ = [
    {"question": "Do you use the same password on more than one site?",
     "topic": "Use a different password for every site",
     "options": [("Yes, the same few everywhere", 0), ("Some, for less important sites", 1),
                 ("No, every site has its own", 2)],
     "lesson": "When one site leaks your password, attackers try it on your email, bank and "
               "shopping accounts within hours. A different password everywhere means one leak "
               "can't open everything."},
    {"question": "Do you use a password manager?",
     "topic": "Use a password manager",
     "options": [("No, I remember them or write them down", 0), ("Yes, for most accounts", 2)],
     "lesson": "A password manager makes and remembers a long, different password for every site. "
               "It only fills them in on the real site, so it also protects you from fake login "
               "pages."},
    {"question": "Is two-step sign-in (a code or a security key) on for your important accounts?",
     "topic": "Turn on two-step sign-in",
     "options": [("No", 0), ("On a few accounts", 1), ("On all my important accounts", 2)],
     "lesson": "With two-step sign-in, a stolen password alone isn't enough to get in. Start with "
               "your email, your bank and your password manager. An authenticator app or a "
               "security key is safer than a text message."},
    {"question": "How long are your passwords, usually?",
     "topic": "Make passwords longer",
     "options": [("Under 8 characters", 0), ("8 to 11 characters", 1), ("12 or more", 2)],
     "lesson": "A computer can guess a short password in hours. Length matters most: four or five "
               "random words beat a short password full of symbols, and they're easier to "
               "remember. Try the passphrase maker above."},
    {"question": "Do your passwords include personal details, such as names, birthdays or pets?",
     "topic": "Keep personal details out of passwords",
     "options": [("Yes, so I can remember them", 0), ("No", 2)],
     "lesson": "Names, birthdays and pets are easy to find on social media, and attackers try them "
               "first. Use random words that have nothing to do with you."},
    {"question": "When do you change a password?",
     "topic": "Change a password when it may have leaked",
     "options": [("On a schedule, such as every 90 days", 1), ("When I think it may have leaked", 2),
                 ("Never", 0)],
     "lesson": "Changing passwords on a schedule makes people pick predictable ones, like "
               "Summer2024 and then Autumn2024. Instead, change a password straight away when a "
               "site you use reports a leak, or if you think someone saw it."},
]


def grade(pct):
    if pct >= 80:
        return "solid habits", COLORS["green"]
    if pct >= 50:
        return "room to improve", COLORS["amber"]
    return "at risk", COLORS["red"]


class VaultView(BaseView):
    def __init__(self, app, master):
        super().__init__(app, master)
        self.header("Vault", "Check how strong a password is, make a strong passphrase, and find "
                    "the weak spots in your password habits.", tag="passwords")
        self.add(note(self.content, "Nothing on this page is saved or sent anywhere. What you type "
                      "and the answers you give stay in this window, and they're gone when you "
                      "close the app.", "green"))
        self._build_strength()
        self._build_passphrase()
        self._build_habits()
        self.spacer()

    # ------------------------------------------------------------ password test
    def _build_strength(self):
        p = self.add(Panel(self.content, "Test a password",
                           "Type a password to see how long it would take to crack and whether "
                           "it's one that attackers try first."))
        row = tk.Frame(p.body, bg=COLORS["panel"])
        row.pack(fill="x")
        self.pw = entry(row, show="\u2022")
        self.pw.configure(font=FONTS["mono_big"])
        self.pw.pack(side="left", fill="x", expand=True, ipady=6)
        self.pw.bind("<KeyRelease>", lambda _e: self.assess())
        self._shown = False
        self.show_btn = button(row, "Show", self._toggle_show)
        self.show_btn.pack(side="left", padx=(10, 0))
        self.meter = Meter(p.body)
        self.meter.pack(fill="x", pady=(14, 10))
        self.verdict = lab(p.body, "Start typing to see the result.", fg=COLORS["muted"],
                           font=FONTS["h2"])
        self.verdict.pack(fill="x")
        self.times = muted(p.body, "")
        self.times.pack(fill="x", pady=(4, 0))
        self.feedback = tk.Frame(p.body, bg=COLORS["panel"])
        self.feedback.pack(fill="x", pady=(8, 0))
        self.leak_out = lab(p.body, "", wrap="auto")
        self.leak_out.pack(fill="x", pady=(8, 0))

    def _toggle_show(self):
        self._shown = not self._shown
        self.pw.configure(show="" if self._shown else "\u2022")
        self.show_btn.configure(text="Hide" if self._shown else "Show")

    def assess(self):
        pw = self.pw.get()
        clear(self.feedback)
        if not pw:
            self.meter.set(0, COLORS["green"])
            self.verdict.configure(text="Start typing to see the result.", fg=COLORS["muted"])
            self.times.configure(text="")
            self.leak_out.configure(text="")
            return
        r = passwords.estimate_strength(pw)
        color = _STRENGTH_COLOR[r["score"]]
        self.meter.set((r["score"] + 1) / 5.0, color)
        self.verdict.configure(text=r["label"].capitalize(), fg=color)
        offline = ("could crack it instantly" if r["offline"] == "instantly"
                   else f"would need {r['offline']} to crack it")
        online = "would work at once" if r["online"] == "instantly" else f"would take {r['online']}"
        self.times.configure(text=f"A powerful computer {offline}. Guessing on a website's "
                                  f"sign-in page {online}.")
        tips = ([("\u26a0", COLORS["amber"], r["warning"])] if r["warning"] else []) + \
               [("\u2022", COLORS["muted"], s) for s in r["suggestions"]]
        for icon, color_, text in tips:
            line = tk.Frame(self.feedback, bg=COLORS["panel"])
            line.pack(fill="x", pady=1)
            lab(line, icon, fg=color_).pack(side="left", anchor="n", padx=(0, 8))
            lab(line, text, fg=COLORS["muted"], wrap="auto").pack(side="left", fill="x", expand=True)
        self.show_leak(leaks.check(pw))

    def show_leak(self, result):
        icon, color_key = _LEAK_LOOK[result["status"]]
        self.leak_out.configure(text=f"{icon}  {result['title']}. {result['detail']}",
                                fg=COLORS[color_key])

    # ------------------------------------------------------------ passphrase
    def _build_passphrase(self):
        p = self.add(Panel(self.content, "Make a passphrase",
                           "Random made-up words are easy to remember and very hard to crack. "
                           "Each word is built from random letters picked by your computer's "
                           "secure random number generator."))
        self.passout = text_box(p.body, height=1, readonly=True, mono=True, wrap="none")
        self.passout.configure(font=FONTS["mono_big"], pady=12)
        self.passout.pack(fill="x")
        self.entropy = muted(p.body, "")
        self.entropy.pack(fill="x", pady=(8, 12))
        opts = tk.Frame(p.body, bg=COLORS["panel"])
        opts.pack(fill="x")
        lab(opts, "Words").pack(side="left")
        self.words = ttk.Combobox(opts, state="readonly", values=[str(n) for n in range(3, 13)],
                                  width=4, font=FONTS["base"])
        self.words.set("5")
        self.words.bind("<<ComboboxSelected>>", lambda _e: self.generate())
        self.words.pack(side="left", padx=(8, 20))
        lab(opts, "Between words").pack(side="left")
        self.sep = ttk.Combobox(opts, state="readonly", values=list(_SEPARATORS), width=13,
                                font=FONTS["base"])
        self.sep.set("hyphen  -")
        self.sep.bind("<<ComboboxSelected>>", lambda _e: self.generate())
        self.sep.pack(side="left", padx=(8, 20))
        self.cap = tk.BooleanVar(value=True)
        self.num = tk.BooleanVar(value=False)
        check(opts, "Capital letters", self.cap, self.generate).pack(side="left", padx=(0, 14))
        check(opts, "Add a number", self.num, self.generate).pack(side="left")
        btns = tk.Frame(p.body, bg=COLORS["panel"])
        btns.pack(fill="x", pady=(14, 0))
        button(btns, "New passphrase", self.generate, "primary").pack(side="left")
        button(btns, "Copy", lambda: self.copy(self.passout.get("1.0", "end").strip())).pack(side="left", padx=10)
        self.generate()

    def generate(self, *_):
        phrase, bits = passwords.generate_passphrase(
            int(self.words.get()), _SEPARATORS[self.sep.get()], self.cap.get(), self.num.get())
        set_text(self.passout, phrase)
        est = passwords.crack_estimates(bits)
        self.entropy.configure(text=f"About {bits:.0f} bits of randomness. A fast computer would "
                                    f"need {est['fast']} on average to guess it.")

    # ------------------------------------------------------------ habits check
    def _build_habits(self):
        p = self.add(Panel(self.content, "Password habits check",
                           "Six quick questions about how you handle passwords. You get a score "
                           "and a short list of what to fix."))
        self.quiz_area = tk.Frame(p.body, bg=COLORS["panel"])
        self.quiz_area.pack(fill="x")
        self.answers = [None] * len(QUIZ)
        self.q_index = 0
        self.show_start()

    def show_start(self):
        clear(self.quiz_area)
        self.answers = [None] * len(QUIZ)
        self.q_index = 0
        button(self.quiz_area, "Start the check", lambda: self.show_question(0), "primary").pack(anchor="w")
        small(self.quiz_area, "Takes about a minute. Your answers aren't saved.").pack(fill="x", pady=(8, 0))

    def show_question(self, index):
        clear(self.quiz_area)
        self.q_index = index
        item = QUIZ[index]
        top = tk.Frame(self.quiz_area, bg=COLORS["panel"])
        top.pack(fill="x")
        lab(top, f"Question {index + 1} of {len(QUIZ)}", fg=COLORS["green"], font=FONTS["tag"]).pack(side="left")
        bar = Meter(self.quiz_area, height=4)
        bar.pack(fill="x", pady=(8, 14))
        bar.set(index / len(QUIZ), COLORS["green"])
        h2(self.quiz_area, item["question"]).pack(fill="x", pady=(0, 12))
        for i, (label, _value) in enumerate(item["options"]):
            b = button(self.quiz_area, label, lambda i=i: self.choose(i))
            b.configure(anchor="w", padx=18, pady=10, font=FONTS["base"])
            if self.answers[index] == i:
                b.configure(highlightbackground=COLORS["green"])
            b.pack(fill="x", pady=3)
        if index > 0:
            button(self.quiz_area, "\u2190 Back", lambda: self.show_question(index - 1), "ghost").pack(anchor="w", pady=(10, 0))

    def choose(self, option_index):
        """Answer the current question and move on."""
        self.answers[self.q_index] = option_index
        if self.q_index + 1 < len(QUIZ):
            self.show_question(self.q_index + 1)
        else:
            self.show_result()

    def score(self):
        got = sum(QUIZ[i]["options"][a][1] for i, a in enumerate(self.answers))
        best = sum(max(v for _l, v in q["options"]) for q in QUIZ)
        return round(got / best * 100)

    def show_result(self):
        clear(self.quiz_area)
        pct = self.score()
        label, color = grade(pct)
        top = tk.Frame(self.quiz_area, bg=COLORS["panel"])
        top.pack(fill="x")
        self.result_score = lab(top, str(pct), fg=color, font=FONTS["score"])
        self.result_score.pack(side="left", padx=(0, 16))
        col = tk.Frame(top, bg=COLORS["panel"])
        col.pack(side="left", fill="x", expand=True)
        lab(col, label.capitalize(), fg=color, font=FONTS["band"]).pack(fill="x")
        muted(col, "out of 100 for your password habits").pack(fill="x")
        meter = Meter(self.quiz_area)
        meter.pack(fill="x", pady=(10, 16))
        meter.set(pct / 100, color)

        weak = [q for q, a in zip(QUIZ, self.answers) if q["options"][a][1] < max(v for _l, v in q["options"])]
        strong = [q for q in QUIZ if q not in weak]
        if weak:
            lab(self.quiz_area, "What to fix", fg=COLORS["text"], font=FONTS["title"]).pack(fill="x", pady=(0, 6))
            for n, q in enumerate(weak, 1):
                card = tk.Frame(self.quiz_area, bg=COLORS["panel_hi"])
                card.pack(fill="x", pady=4)
                tk.Frame(card, bg=COLORS["amber"], width=4).pack(side="left", fill="y")
                inner = tk.Frame(card, bg=COLORS["panel_hi"])
                inner.pack(side="left", fill="x", expand=True, padx=14, pady=10)
                lab(inner, f"{n}. {q['topic']}", font=FONTS["bold"], bg=COLORS["panel_hi"], wrap="auto").pack(fill="x")
                lab(inner, q["lesson"], fg=COLORS["muted"], bg=COLORS["panel_hi"], wrap="auto").pack(fill="x", pady=(3, 0))
        if strong:
            lab(self.quiz_area, "Already doing well", fg=COLORS["text"], font=FONTS["title"]).pack(fill="x", pady=(14, 4))
            for q in strong:
                lab(self.quiz_area, "\u2714  " + q["topic"], fg=COLORS["green"], wrap="auto").pack(fill="x", pady=1)
        self.weak_topics = [q["topic"] for q in weak]
        button(self.quiz_area, "Start again", self.show_start).pack(anchor="w", pady=(16, 0))
        small(self.quiz_area, "These answers weren't saved anywhere.").pack(fill="x", pady=(8, 0))
