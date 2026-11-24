"""Password hygiene: an original strength estimator + passphrase generator.

The strength model is a transparent entropy estimate (character pool x length)
discounted for the predictable patterns attackers try first - common passwords,
sequences, repeats, dates, keyboard runs. The passphrase generator builds
pronounceable words from random letters with a CSPRNG, so there is no wordlist
to license. Standard library only.
"""
from __future__ import annotations

import math
import re
import secrets

from . import leaks
from .leaks import LEAKED as COMMON  # one shared list of commonly leaked passwords

STRENGTH_LABELS = ["very weak", "weak", "fair", "strong", "very strong"]
_KEYBOARD = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
_SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789"] + _KEYBOARD


def _pool_size(pw: str) -> int:
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"[0-9]", pw):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", pw):
        pool += 33
    return pool or 1


def _has_run(pw: str) -> bool:
    low = pw.lower()
    for seq in _SEQUENCES:
        for i in range(len(seq) - 2):
            tri = seq[i:i + 3]
            if tri in low or tri[::-1] in low:
                return True
    return False


def estimate_strength(password: str) -> dict:
    if not password:
        return {"score": 0, "label": "", "offline": "", "online": "", "warning": "", "suggestions": []}
    low = password.lower()
    pool = _pool_size(password)
    entropy = len(password) * math.log2(pool)
    warning = ""
    suggestions: list[str] = []

    if low in COMMON:
        entropy = min(entropy, 8.0)
        warning = "This is one of the most common passwords in the world."
    stripped = re.sub(r"\d+$", "", low)
    if not warning and stripped in COMMON and stripped != low:
        entropy = min(entropy, 14.0)
        warning = "This is a common word with digits tacked on - attackers try that first."
    # Cracking tools try the leak check's patterns (a common word plus digits and
    # a symbol, dates, keyboard runs) right after the plain list, so a password
    # it flags is never rated strong, however long it is ("Summer2024!" is weak).
    leak = leaks.check(password)["status"]
    if leak == "leaked":
        entropy = min(entropy, 8.0)
    elif leak == "pattern":
        entropy = min(entropy, 30.0)

    if re.search(r"(.)\1\1", password):
        entropy *= 0.72
        suggestions.append("Avoid characters repeated three or more times.")
    if _has_run(password):
        entropy *= 0.7
        suggestions.append("Avoid sequences and keyboard runs like 'abc', '123' or 'qwerty'.")
    if password.isdigit():
        entropy = min(entropy, len(password) * math.log2(10))
        if len(password) <= 8:
            warning = warning or "All-numeric and short - cracked almost instantly."
    if re.search(r"(19|20)\d\d", password):
        suggestions.append("Avoid years and dates - they add very little strength.")
    if len(password) < 12:
        suggestions.append("Use at least 12-16 characters, or a passphrase of several words.")
    if pool < 36:
        suggestions.append("Mix in upper/lower case, numbers and symbols (or just make it longer).")

    entropy = max(0.0, entropy)
    score = (0 if entropy < 28 else 1 if entropy < 40 else 2 if entropy < 60
             else 3 if entropy < 90 else 4)
    guesses_half = 2 ** max(0.0, entropy - 1)
    return {
        "score": score,
        "label": STRENGTH_LABELS[score],
        "offline": format_duration(guesses_half / 1e10),   # 10 billion guesses/sec
        "online": format_duration(guesses_half / 10.0),    # 10 guesses/sec (throttled)
        "warning": warning,
        "suggestions": suggestions,
    }


# ------------------------------------------------------------ passphrases
_CONS = "bcdfghjklmnpqrstvwxyz"
_VOWELS = "aeiou"
_BITS_PER_WORD = 3 * math.log2(len(_CONS)) + 2 * math.log2(len(_VOWELS))  # CVCVC pattern


def _word() -> str:
    c = secrets.choice
    return c(_CONS) + c(_VOWELS) + c(_CONS) + c(_VOWELS) + c(_CONS)


def generate_passphrase(words: int = 5, sep: str = "-", capitalize: bool = True,
                        add_number: bool = False) -> tuple[str, float]:
    words = max(3, min(12, int(words)))
    chosen = [_word() for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = sep.join(chosen)
    bits = words * _BITS_PER_WORD
    if add_number:
        phrase += sep + str(secrets.randbelow(10000))
        bits += math.log2(10000)
    return phrase, bits


# ------------------------------------------------------------ helpers
def format_duration(seconds: float) -> str:
    if seconds == float("inf"):
        return "longer than the age of the universe"
    if seconds < 1:
        return "instantly"
    units = [("second", 1), ("minute", 60), ("hour", 3600), ("day", 86400),
             ("month", 2629800), ("year", 31557600)]
    for name, size in reversed(units):
        if seconds >= size:
            v = seconds / size
            if name == "year" and v >= 1000:
                if v >= 1.4e10:  # the universe is about 13.8 billion years old
                    return "longer than the age of the universe"
                for f, label in [(1e9, "billion"), (1e6, "million"), (1e3, "thousand")]:
                    if v >= f:
                        return f"{v / f:.1f} {label} years"
            n = f"{v:.1f}" if v < 10 else str(round(v))
            return f"{n} {name}{'' if n in ('1', '1.0') else 's'}"
    return f"{round(seconds)} seconds"


def crack_estimates(bits: float) -> dict:
    guesses_half = 2 ** (bits - 1)
    return {"fast": format_duration(guesses_half / 1e10),
            "nation": format_duration(guesses_half / 1e12)}
