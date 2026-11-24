"""A tiny property-based test runner, written for Cathodemon.

See .kiro/specs/property-based-tests. A property is a rule that must hold for
any input. The runner checks it against many inputs drawn from a seeded
random.Random (so a seed reproduces every input), and on the first failure it
shrinks the input to the simplest one that still fails. Standard library only;
no Hypothesis or other third-party package.
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass

DEFAULT_RUNS = 100
MAX_SHRINK = 200


# ------------------------------------------------------------------ generators
class Gen:
    """A value generator: draw(rng) makes one, shrink(value) yields simpler ones."""

    def draw(self, rng):
        raise NotImplementedError

    def shrink(self, value):
        return iter(())


class Integers(Gen):
    def __init__(self, lo, hi):
        self.lo, self.hi = lo, hi

    def draw(self, rng):
        return rng.randint(self.lo, self.hi)

    def shrink(self, value):
        seen = set()
        for cand in (self.lo, (self.lo + value) // 2, value - 1):
            if self.lo <= cand < value and cand not in seen:
                seen.add(cand)
                yield cand


class Booleans(Gen):
    def draw(self, rng):
        return rng.random() < 0.5

    def shrink(self, value):
        if value:
            yield False


class Binary(Gen):
    def __init__(self, min_len=0, max_len=64):
        self.min_len, self.max_len = min_len, max_len

    def draw(self, rng):
        n = rng.randint(self.min_len, self.max_len)
        return bytes(rng.randrange(256) for _ in range(n))

    def shrink(self, value):
        n = len(value)
        if n > self.min_len:
            half = max(self.min_len, n // 2)
            if half < n:
                yield value[:half]
            yield value[:n - 1]
        if any(value):
            yield bytes(n)


class Text(Gen):
    def __init__(self, alphabet, min_len=0, max_len=20):
        self.alphabet, self.min_len, self.max_len = alphabet, min_len, max_len

    def draw(self, rng):
        n = rng.randint(self.min_len, self.max_len)
        return "".join(rng.choice(self.alphabet) for _ in range(n))

    def shrink(self, value):
        n = len(value)
        if n > self.min_len:
            yield value[:max(self.min_len, n // 2)]
            yield value[:n - 1]
        first = self.alphabet[0]
        if value and any(c != first for c in value):
            yield first * n


class Lists(Gen):
    def __init__(self, element, min_len=0, max_len=10):
        self.element, self.min_len, self.max_len = element, min_len, max_len

    def draw(self, rng):
        n = rng.randint(self.min_len, self.max_len)
        return [self.element.draw(rng) for _ in range(n)]

    def shrink(self, value):
        n = len(value)
        if n > self.min_len:
            yield value[:n - 1]
            yield value[:max(self.min_len, n // 2)]
        for i in range(n):
            for cand in self.element.shrink(value[i]):
                yield value[:i] + [cand] + value[i + 1:]
                break


class Tuples(Gen):
    def __init__(self, *gens):
        self.gens = gens

    def draw(self, rng):
        return tuple(g.draw(rng) for g in self.gens)

    def shrink(self, value):
        for i, g in enumerate(self.gens):
            for cand in g.shrink(value[i]):
                yield value[:i] + (cand,) + value[i + 1:]


class SampledFrom(Gen):
    def __init__(self, seq):
        self.seq = list(seq)

    def draw(self, rng):
        return rng.choice(self.seq)

    def shrink(self, value):
        try:
            idx = self.seq.index(value)
        except ValueError:
            return
        for j in (0, idx // 2):
            if j < idx:
                yield self.seq[j]


class DnsNames(Gen):
    """A valid DNS name of 1 to 4 labels, each 1 to 20 of a-z0-9-, never
    starting or ending with a hyphen."""
    _EDGE = "abcdefghijklmnopqrstuvwxyz0123456789"
    _MID = _EDGE + "-"

    def draw(self, rng):
        labels = []
        for _ in range(rng.randint(1, 4)):
            n = rng.randint(1, 20)
            if n == 1:
                labels.append(rng.choice(self._EDGE))
            else:
                mid = "".join(rng.choice(self._MID) for _ in range(n - 2))
                labels.append(rng.choice(self._EDGE) + mid + rng.choice(self._EDGE))
        return ".".join(labels)

    def shrink(self, value):
        labels = value.split(".")
        if len(labels) > 1:
            yield labels[0]
            yield ".".join(labels[:-1])
        if value != "a":
            yield "a"


# ------------------------------------------------------------------ runner
@dataclass
class Result:
    name: str
    passed: bool
    seed: int
    runs: int
    failing: object = None
    shrunk: object = None
    error: str = ""


def _run(prop, value):
    """Return (ok, error_text). A property fails when it returns False or raises."""
    try:
        return (prop(value) is not False, "")
    except Exception as exc:  # noqa: BLE001 - any exception is a failing property
        return (False, f"{type(exc).__name__}: {exc}")


def _shrink(gen, value, prop):
    best = value
    for _ in range(MAX_SHRINK):
        for cand in gen.shrink(best):
            if not _run(prop, cand)[0]:
                best = cand
                break
        else:
            break
    return best


def check(name, gen, prop, runs=None, seed=None) -> Result:
    if runs is None:
        runs = int(os.environ.get("CATHODEMON_PBT_RUNS", DEFAULT_RUNS))
    if seed is None:
        env = os.environ.get("CATHODEMON_PBT_SEED")
        seed = int(env) if env else random.SystemRandom().randrange(2 ** 63)
    rng = random.Random(seed)
    for _ in range(runs):
        value = gen.draw(rng)
        ok, err = _run(prop, value)
        if not ok:
            shrunk = _shrink(gen, value, prop)
            return Result(name, False, seed, runs, value, shrunk, _run(prop, shrunk)[1] or err)
    return Result(name, True, seed, runs)
