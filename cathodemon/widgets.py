"""Reusable themed Tkinter widgets. Standard library only."""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import ttk

from .theme import COLORS, FONTS, sev_color

_SEV_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "good": "GOOD", "info": "INFO"}
WRAP = 780  # fixed wrap width, for callers that don't want automatic wrapping
LOGO_PATH = Path(__file__).resolve().parent.parent / "assets" / "logo.png"


def load_logo(master, subsample=1):
    """Load assets/logo.png as a Tk image. Tk's own PhotoImage reads PNG (8.6+),
    so this stays standard-library-only. `subsample` shrinks it by an integer
    factor. Returns None if the file can't be loaded, so callers fall back to
    the hand-drawn block-letter banner."""
    try:
        img = tk.PhotoImage(master=master, file=str(LOGO_PATH))
    except tk.TclError:
        return None
    return img.subsample(subsample, subsample) if subsample > 1 else img


# ---------------------------------------------------------------- text
def _autowrap(label, minimum=240):
    """Re-wrap a label's text to its width whenever the window is resized."""
    def on_resize(event):
        width = max(minimum, event.width - 4)
        if int(float(label.cget("wraplength") or 0)) != width:
            label.configure(wraplength=width)
    label.bind("<Configure>", on_resize, add="+")
    return label


def lab(parent, text="", fg=None, font=None, wrap=None, anchor="w", **kw):
    """A label. wrap="auto" re-wraps to the label's width; a number wraps at that width."""
    bg = kw.pop("bg", None) or parent.cget("bg")
    label = tk.Label(parent, text=text, bg=bg, fg=fg or COLORS["text"], font=font or FONTS["base"],
                     anchor=anchor, justify="left", **kw)
    if wrap == "auto":
        _autowrap(label)
    elif wrap:
        label.configure(wraplength=wrap)
    return label


def muted(parent, text="", wrap="auto"):
    return lab(parent, text, fg=COLORS["muted"], wrap=wrap)


def small(parent, text="", wrap="auto"):
    return lab(parent, text, fg=COLORS["faint"], font=FONTS["small"], wrap=wrap)


def title(parent, text):
    return lab(parent, text.upper(), fg=COLORS["green"], font=FONTS["title"])


def h1(parent, text):
    return lab(parent, text, fg=COLORS["text"], font=FONTS["h1"])


def h2(parent, text, wrap="auto"):
    return lab(parent, text, fg=COLORS["text"], font=FONTS["h2"], wrap=wrap)


# ---------------------------------------------------------------- controls
_BUTTONS = {
    # variant: (background, text, hover background, border)
    "primary": ("green", "ink", "green_bright", None),
    "default": ("panel_hi", "text", "line", "line_hi"),
    "ghost": (None, "muted", "panel_hi", None),
    "danger": ("panel_hi", "red", "line", "line"),
}


def button(parent, text, command, variant="default", width=None):
    bg_key, fg_key, hover_key, border_key = _BUTTONS.get(variant, _BUTTONS["default"])
    bg = COLORS[bg_key] if bg_key else parent.cget("bg")
    hover = COLORS[hover_key]
    border = COLORS[border_key] if border_key else bg
    b = tk.Button(parent, text=text, command=command, bg=bg, fg=COLORS[fg_key],
                  activebackground=hover, activeforeground=COLORS[fg_key], relief="flat", bd=0,
                  padx=16, pady=7, font=FONTS["button"], cursor="hand2",
                  highlightthickness=1 if border_key else 0, highlightbackground=border,
                  highlightcolor=border, disabledforeground=COLORS["faint"])

    def enter(_event):
        if str(b.cget("state")) != "disabled":
            b.configure(bg=hover)

    b.bind("<Enter>", enter)
    b.bind("<Leave>", lambda _e: b.configure(bg=bg))
    if width:
        b.configure(width=width)
    return b


def entry(parent, show=None, textvariable=None, width=None):
    e = tk.Entry(parent, bg=COLORS["input"], fg=COLORS["text"], insertbackground=COLORS["green"],
                 relief="flat", bd=0, highlightthickness=1, highlightbackground=COLORS["line"],
                 highlightcolor=COLORS["green_dim"], font=FONTS["base"], show=show or "",
                 textvariable=textvariable, selectbackground=COLORS["sel"],
                 selectforeground=COLORS["text"])
    if width:
        e.configure(width=width)
    return e


def text_box(parent, height=6, readonly=False, mono=False, wrap="word"):
    t = tk.Text(parent, bg=COLORS["input"], fg=COLORS["text"], insertbackground=COLORS["green"],
                relief="flat", bd=0, highlightthickness=1, highlightbackground=COLORS["line"],
                highlightcolor=COLORS["green_dim"], font=FONTS["mono"] if mono else FONTS["base"],
                height=height, wrap=wrap, padx=10, pady=8, selectbackground=COLORS["sel"],
                selectforeground=COLORS["text"], spacing1=1, spacing3=1)
    if readonly:
        t.configure(state="disabled")
    return t


def set_text(widget, content):
    state = widget.cget("state")
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", content)
    if state == "disabled":
        widget.configure(state="disabled")


def check(parent, text, variable, command=None):
    return tk.Checkbutton(parent, text=text, variable=variable, command=command,
                          bg=parent.cget("bg"), fg=COLORS["text"], selectcolor=COLORS["input"],
                          activebackground=parent.cget("bg"), activeforeground=COLORS["green"],
                          font=FONTS["base"], highlightthickness=0, bd=0, anchor="w")


# ---------------------------------------------------------------- layout
class Panel(tk.Frame):
    """A card with an optional title and subtitle. Put its content in .body."""

    def __init__(self, master, title_text=None, subtitle=None, pad=20):
        super().__init__(master, bg=COLORS["panel"], highlightbackground=COLORS["line"],
                         highlightthickness=1, bd=0)
        self.body = tk.Frame(self, bg=COLORS["panel"])
        self.body.pack(fill="both", expand=True, padx=pad, pady=pad - 4)
        if title_text:
            title(self.body, title_text).pack(fill="x")
        if subtitle:
            muted(self.body, subtitle).pack(fill="x", pady=(4, 0))
        if title_text or subtitle:
            tk.Frame(self.body, bg=COLORS["panel"], height=10).pack(fill="x")


class Collapsible(tk.Frame):
    """A section that opens and closes when its heading is clicked. Content goes in .body."""

    def __init__(self, master, title_text, opened=False):
        super().__init__(master, bg=master.cget("bg"))
        self._title = title_text
        self.opened = False
        self.heading = tk.Label(self, bg=master.cget("bg"), fg=COLORS["green"], font=FONTS["button"],
                                cursor="hand2", anchor="w")
        self.heading.pack(fill="x")
        self.heading.bind("<Button-1>", lambda _e: self.toggle())
        self.body = tk.Frame(self, bg=master.cget("bg"))
        self.set_open(opened)

    def set_open(self, value):
        self.opened = bool(value)
        self.heading.configure(text=("\u25be  " if self.opened else "\u25b8  ") + self._title)
        if self.opened:
            self.body.pack(fill="x", pady=(10, 0))
        else:
            self.body.pack_forget()

    def toggle(self):
        self.set_open(not self.opened)


def steps(parent, items):
    """A numbered list of steps."""
    bg = parent.cget("bg")
    frame = tk.Frame(parent, bg=bg)
    for i, text in enumerate(items, 1):
        row = tk.Frame(frame, bg=bg)
        row.pack(fill="x", pady=4)
        tk.Label(row, text=str(i), bg=COLORS["green"], fg=COLORS["ink"], font=FONTS["small_bold"],
                 width=2).pack(side="left", anchor="n", padx=(0, 12), pady=(2, 0))
        lab(row, text, wrap="auto").pack(side="left", fill="x", expand=True)
    return frame


def note(parent, text, color_key="cyan"):
    """A highlighted remark, such as what is or isn't saved."""
    box = tk.Frame(parent, bg=COLORS["panel_hi"])
    tk.Frame(box, bg=COLORS[color_key], width=3).pack(side="left", fill="y")
    lab(box, text, bg=COLORS["panel_hi"], wrap="auto").pack(side="left", fill="x", expand=True,
                                                            padx=12, pady=9)
    return box


def badge_text(sev):
    return _SEV_LABEL.get(sev, "INFO")


def finding(parent, sev, title_text, detail, evidence=None, source=None):
    color = sev_color(sev)
    bg = COLORS["panel_hi"]
    row = tk.Frame(parent, bg=bg)
    tk.Frame(row, bg=color, width=4).pack(side="left", fill="y")
    body = tk.Frame(row, bg=bg)
    body.pack(side="left", fill="both", expand=True, padx=14, pady=10)
    head = tk.Frame(body, bg=bg)
    head.pack(fill="x")
    lab(head, badge_text(sev), fg=color, font=FONTS["tag"], bg=bg).pack(side="left", anchor="n",
                                                                       padx=(0, 10), pady=(2, 0))
    if source:
        lab(head, source, fg=COLORS["faint"], font=FONTS["small"], bg=bg).pack(side="right", anchor="n")
    lab(head, title_text, font=FONTS["bold"], bg=bg, wrap="auto").pack(side="left", fill="x", expand=True)
    lab(body, detail, fg=COLORS["muted"], bg=bg, wrap="auto").pack(fill="x", pady=(4, 0))
    if evidence:
        lab(body, "\u21b3 " + evidence, fg=COLORS["amber"], font=FONTS["mono_small"], bg=bg,
            wrap="auto").pack(fill="x", pady=(4, 0))
    return row


class Meter(tk.Canvas):
    """A thin horizontal bar that fills to a fraction of its width."""

    def __init__(self, master, width=None, height=8):
        super().__init__(master, height=height, bg=COLORS["line"], highlightthickness=0, bd=0)
        self._frac = 0.0
        self._color = COLORS["green"]
        self.bind("<Configure>", lambda _e: self._draw())

    def set(self, frac, color):
        self._frac = max(0.0, min(1.0, frac))
        self._color = color
        self._draw()

    def _draw(self):
        self.delete("all")
        if self._frac > 0:
            self.create_rectangle(0, 0, max(2, self.winfo_width() * self._frac),
                                  int(self.cget("height")), fill=self._color, outline="")


class ScoreGauge(tk.Frame):
    """A big score, a verdict, a one-line explanation and a bar."""

    def __init__(self, master):
        bg = master.cget("bg")
        super().__init__(master, bg=bg)
        top = tk.Frame(self, bg=bg)
        top.pack(fill="x")
        self.num = lab(top, "0", fg=COLORS["green"], font=FONTS["score"])
        self.num.pack(side="left", padx=(0, 18))
        col = tk.Frame(top, bg=bg)
        col.pack(side="left", fill="x", expand=True)
        self.band = lab(col, "\u2014", fg=COLORS["green"], font=FONTS["band"])
        self.band.pack(fill="x")
        self.blurb = muted(col, "")
        self.blurb.pack(fill="x")
        self.meter = Meter(self)
        self.meter.pack(fill="x", pady=(12, 0))

    def set(self, score, band, blurb, color):
        self.num.configure(text=str(score), fg=color)
        self.band.configure(text=band, fg=color)
        self.blurb.configure(text=blurb)
        self.meter.set(score / 100.0, color)


def chip(parent, text, command):
    bg = parent.cget("bg")
    c = tk.Label(parent, text=text, bg=bg, fg=COLORS["muted"], font=FONTS["small"], padx=10,
                 pady=3, cursor="hand2", highlightthickness=1, highlightbackground=COLORS["line"])
    c.bind("<Button-1>", lambda _e: command())
    c.bind("<Enter>", lambda _e: c.configure(fg=COLORS["green"], highlightbackground=COLORS["green_dim"]))
    c.bind("<Leave>", lambda _e: c.configure(fg=COLORS["muted"], highlightbackground=COLORS["line"]))
    return c


# ---------------------------------------------------------------- scrolling
_WHEEL_READY = set()
WHEEL_PIXELS = 120  # how far one mouse-wheel notch moves the page
# ttk widgets that normally swallow the wheel to change their own value or tab.
# Over them we scroll the page instead, so dragging two fingers always moves the
# window rather than quietly cycling a dropdown or switching a tab.
_HIJACK_CLASSES = ("TCombobox", "TSpinbox", "TNotebook")


def _scrollable_text(widget, direction):
    """True if a text box or table under the pointer can scroll that way itself."""
    try:
        first, last = widget.yview()
    except (tk.TclError, AttributeError, ValueError):
        return False
    return (direction < 0 and first > 0) or (direction > 0 and last < 1)


def _scroll_canvas(canvas, pixels):
    """Move a page canvas by a number of pixels, clamped to its content."""
    box = canvas.bbox("all")
    if not box:
        return
    content = box[3] - box[1]
    view = canvas.winfo_height()
    if content <= view:
        return
    top_px = min(max(0, canvas.canvasy(0) + pixels), content - view)
    canvas.yview_moveto(top_px / content)


def _install_wheel(top):
    """One wheel and touchpad handler per window. It scrolls whatever is under
    the pointer: an inner text box or table while it can still scroll that way,
    otherwise the page. Handles both a mouse wheel (<MouseWheel>, 120 a notch)
    and a precision touchpad (<TouchpadScroll>, many small deltas)."""
    if str(top) in _WHEEL_READY:
        return
    _WHEEL_READY.add(str(top))

    def touch_pixels(delta):
        # A precision touchpad sends <TouchpadScroll>; its delta packs (x, y).
        try:
            _dx, dy = top.tk.call("::tk::PreciseScrollDeltas", delta)
            return -int(dy)
        except (tk.TclError, ValueError):
            return 0

    def scroll(pixels):
        if not pixels:
            return
        direction = 1 if pixels > 0 else -1
        try:
            widget = top.winfo_containing(*top.winfo_pointerxy())
        except (KeyError, tk.TclError):
            return
        while widget is not None:
            if widget.winfo_class() in ("Text", "Listbox", "Treeview") \
                    and _scrollable_text(widget, direction):
                return  # the inner widget scrolls itself
            if getattr(widget, "_scroll_page", False):
                _scroll_canvas(widget, pixels)
                return
            try:
                widget = widget.master
            except (KeyError, tk.TclError):
                return

    def on_wheel(event):
        scroll(-event.delta if event.delta else 0)

    def on_touch(event):
        scroll(touch_pixels(event.delta))

    def page_only_wheel(event):  # replaces a combobox/notebook's own wheel binding
        scroll(-event.delta if event.delta else 0)
        return "break"

    def page_only_touch(event):
        scroll(touch_pixels(event.delta))
        return "break"

    top.bind_all("<MouseWheel>", on_wheel, add="+")
    top.bind_all("<Button-4>", lambda _e: scroll(-WHEEL_PIXELS), add="+")  # Linux wheel up
    top.bind_all("<Button-5>", lambda _e: scroll(WHEEL_PIXELS), add="+")   # Linux wheel down
    for cls in _HIJACK_CLASSES:
        top.bind_class(cls, "<MouseWheel>", page_only_wheel)
    try:  # precision-touchpad events exist on Tk 8.7+
        top.bind_all("<TouchpadScroll>", on_touch, add="+")
        for cls in _HIJACK_CLASSES:
            top.bind_class(cls, "<TouchpadScroll>", page_only_touch)
    except tk.TclError:
        pass


class ScrollFrame(tk.Frame):
    """A vertically scrollable page. Content goes in .inner, centred and
    limited to max_width so long lines stay easy to read."""

    def __init__(self, master, max_width=1060):
        super().__init__(master, bg=COLORS["bg"])
        self._max_width = max_width
        self.canvas = tk.Canvas(self, bg=COLORS["bg"], highlightthickness=0, bd=0)
        self.canvas._scroll_page = True
        bar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=COLORS["bg"])
        self.inner.bind("<Configure>",
                        lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.bind("<Configure>", self._fit)
        self.canvas.configure(yscrollcommand=bar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        _install_wheel(self.winfo_toplevel())

    def _fit(self, event):
        width = min(event.width, self._max_width)
        self.canvas.itemconfig(self._win, width=width)
        self.canvas.coords(self._win, max(0, (event.width - width) // 2), 0)


def clear(widget):
    for child in widget.winfo_children():
        child.destroy()
