"""Run blocking work off the Tk main thread, delivering results safely back.

Tkinter is not thread-safe, so the worker thread only touches a queue; the
result is picked up by a poll scheduled with widget.after() on the main thread.
"""
from __future__ import annotations

import queue
import threading


def run_async(widget, fn, on_done, on_error=None):
    """Call fn() in a background thread; invoke on_done(result) / on_error(msg)
    on the Tk main thread when it finishes."""
    q: "queue.Queue" = queue.Queue(maxsize=1)

    def work():
        try:
            q.put(("ok", fn()))
        except Exception as e:  # noqa: BLE001
            q.put(("err", str(e)))

    def poll():
        try:
            kind, value = q.get_nowait()
        except queue.Empty:
            widget.after(60, poll)
            return
        if kind == "ok":
            on_done(value)
        elif on_error is not None:
            on_error(value)

    threading.Thread(target=work, daemon=True).start()
    widget.after(60, poll)
