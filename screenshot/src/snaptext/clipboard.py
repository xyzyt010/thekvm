"""Clipboard auto-copy (text). pyperclip primary, tkinter fallback."""
from __future__ import annotations


def copy_text(text: str) -> bool:
    if not text:
        return False
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        pass
    try:
        import tkinter as tk
        r = tk.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(text)
        r.update()
        r.destroy()
        return True
    except Exception:
        return False
