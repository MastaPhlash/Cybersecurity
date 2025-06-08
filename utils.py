"""
utils.py
Utility functions, config, logging, and tooltips for the Python Port Scanner.
"""
import tkinter as tk
import configparser
import logging
import os

CONFIG_FILE = 'portscanner.cfg'
config = configparser.ConfigParser()

logging.basicConfig(filename='portscanner.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

def load_theme() -> str:
    """Load the saved theme mode from config file, defaulting to 'light' if missing or corrupt."""
    if os.path.exists(CONFIG_FILE):
        try:
            config.read(CONFIG_FILE)
            return config.get('theme', 'mode', fallback='light')
        except Exception:
            return 'light'
    return 'light'

def save_theme(mode: str) -> None:
    """Save the theme mode to config file."""
    if not config.has_section('theme'):
        config.add_section('theme')
    config.set('theme', 'mode', mode)
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)

def show_info_dialog(title: str, message: str) -> None:
    """Show an informational dialog (for About/help)."""
    from tkinter import messagebox
    messagebox.showinfo(title, message)

class ToolTip:
    """Tooltip for Tkinter widgets."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)
    def show_tip(self, event=None):
        if self.tipwindow or not self.text:
            return
        x, y, _, cy = self.widget.bbox("insert") if hasattr(self.widget, 'bbox') else (0,0,0,0)
        x = x + self.widget.winfo_rootx() + 25
        y = y + cy + self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT, background="#ffffe0", relief=tk.SOLID, borderwidth=1, font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)
    def hide_tip(self, event=None):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()
