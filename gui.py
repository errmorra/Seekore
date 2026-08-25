#!/usr/bin/env python3
"""
gui.py -- Desktop GUI for Seekore, the Threat Intelligence Web Scraper

Built with Tkinter, Python's standard-library GUI toolkit, so running the
GUI requires ZERO extra dependencies beyond what main.py already needs
(on some minimal Linux installs you may need `sudo apt-get install
python3-tk` -- see README.md).

This file is a presentation layer ONLY. It reuses the exact same skills/
modules as main.py:
    skills.file_handler -> load/save sources.json, write the JSON report
    skills.scanner       -> process_source() / run_full_scan() (shared with main.py)

main.py and gui.py can therefore never drift out of sync -- there is only
one implementation of "how to scan a source" and "how to build a report",
and both front-ends call it.

Run it with:
    python3 gui.py
"""

import json
import logging
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from skills.file_handler import ensure_output_dir, load_sources, save_json_report
from skills.scanner import run_full_scan

SOURCES_CONFIG_PATH = "sources.json"
OUTPUT_REPORT_PATH = "output/ioc_report.json"


# =============================================================================
# Logging bridge: pipes Python's `logging` output into the GUI's log panel.
# =============================================================================
class QueueLogHandler(logging.Handler):
    """
    A logging.Handler that pushes formatted log lines into a thread-safe
    queue.Queue instead of printing them.

    This exists because the scan runs on a background thread (so the UI
    doesn't freeze while waiting on slow HTTP requests), but Tkinter
    widgets may ONLY be safely touched from the main thread. The main
    thread polls this queue on a timer (see ThreatIntelGUI._poll_queues)
    and is the only place that actually writes to the log Text widget.
    """

    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(self.format(record))


# =============================================================================
# Small modal dialog for adding/editing a single source entry.
# =============================================================================
class SourceDialog(simpledialog.Dialog):
    """Modal popup with Name / URL / Active fields, used for Add and Edit."""

    def __init__(self, parent, title, name="", url="", active=True):
        self.initial_name = name
        self.initial_url = url
        self.initial_active = active
        self.result = None
        super().__init__(parent, title=title)

    def body(self, master):
        ttk.Label(master, text="Name:").grid(row=0, column=0, sticky="w", padx=4, pady=6)
        self.name_var = tk.StringVar(value=self.initial_name)
        ttk.Entry(master, textvariable=self.name_var, width=48).grid(row=0, column=1, padx=4, pady=6)

        ttk.Label(master, text="URL:").grid(row=1, column=0, sticky="w", padx=4, pady=6)
        self.url_var = tk.StringVar(value=self.initial_url)
        url_entry = ttk.Entry(master, textvariable=self.url_var, width=48)
        url_entry.grid(row=1, column=1, padx=4, pady=6)

        self.active_var = tk.BooleanVar(value=self.initial_active)
        ttk.Checkbutton(master, text="Active", variable=self.active_var).grid(
            row=2, column=1, sticky="w", padx=4, pady=6
        )
        return url_entry  # initial focus

    def validate(self):
        if not self.url_var.get().strip():
            messagebox.showerror("Missing URL", "A source must have a URL.", parent=self)
            return False
        return True

    def apply(self):
        url = self.url_var.get().strip()
        self.result = {
            "name": self.name_var.get().strip() or url,
            "url": url,
            "active": bool(self.active_var.get()),
        }


# =============================================================================
# Main application window
# =============================================================================
class ThreatIntelGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Seekore -- Threat Intelligence Web Scraper")
        self.root.geometry("1000x700")
        self.root.minsize(880, 580)

        # Thread-safe channels between the background scan thread and the
        # Tkinter main loop. Nothing from the scan thread touches a widget
        # directly -- everything goes through one of these two queues.
        self.log_queue = queue.Queue()
        self.result_queue = queue.Queue()

        self.scan_thread = None
        self.sources = []        # in-memory copy of sources.json's list
        self.last_report = None  # most recently completed scan report

        self._setup_logging()
        self._build_layout()
        self._load_sources_into_ui()

        # Start polling the queues every 100ms for log lines / finished scans.
        self.root.after(100, self._poll_queues)

    # -------------------------------------------------------------------
    # Logging wiring
    # -------------------------------------------------------------------
    def _setup_logging(self):
        """
        Attach a QueueLogHandler to the same "ThreatIntelScraper" logger
        tree that skills/scanner.py and skills/web_scraper.py already log
        to, so every log line generated during a scan shows up live in
        the GUI's "Live Log" tab -- no changes needed in those modules.
        """
        handler = QueueLogHandler(self.log_queue)
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%H:%M:%S"))

        root_logger = logging.getLogger("ThreatIntelScraper")
        root_logger.setLevel(logging.INFO)
        root_logger.addHandler(handler)
        # The CLI's own basicConfig() isn't loaded here, so there's no
        # console handler to duplicate against -- this keeps the GUI's
        # log panel as the single destination for scan activity.

    # -------------------------------------------------------------------
    # Layout construction
    # -------------------------------------------------------------------
    def _build_layout(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass  # fall back to whatever default ttk theme is available
        style.configure("Accent.TButton", font=("TkDefaultFont", 10, "bold"))

        # --- Sources panel -----------------------------------------------------
        sources_frame = ttk.LabelFrame(self.root, text=f"Sources  ({SOURCES_CONFIG_PATH})")
        sources_frame.pack(side="top", fill="x", padx=10, pady=(10, 5))

        columns = ("name", "url", "active")
        self.sources_tree = ttk.Treeview(sources_frame, columns=columns, show="headings", height=6)
        self.sources_tree.heading("name", text="Name")
        self.sources_tree.heading("url", text="URL")
        self.sources_tree.heading("active", text="Active")
        self.sources_tree.column("name", width=190)
        self.sources_tree.column("url", width=440)
        self.sources_tree.column("active", width=70, anchor="center")
        self.sources_tree.pack(side="left", fill="both", expand=True, padx=(8, 4), pady=8)
        self.sources_tree.bind("<Double-1>", lambda _e: self._edit_source())

        btns = ttk.Frame(sources_frame)
        btns.pack(side="left", fill="y", padx=(0, 8), pady=8)
        ttk.Button(btns, text="Add...", command=self._add_source, width=16).pack(fill="x", pady=2)
        ttk.Button(btns, text="Edit...", command=self._edit_source, width=16).pack(fill="x", pady=2)
        ttk.Button(btns, text="Remove", command=self._remove_source, width=16).pack(fill="x", pady=2)
        ttk.Button(btns, text="Toggle Active", command=self._toggle_active, width=16).pack(fill="x", pady=2)
        ttk.Separator(btns, orient="horizontal").pack(fill="x", pady=6)
        ttk.Button(btns, text="Save to disk", command=self._save_sources, width=16).pack(fill="x", pady=2)
        ttk.Button(btns, text="Reload from disk", command=self._load_sources_into_ui, width=16).pack(
            fill="x", pady=2
        )

        # --- Scan control bar ----------------------------------------------------
        control_frame = ttk.Frame(self.root)
        control_frame.pack(side="top", fill="x", padx=10, pady=5)

        self.run_button = ttk.Button(
            control_frame, text="▶  Run Scan", style="Accent.TButton", command=self._start_scan
        )
        self.run_button.pack(side="left")

        self.progress = ttk.Progressbar(control_frame, mode="indeterminate", length=180)
        self.progress.pack(side="left", padx=10)

        self.status_var = tk.StringVar(value="Idle.")
        ttk.Label(control_frame, textvariable=self.status_var).pack(side="left", padx=6)

        ttk.Button(control_frame, text="Open Output Folder", command=self._open_output_folder).pack(side="right")

        # --- Tabbed output area: Log / Results / IOC map --------------------------
        notebook = ttk.Notebook(self.root)
        notebook.pack(side="top", fill="both", expand=True, padx=10, pady=(5, 0))

        self._build_log_tab(notebook)
        self._build_results_tab(notebook)
        self._build_ioc_tab(notebook)

        # --- Bottom status bar -----------------------------------------------------
        self.summary_var = tk.StringVar(value="No scan run yet.")
        ttk.Label(self.root, textvariable=self.summary_var, relief="sunken", anchor="w", padding=(6, 3)).pack(
            side="bottom", fill="x"
        )

    def _build_log_tab(self, notebook):
        log_tab = ttk.Frame(notebook)
        notebook.add(log_tab, text="Live Log")

        self.log_text = tk.Text(
            log_tab,
            wrap="word",
            state="disabled",
            background="#0f172a",
            foreground="#e2e8f0",
            insertbackground="white",
            font=("Consolas", 10) if sys.platform == "win32" else ("Monospace", 10),
        )
        log_scroll = ttk.Scrollbar(log_tab, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

    def _build_results_tab(self, notebook):
        results_tab = ttk.Frame(notebook)
        notebook.add(results_tab, text="Results by Source")

        columns = ("source", "status", "ips", "hashes", "error")
        self.results_tree = ttk.Treeview(results_tab, columns=columns, show="headings")
        headers = {"source": "Source", "status": "Status", "ips": "IPv4 Found", "hashes": "SHA256 Found", "error": "Error"}
        widths = {"source": 260, "status": 80, "ips": 90, "hashes": 100, "error": 320}
        for col in columns:
            self.results_tree.heading(col, text=headers[col])
            self.results_tree.column(col, width=widths[col], anchor="w")

        self.results_tree.tag_configure("success", foreground="#15803d")
        self.results_tree.tag_configure("failed", foreground="#b91c1c")

        results_scroll = ttk.Scrollbar(results_tab, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)
        self.results_tree.pack(side="left", fill="both", expand=True)
        results_scroll.pack(side="right", fill="y")

    def _build_ioc_tab(self, notebook):
        ioc_tab = ttk.Frame(notebook)
        notebook.add(ioc_tab, text="IOC → Source Mapping")

        columns = ("ioc", "type", "sources")
        self.ioc_tree = ttk.Treeview(ioc_tab, columns=columns, show="headings")
        self.ioc_tree.heading("ioc", text="Indicator")
        self.ioc_tree.heading("type", text="Type")
        self.ioc_tree.heading("sources", text="Found On")
        self.ioc_tree.column("ioc", width=300)
        self.ioc_tree.column("type", width=90, anchor="center")
        self.ioc_tree.column("sources", width=470)

        ioc_scroll = ttk.Scrollbar(ioc_tab, command=self.ioc_tree.yview)
        self.ioc_tree.configure(yscrollcommand=ioc_scroll.set)
        self.ioc_tree.pack(side="left", fill="both", expand=True)
        ioc_scroll.pack(side="right", fill="y")

    # -------------------------------------------------------------------
    # Sources CRUD -- all in-memory; nothing touches sources.json until
    # the user explicitly clicks "Save to disk". This mirrors editing a
    # file in a text editor: browse/change freely, save when you mean it.
    # -------------------------------------------------------------------
    def _load_sources_into_ui(self):
        try:
            self.sources = load_sources(SOURCES_CONFIG_PATH)
        except FileNotFoundError:
            self.sources = []
        except ValueError as e:
            messagebox.showerror("Invalid sources.json", str(e))
            self.sources = []
        self._refresh_sources_tree()

    def _refresh_sources_tree(self):
        self.sources_tree.delete(*self.sources_tree.get_children())
        for idx, src in enumerate(self.sources):
            self.sources_tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(src.get("name", ""), src.get("url", ""), "Yes" if src.get("active", True) else "No"),
            )

    def _selected_index(self):
        selection = self.sources_tree.selection()
        return int(selection[0]) if selection else None

    def _add_source(self):
        dialog = SourceDialog(self.root, "Add Source")
        if dialog.result:
            self.sources.append(dialog.result)
            self._refresh_sources_tree()

    def _edit_source(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("No selection", "Select a source to edit first.")
            return
        src = self.sources[idx]
        dialog = SourceDialog(
            self.root, "Edit Source", name=src.get("name", ""), url=src.get("url", ""), active=src.get("active", True)
        )
        if dialog.result:
            self.sources[idx] = dialog.result
            self._refresh_sources_tree()

    def _remove_source(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("No selection", "Select a source to remove first.")
            return
        removed = self.sources.pop(idx)
        self._refresh_sources_tree()
        self.status_var.set(f"Removed '{removed.get('name', removed.get('url'))}' (not yet saved).")

    def _toggle_active(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("No selection", "Select a source to toggle first.")
            return
        self.sources[idx]["active"] = not self.sources[idx].get("active", True)
        self._refresh_sources_tree()

    def _save_sources(self):
        try:
            with open(SOURCES_CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump({"sources": self.sources}, f, indent=2)
            self.status_var.set(f"Saved {len(self.sources)} source(s) to {SOURCES_CONFIG_PATH}.")
        except OSError as e:
            messagebox.showerror("Save failed", str(e))

    # -------------------------------------------------------------------
    # Scan execution: kicked off on a background thread so slow/hanging
    # HTTP requests never freeze the window. All UI updates from the scan
    # happen later, via _poll_queues() running on the Tkinter main thread.
    # -------------------------------------------------------------------
    def _start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return  # a scan is already running -- ignore duplicate clicks

        active_sources = [s for s in self.sources if s.get("active", True)]
        if not active_sources:
            messagebox.showwarning("No active sources", "Add at least one active source before scanning.")
            return

        self.run_button.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set(f"Scanning {len(active_sources)} source(s)...")
        self._clear_log()
        self.results_tree.delete(*self.results_tree.get_children())
        self.ioc_tree.delete(*self.ioc_tree.get_children())

        self.scan_thread = threading.Thread(
            target=self._run_scan_worker,
            args=(active_sources, len(self.sources)),
            daemon=True,  # so a hung scan never blocks the app from closing
        )
        self.scan_thread.start()

    def _run_scan_worker(self, active_sources, total_configured):
        """
        Runs on a background thread. MUST NOT touch any Tkinter widget
        directly -- results are only ever handed back via result_queue,
        which the main thread drains in _poll_queues().
        """
        report = run_full_scan(active_sources, total_configured)

        try:
            ensure_output_dir("output")
            save_json_report(report, OUTPUT_REPORT_PATH)
        except OSError as e:
            report["scan_metadata"]["write_error"] = str(e)

        self.result_queue.put(report)

    # -------------------------------------------------------------------
    # Queue polling -- the ONLY place background-thread data reaches the UI
    # -------------------------------------------------------------------
    def _poll_queues(self):
        try:
            while True:
                self._append_log(self.log_queue.get_nowait())
        except queue.Empty:
            pass

        try:
            report = self.result_queue.get_nowait()
            self._on_scan_complete(report)
        except queue.Empty:
            pass

        self.root.after(100, self._poll_queues)

    def _on_scan_complete(self, report):
        self.last_report = report
        self.progress.stop()
        self.run_button.configure(state="normal")

        meta = report["scan_metadata"]
        self.status_var.set("Scan complete.")

        write_note = ""
        if meta.get("write_error"):
            write_note = f"  |  ⚠ Could not save report: {meta['write_error']}"
        self.summary_var.set(
            f"Sources: {meta['sources_succeeded']} succeeded / {meta['sources_failed']} failed   |   "
            f"Unique IOCs: {meta['total_unique_iocs']}   |   Report: {OUTPUT_REPORT_PATH}{write_note}"
        )

        for url, result in report["results_by_source"].items():
            tag = "success" if result["status"] == "success" else "failed"
            self.results_tree.insert(
                "",
                "end",
                values=(
                    result.get("source_name", url),
                    result["status"],
                    len(result.get("ipv4_addresses", [])),
                    len(result.get("sha256_hashes", [])),
                    result.get("error") or "",
                ),
                tags=(tag,),
            )

        for ioc, sources_found_on in report["ioc_to_source_mapping"].items():
            ioc_type = "SHA256" if len(ioc) == 64 else "IPv4"
            self.ioc_tree.insert("", "end", values=(ioc, ioc_type, ", ".join(sources_found_on)))

    # -------------------------------------------------------------------
    # Small helpers
    # -------------------------------------------------------------------
    def _append_log(self, line):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _open_output_folder(self):
        path = os.path.abspath("output")
        ensure_output_dir(path)
        try:
            if sys.platform == "win32":
                os.startfile(path)  # noqa: S606 -- Windows-only API, no shell injection risk here
            elif sys.platform == "darwin":
                subprocess.run(["open", path], check=False)
            else:
                subprocess.run(["xdg-open", path], check=False)
        except Exception as e:
            messagebox.showerror("Could not open folder", f"{path}\n\n{e}")


def main():
    root = tk.Tk()
    ThreatIntelGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
