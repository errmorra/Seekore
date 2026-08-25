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

import csv
import logging
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from skills.file_handler import ensure_output_dir, load_sources, save_json_report, save_sources
from skills.scanner import run_full_scan

SOURCES_CONFIG_PATH = "sources.json"
OUTPUT_REPORT_PATH = "output/ioc_report.json"

APP_TITLE = "Seekore -- Threat Intelligence Web Scraper"


# =============================================================================
# Logging bridge: pipes Python's `logging` output into the GUI's log panel.
# =============================================================================
class QueueLogHandler(logging.Handler):
    """
    A logging.Handler that pushes (levelname, formatted_line) tuples into a
    thread-safe queue.Queue instead of printing them.

    This exists because the scan runs on background threads (so the UI
    doesn't freeze while waiting on slow HTTP requests), but Tkinter
    widgets may ONLY be safely touched from the main thread. The main
    thread polls this queue on a timer (see ThreatIntelGUI._poll_queues)
    and is the only place that actually writes to the log Text widget.

    The level name rides along so the log panel can color-code WARNING and
    ERROR lines, making failures easy to spot while a scan is streaming.
    """

    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put((record.levelname, self.format(record)))


# =============================================================================
# Small modal dialog for adding/editing a single source entry.
# =============================================================================
class SourceDialog(simpledialog.Dialog):
    """Modal popup with Name / URL / Active fields, used for Add and Edit."""

    def __init__(self, parent, title, name="", url="", active=True, existing_urls=()):
        self.initial_name = name
        self.initial_url = url
        self.initial_active = active
        # URLs already configured (excluding the entry being edited), used
        # to warn about accidental duplicates before they're added.
        self.existing_urls = set(existing_urls)
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
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Missing URL", "A source must have a URL.", parent=self)
            return False

        # Quality-of-life: "thehackernews.com" is obviously meant to be a
        # URL, so silently normalize it instead of rejecting it.
        if not url.lower().startswith(("http://", "https://")):
            url = "https://" + url
            self.url_var.set(url)

        if url in self.existing_urls:
            keep = messagebox.askyesno(
                "Duplicate URL",
                f"A source with the URL\n\n  {url}\n\nis already configured. Add it anyway?",
                parent=self,
            )
            if not keep:
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
        self.root.title(APP_TITLE)
        self.root.geometry("1000x700")
        self.root.minsize(880, 580)

        # Thread-safe channels between the background scan threads and the
        # Tkinter main loop. Nothing from a scan thread touches a widget
        # directly -- everything goes through one of these two queues.
        self.log_queue = queue.Queue()
        self.event_queue = queue.Queue()  # ("source_done", ...) / ("scan_done", report)

        self.scan_thread = None
        self.cancel_event = threading.Event()
        self.sources = []         # in-memory copy of sources.json's list
        self.last_report = None   # most recently completed scan report
        self.dirty = False        # True when in-memory sources differ from disk
        self.ioc_rows = []        # (indicator, type, sources) tuples backing the IOC tab

        self._setup_logging()
        self._build_layout()
        self._bind_shortcuts()
        self._load_sources_into_ui()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Start polling the queues every 100ms for log lines / scan events.
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
        self._setup_sortable_headings(
            self.sources_tree,
            {"name": "Name", "url": "URL", "active": "Active"},
        )
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
        ttk.Button(btns, text="Reload from disk", command=self._reload_sources, width=16).pack(fill="x", pady=2)

        # --- Scan control bar ----------------------------------------------------
        control_frame = ttk.Frame(self.root)
        control_frame.pack(side="top", fill="x", padx=10, pady=5)

        self.run_button = ttk.Button(
            control_frame, text="\u25b6  Run Scan (F5)", style="Accent.TButton", command=self._start_scan
        )
        self.run_button.pack(side="left")

        self.stop_button = ttk.Button(control_frame, text="\u25a0  Stop", command=self._stop_scan, state="disabled")
        self.stop_button.pack(side="left", padx=(6, 0))

        self.progress = ttk.Progressbar(control_frame, mode="determinate", length=180)
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
        # Color-code by severity so failures jump out of a streaming log.
        self.log_text.tag_configure("WARNING", foreground="#facc15")
        self.log_text.tag_configure("ERROR", foreground="#f87171")
        self.log_text.tag_configure("CRITICAL", foreground="#f87171")

        log_scroll = ttk.Scrollbar(log_tab, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

    def _build_results_tab(self, notebook):
        results_tab = ttk.Frame(notebook)
        notebook.add(results_tab, text="Results by Source")

        columns = ("source", "status", "ips", "hashes", "error")
        self.results_tree = ttk.Treeview(results_tab, columns=columns, show="headings")
        self._setup_sortable_headings(
            self.results_tree,
            {"source": "Source", "status": "Status", "ips": "IPv4 Found", "hashes": "SHA256 Found", "error": "Error"},
            numeric_columns=("ips", "hashes"),
        )
        widths = {"source": 260, "status": 80, "ips": 90, "hashes": 100, "error": 320}
        for col in columns:
            self.results_tree.column(col, width=widths[col], anchor="w")

        self.results_tree.tag_configure("success", foreground="#15803d")
        self.results_tree.tag_configure("failed", foreground="#b91c1c")

        results_scroll = ttk.Scrollbar(results_tab, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)
        self.results_tree.pack(side="left", fill="both", expand=True)
        results_scroll.pack(side="right", fill="y")

    def _build_ioc_tab(self, notebook):
        ioc_tab = ttk.Frame(notebook)
        notebook.add(ioc_tab, text="IOC \u2192 Source Mapping")

        # Toolbar: live search, type filter, copy, and export.
        toolbar = ttk.Frame(ioc_tab)
        toolbar.pack(side="top", fill="x", padx=4, pady=(4, 2))

        ttk.Label(toolbar, text="Search:").pack(side="left")
        self.ioc_search_var = tk.StringVar()
        self.ioc_search_var.trace_add("write", lambda *_: self._refresh_ioc_tree())
        ttk.Entry(toolbar, textvariable=self.ioc_search_var, width=32).pack(side="left", padx=(4, 12))

        ttk.Label(toolbar, text="Type:").pack(side="left")
        self.ioc_type_var = tk.StringVar(value="All")
        type_combo = ttk.Combobox(
            toolbar, textvariable=self.ioc_type_var, values=("All", "IPv4", "SHA256"), state="readonly", width=8
        )
        type_combo.pack(side="left", padx=(4, 12))
        type_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_ioc_tree())

        self.ioc_count_var = tk.StringVar(value="")
        ttk.Label(toolbar, textvariable=self.ioc_count_var).pack(side="left")

        ttk.Button(toolbar, text="Export...", command=self._export_iocs).pack(side="right")
        ttk.Button(toolbar, text="Copy Selected", command=self._copy_selected_iocs).pack(side="right", padx=(0, 6))

        table_frame = ttk.Frame(ioc_tab)
        table_frame.pack(side="top", fill="both", expand=True)

        columns = ("ioc", "type", "sources")
        self.ioc_tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        self._setup_sortable_headings(
            self.ioc_tree,
            {"ioc": "Indicator", "type": "Type", "sources": "Found On"},
        )
        self.ioc_tree.column("ioc", width=300)
        self.ioc_tree.column("type", width=90, anchor="center")
        self.ioc_tree.column("sources", width=470)

        ioc_scroll = ttk.Scrollbar(table_frame, command=self.ioc_tree.yview)
        self.ioc_tree.configure(yscrollcommand=ioc_scroll.set)
        self.ioc_tree.pack(side="left", fill="both", expand=True)
        ioc_scroll.pack(side="right", fill="y")

        # Right-click context menu + Ctrl+C for the copy-paste workflow an
        # analyst actually uses: grab an indicator, drop it in another tool.
        self.ioc_menu = tk.Menu(self.ioc_tree, tearoff=0)
        self.ioc_menu.add_command(label="Copy Indicator(s)", command=self._copy_selected_iocs)
        self.ioc_menu.add_command(label="Copy Row(s)", command=lambda: self._copy_selected_iocs(full_row=True))
        self.ioc_tree.bind("<Button-3>", self._show_ioc_menu)
        self.ioc_tree.bind("<Control-c>", lambda _e: self._copy_selected_iocs())

    def _bind_shortcuts(self):
        self.root.bind("<F5>", lambda _e: self._start_scan())
        self.root.bind("<Control-s>", lambda _e: self._save_sources())

    # -------------------------------------------------------------------
    # Column sorting (shared by all three tables)
    # -------------------------------------------------------------------
    def _setup_sortable_headings(self, tree, headers, numeric_columns=()):
        """Wire every column heading to sort the table on click (toggling
        ascending/descending on repeat clicks)."""
        for col, text in headers.items():
            tree.heading(
                col,
                text=text,
                command=lambda t=tree, c=col, n=(col in numeric_columns): self._sort_tree(t, c, n),
            )

    def _sort_tree(self, tree, col, numeric):
        reverse = getattr(tree, "_last_sort", None) == (col, False)
        tree._last_sort = (col, reverse)

        def key(item):
            value = tree.set(item, col)
            if numeric:
                try:
                    return float(value)
                except ValueError:
                    return -1.0
            return value.lower()

        for position, item in enumerate(sorted(tree.get_children(""), key=key, reverse=reverse)):
            tree.move(item, "", position)

    # -------------------------------------------------------------------
    # Sources CRUD -- all in-memory; nothing touches sources.json until
    # the user explicitly clicks "Save to disk". This mirrors editing a
    # file in a text editor: browse/change freely, save when you mean it.
    # Any unsaved change flips self.dirty, which marks the window title
    # and arms the "save before exiting?" prompt.
    # -------------------------------------------------------------------
    def _load_sources_into_ui(self):
        try:
            self.sources = load_sources(SOURCES_CONFIG_PATH)
        except FileNotFoundError:
            self.sources = []
        except ValueError as e:
            messagebox.showerror("Invalid sources.json", str(e))
            self.sources = []
        self._set_dirty(False)
        self._refresh_sources_tree()

    def _reload_sources(self):
        if self.dirty and not messagebox.askyesno(
            "Discard unsaved changes?",
            "Reloading from disk will discard your unsaved source changes. Continue?",
        ):
            return
        self._load_sources_into_ui()
        self.status_var.set(f"Reloaded {len(self.sources)} source(s) from {SOURCES_CONFIG_PATH}.")

    def _set_dirty(self, dirty):
        self.dirty = dirty
        self.root.title(f"{APP_TITLE}  [unsaved changes]" if dirty else APP_TITLE)

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
        dialog = SourceDialog(
            self.root, "Add Source", existing_urls=[s.get("url", "") for s in self.sources]
        )
        if dialog.result:
            self.sources.append(dialog.result)
            self._set_dirty(True)
            self._refresh_sources_tree()

    def _edit_source(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("No selection", "Select a source to edit first.")
            return
        src = self.sources[idx]
        dialog = SourceDialog(
            self.root,
            "Edit Source",
            name=src.get("name", ""),
            url=src.get("url", ""),
            active=src.get("active", True),
            existing_urls=[s.get("url", "") for i, s in enumerate(self.sources) if i != idx],
        )
        if dialog.result:
            self.sources[idx] = dialog.result
            self._set_dirty(True)
            self._refresh_sources_tree()

    def _remove_source(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("No selection", "Select a source to remove first.")
            return
        removed = self.sources.pop(idx)
        self._set_dirty(True)
        self._refresh_sources_tree()
        self.status_var.set(f"Removed '{removed.get('name', removed.get('url'))}' (not yet saved).")

    def _toggle_active(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("No selection", "Select a source to toggle first.")
            return
        self.sources[idx]["active"] = not self.sources[idx].get("active", True)
        self._set_dirty(True)
        self._refresh_sources_tree()
        self.sources_tree.selection_set(str(idx))

    def _save_sources(self):
        try:
            save_sources(self.sources, SOURCES_CONFIG_PATH)
            self._set_dirty(False)
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

        self.cancel_event.clear()
        self.run_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.progress.configure(maximum=len(active_sources), value=0)
        self.status_var.set(f"Scanning... 0/{len(active_sources)} sources done.")
        self._clear_log()
        self.results_tree.delete(*self.results_tree.get_children())
        self.ioc_rows = []
        self._refresh_ioc_tree()

        self.scan_thread = threading.Thread(
            target=self._run_scan_worker,
            args=(active_sources, len(self.sources)),
            daemon=True,  # so a hung scan never blocks the app from closing
        )
        self.scan_thread.start()

    def _stop_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.cancel_event.set()
            self.stop_button.configure(state="disabled")
            self.status_var.set("Stopping... waiting for in-flight requests to finish.")

    def _run_scan_worker(self, active_sources, total_configured):
        """
        Runs on a background thread. MUST NOT touch any Tkinter widget
        directly -- progress and results are only ever handed back via
        event_queue, which the main thread drains in _poll_queues().
        """

        def on_source_done(completed, total, url, result):
            self.event_queue.put(("source_done", completed, total, url, result))

        report = run_full_scan(
            active_sources,
            total_configured,
            progress_callback=on_source_done,
            cancel_event=self.cancel_event,
        )

        try:
            ensure_output_dir("output")
            save_json_report(report, OUTPUT_REPORT_PATH)
        except OSError as e:
            report["scan_metadata"]["write_error"] = str(e)

        self.event_queue.put(("scan_done", report))

    # -------------------------------------------------------------------
    # Queue polling -- the ONLY place background-thread data reaches the UI
    # -------------------------------------------------------------------
    def _poll_queues(self):
        try:
            while True:
                level, line = self.log_queue.get_nowait()
                self._append_log(level, line)
        except queue.Empty:
            pass

        try:
            while True:
                event = self.event_queue.get_nowait()
                if event[0] == "source_done":
                    _, completed, total, url, result = event
                    self._on_source_done(completed, total, url, result)
                elif event[0] == "scan_done":
                    self._on_scan_complete(event[1])
        except queue.Empty:
            pass

        self.root.after(100, self._poll_queues)

    def _on_source_done(self, completed, total, url, result):
        """Update the progress bar and add this source's result row as soon
        as it finishes, instead of making the user wait for the whole scan."""
        self.progress.configure(maximum=total, value=completed)
        if not self.cancel_event.is_set():
            self.status_var.set(f"Scanning... {completed}/{total} sources done.")

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

    def _on_scan_complete(self, report):
        self.last_report = report
        self.run_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

        meta = report["scan_metadata"]
        self.status_var.set("Scan cancelled." if meta.get("cancelled") else "Scan complete.")

        write_note = ""
        if meta.get("write_error"):
            write_note = f"  |  \u26a0 Could not save report: {meta['write_error']}"
        self.summary_var.set(
            f"Sources: {meta['sources_succeeded']} succeeded / {meta['sources_failed']} failed   |   "
            f"Unique IOCs: {meta['total_unique_iocs']} "
            f"({meta.get('total_unique_ipv4', 0)} IPv4, {meta.get('total_unique_sha256', 0)} SHA256)   |   "
            f"Report: {OUTPUT_REPORT_PATH}{write_note}"
        )

        self.ioc_rows = []
        for ioc, sources_found_on in report["ioc_to_source_mapping"].items():
            ioc_type = "SHA256" if len(ioc) == 64 else "IPv4"
            self.ioc_rows.append((ioc, ioc_type, ", ".join(sources_found_on)))
        self._refresh_ioc_tree()

    # -------------------------------------------------------------------
    # IOC tab: filtering, clipboard, export
    # -------------------------------------------------------------------
    def _refresh_ioc_tree(self):
        """Re-render the IOC table from self.ioc_rows through the current
        search text and type filter."""
        needle = self.ioc_search_var.get().strip().lower()
        type_filter = self.ioc_type_var.get()

        self.ioc_tree.delete(*self.ioc_tree.get_children())
        shown = 0
        for ioc, ioc_type, sources in self.ioc_rows:
            if type_filter != "All" and ioc_type != type_filter:
                continue
            if needle and needle not in ioc.lower() and needle not in sources.lower():
                continue
            self.ioc_tree.insert("", "end", values=(ioc, ioc_type, sources))
            shown += 1

        total = len(self.ioc_rows)
        self.ioc_count_var.set(f"{shown} of {total} shown" if total else "")

    def _show_ioc_menu(self, event):
        item = self.ioc_tree.identify_row(event.y)
        if item:
            if item not in self.ioc_tree.selection():
                self.ioc_tree.selection_set(item)
            self.ioc_menu.tk_popup(event.x_root, event.y_root)

    def _copy_selected_iocs(self, full_row=False):
        selection = self.ioc_tree.selection()
        if not selection:
            self.status_var.set("Nothing selected to copy.")
            return
        lines = []
        for item in selection:
            ioc, ioc_type, sources = self.ioc_tree.item(item, "values")
            lines.append(f"{ioc}\t{ioc_type}\t{sources}" if full_row else ioc)
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self.status_var.set(f"Copied {len(lines)} indicator(s) to clipboard.")

    def _export_iocs(self):
        """Export the currently *visible* (filtered) IOC rows to CSV or a
        plain-text list of indicators, chosen by file extension."""
        items = self.ioc_tree.get_children()
        if not items:
            messagebox.showinfo("Nothing to export", "Run a scan first -- there are no IOCs to export.")
            return

        path = filedialog.asksaveasfilename(
            title="Export IOCs",
            defaultextension=".csv",
            filetypes=[("CSV (indicator, type, sources)", "*.csv"), ("Plain text (one indicator per line)", "*.txt")],
            initialfile="iocs.csv",
        )
        if not path:
            return

        try:
            if path.lower().endswith(".txt"):
                with open(path, "w", encoding="utf-8") as f:
                    for item in items:
                        f.write(self.ioc_tree.item(item, "values")[0] + "\n")
            else:
                with open(path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["indicator", "type", "sources"])
                    for item in items:
                        writer.writerow(self.ioc_tree.item(item, "values"))
            self.status_var.set(f"Exported {len(items)} IOC(s) to {path}.")
        except OSError as e:
            messagebox.showerror("Export failed", str(e))

    # -------------------------------------------------------------------
    # Small helpers
    # -------------------------------------------------------------------
    def _append_log(self, level, line):
        self.log_text.configure(state="normal")
        tags = (level,) if level in ("WARNING", "ERROR", "CRITICAL") else ()
        self.log_text.insert("end", line + "\n", tags)
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

    def _on_close(self):
        if self.dirty:
            answer = messagebox.askyesnocancel(
                "Unsaved changes",
                f"You have unsaved changes to your sources.\n\nSave them to {SOURCES_CONFIG_PATH} before exiting?",
            )
            if answer is None:
                return  # Cancel: keep the window open
            if answer:
                self._save_sources()
                if self.dirty:
                    return  # save failed -- don't lose the user's edits
        self.root.destroy()


def main():
    root = tk.Tk()
    ThreatIntelGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
