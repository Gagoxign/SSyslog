"""
View: Tkinter widgets only. No parsing/server/socket logic lives here.
All user actions are delegated to a controller supplied at construction time.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from syslog_model import default_ip, default_port


class SyslogView:
    COLUMNS = (
        "timestamp",
        "source_ip",
        "hostname",
        "app_name",
        "procid",
        "protocol",
        "pri",
        "facility",
        "severity",
        "msgid",
        "structured_data",
        "message",
    )

    COL_HEADERS = {
        "timestamp": "Timestamp",
        "source_ip": "Source IP",
        "hostname": "Host",
        "app_name": "App",
        "procid": "ProcID",
        "protocol": "Proto",
        "pri": "PRI",
        "facility": "Facility",
        "severity": "Severity",
        "msgid": "MsgID",
        "structured_data": "Structured Data",
        "message": "Message",
    }

    # Solarized Light theme palette
    BG = "#fdf6e3"
    BG_ALT = "#eee8d5"
    FG = "#586e75"
    ACCENT = "#268bd2"
    ACCENT_ACTIVE = "#2aa198"
    ACCENT_PRESSED = "#1a6591"
    SELECT_BG = "#93a1a1"
    ROW_ODD = "#eee8d5"
    ROW_EVEN = "#fdf6e3"

    def __init__(self, root, controller):
        self.root = root
        self.controller = controller
        self.root.title("Durian - Advanced SysLog Server")
        #self.root.iconbitmap("C:\\Users\\SESA656956\\Documents\\others\\syslog\\durian.ico")

        self.apply_theme()

        # Top controls frame
        top = ttk.Frame(root, padding=8)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(4, weight=1)

        ttk.Label(top, text="Listen IP:").grid(row=0, column=0, sticky="w", padx=(0,6))
        self.ip_var = tk.StringVar(value=default_ip)
        self.ip_entry = ttk.Entry(top, textvariable=self.ip_var, width=15)
        self.ip_entry.grid(row=0, column=1, sticky="w")

        ttk.Label(top, text="Port:").grid(row=0, column=2, sticky="w", padx=(12,6))
        self.port_var = tk.StringVar(value=default_port)  # non-privileged default
        self.port_entry = ttk.Entry(top, textvariable=self.port_var, width=8)
        self.port_entry.grid(row=0, column=3, sticky="w")

        self.start_btn = ttk.Button(top, text="Start Server", command=self.controller.start_server)
        self.start_btn.grid(row=0, column=5, padx=(12,6))
        self.stop_btn = ttk.Button(top, text="Stop Server", command=self.controller.stop_server, state="disabled")
        self.stop_btn.grid(row=0, column=6)

        self.clear_btn = ttk.Button(top, text="Clear Table", command=self.controller.clear_table)
        self.clear_btn.grid(row=0, column=7, padx=(12,0))

        # TLS controls frame
        tls = ttk.Frame(root, padding=(8, 0, 8, 8))
        tls.grid(row=1, column=0, sticky="ew")
        tls.columnconfigure(5, weight=1)

        self.tls_var = tk.BooleanVar(value=False)
        self.tls_check = ttk.Checkbutton(
            tls, text="Enable TLS", variable=self.tls_var, command=self.controller.on_tls_toggle
        )
        self.tls_check.grid(row=0, column=0, sticky="w")

        self.mtls_var = tk.BooleanVar(value=False)
        self.mtls_check = ttk.Checkbutton(
            tls, text="Require Mutual TLS (client cert)", variable=self.mtls_var,
            command=self.controller.on_mtls_toggle, state="disabled"
        )
        self.mtls_check.grid(row=0, column=1, sticky="w", padx=(12, 0))

        ttk.Label(tls, text="Certificate:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.cert_var = tk.StringVar(value="")
        self.cert_entry = ttk.Entry(tls, textvariable=self.cert_var, width=30, state="disabled")
        self.cert_entry.grid(row=1, column=1, sticky="w", pady=(6, 0))
        self.cert_btn = ttk.Button(tls, text="Browse...", command=self.controller.browse_cert, state="disabled")
        self.cert_btn.grid(row=1, column=2, sticky="w", padx=(6, 0), pady=(6, 0))

        ttk.Label(tls, text="Key:").grid(row=1, column=3, sticky="w", padx=(12, 0), pady=(6, 0))
        self.key_var = tk.StringVar(value="")
        self.key_entry = ttk.Entry(tls, textvariable=self.key_var, width=30, state="disabled")
        self.key_entry.grid(row=1, column=4, sticky="w", pady=(6, 0))
        self.key_btn = ttk.Button(tls, text="Browse...", command=self.controller.browse_key, state="disabled")
        self.key_btn.grid(row=1, column=5, sticky="w", padx=(6, 0), pady=(6, 0))

        ttk.Label(tls, text="Client Cert (mutual TLS):").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.ca_var = tk.StringVar(value="")
        self.ca_entry = ttk.Entry(tls, textvariable=self.ca_var, width=30, state="disabled")
        self.ca_entry.grid(row=2, column=1, sticky="w", pady=(6, 0))
        self.ca_btn = ttk.Button(tls, text="Browse...", command=self.controller.browse_ca, state="disabled")
        self.ca_btn.grid(row=2, column=2, sticky="w", padx=(6, 0), pady=(6, 0))

        # Table (Treeview)
        table_frame = ttk.Frame(root, padding=(8, 0, 8, 8))
        table_frame.grid(row=2, column=0, sticky="nsew")
        root.rowconfigure(2, weight=1)
        root.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            table_frame,
            columns=self.COLUMNS,
            show="headings",
            height=20
        )
        # Configure headings & columns
        for col in self.COLUMNS:
            self.tree.heading(col, text=self.COL_HEADERS[col], command=lambda c=col: self.controller.sort_by_column(c))
            # Reasonable default widths; adjust as you like
            width = {
                "timestamp": 150,
                "source_ip": 80,
                "hostname": 80,
                "app_name": 90,
                "procid": 50,
                "protocol": 60,
                "pri": 30,
                "facility": 30,
                "severity": 30,
                "msgid": 150,
                "structured_data": 400,
                "message": 200,
            }.get(col, 120)
            self.tree.column(col, width=width, anchor="w", stretch=True)

        self.tree.tag_configure("oddrow", background=self.ROW_ODD)
        self.tree.tag_configure("evenrow", background=self.ROW_EVEN)

        # Scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

    def apply_theme(self):
        self.root.configure(bg=self.BG)
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(".", background=self.BG, foreground=self.FG,
                        fieldbackground=self.BG_ALT, bordercolor=self.BG_ALT,
                        darkcolor=self.BG_ALT, lightcolor=self.BG_ALT)
        style.configure("TFrame", background=self.BG)
        style.configure("TLabel", background=self.BG, foreground=self.FG)
        style.configure("TButton", background=self.ACCENT, foreground="#ffffff",
                        bordercolor=self.ACCENT_PRESSED, borderwidth=2, relief="raised",
                        focusthickness=2, focuscolor=self.ACCENT_PRESSED, padding=(10, 6),
                        font=("Segoe UI", 9, "bold"))
        style.map("TButton",
                  background=[("disabled", "#93a1a1"), ("pressed", self.ACCENT_PRESSED),
                              ("active", self.ACCENT_ACTIVE)],
                  bordercolor=[("disabled", "#93a1a1"), ("pressed", self.ACCENT_PRESSED),
                               ("active", self.ACCENT_ACTIVE)],
                  relief=[("pressed", "sunken"), ("!pressed", "raised")],
                  foreground=[("disabled", "#eee8d5")])
        style.configure("TEntry", fieldbackground=self.BG_ALT, foreground=self.FG,
                        insertcolor=self.FG, bordercolor=self.BG_ALT, borderwidth=2,
                        lightcolor=self.BG_ALT, darkcolor=self.BG_ALT)
        style.map("TEntry",
                  fieldbackground=[("focus", "#ffffff")],
                  bordercolor=[("focus", self.ACCENT)],
                  lightcolor=[("focus", self.ACCENT)],
                  darkcolor=[("focus", self.ACCENT)])
        style.configure("Treeview", background=self.BG_ALT, fieldbackground=self.BG_ALT,
                        foreground=self.FG, rowheight=22, borderwidth=0)
        style.map("Treeview", background=[("selected", self.SELECT_BG)],
                  foreground=[("selected", "#fdf6e3")])
        style.configure("Treeview.Heading", background=self.ACCENT, foreground="#ffffff",
                        relief="flat")
        style.map("Treeview.Heading", background=[("active", self.ACCENT_ACTIVE)])
        style.configure("Vertical.TScrollbar", background=self.BG_ALT, troughcolor=self.BG,
                        bordercolor=self.BG, arrowcolor=self.FG)
        style.configure("Horizontal.TScrollbar", background=self.BG_ALT, troughcolor=self.BG,
                        bordercolor=self.BG, arrowcolor=self.FG)

    # ------------------------------------------------------------------
    # Pure-UI helpers (no business logic); called by the controller.
    # ------------------------------------------------------------------
    def set_tls_fields_state(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.cert_entry.config(state=state)
        self.cert_btn.config(state=state)
        self.key_entry.config(state=state)
        self.key_btn.config(state=state)
        self.mtls_check.config(state=state)

    def set_mtls_fields_state(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.ca_entry.config(state=state)
        self.ca_btn.config(state=state)

    def ask_open_file(self, title, filetypes):
        return filedialog.askopenfilename(title=title, filetypes=filetypes)

    def show_error(self, title, message):
        messagebox.showerror(title, message)

    def show_info(self, title, message):
        messagebox.showinfo(title, message)

    def show_warning(self, title, message):
        messagebox.showwarning(title, message)

    def set_server_running_state(self, running: bool):
        self.start_btn.config(state="disabled" if running else "normal")
        self.stop_btn.config(state="normal" if running else "disabled")
        self.tls_check.config(state="disabled" if running else "normal")

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def add_info_row(self, text: str):
        row = {
            "timestamp": "",
            "source_ip": "",
            "hostname": "",
            "app_name": "",
            "procid": "",
            "protocol": "INFO",
            "pri": "",
            "facility": "",
            "severity": "",
            "msgid": "",
            "structured_data": "",
            "message": text,
        }
        self.insert_data_row(row)

    def insert_data_row(self, row: dict):
        values = [row.get(col, "") for col in self.COLUMNS]
        self._insert_row(values)

    def _insert_row(self, values):
        row_count = len(self.tree.get_children())
        tag = "evenrow" if row_count % 2 == 0 else "oddrow"
        self.tree.insert("", "end", values=values, tags=(tag,))

    def sort_column(self, col, descending: bool):
        """
        Reorder tree rows by column value; attempts numeric sort when possible.
        Lets any exception (e.g. comparing incompatible types) propagate so the
        controller can report it as an internal error.
        """
        data = []
        for iid in self.tree.get_children(""):
            values = self.tree.item(iid, "values")
            col_index = self.COLUMNS.index(col)
            cell = values[col_index]
            # Try numeric comparison, fallback to string
            try:
                key = float(cell)
            except (ValueError, TypeError):
                key = cell
            data.append((key, iid))

        data.sort(reverse=descending)
        for index, (_, iid) in enumerate(data):
            self.tree.move(iid, "", index)

    def set_sort_indicator(self, active_col, descending: bool):
        """Mark which column heading is the active sort with an arrow; clear the rest."""
        arrow = " \u25bc" if descending else " \u25b2"
        for col in self.COLUMNS:
            text = self.COL_HEADERS[col] + (arrow if col == active_col else "")
            self.tree.heading(col, text=text)
