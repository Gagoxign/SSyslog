"""
Controller: mediates between the SyslogServerModel and SyslogView.
Handles all user actions from the view and pushes model data/state to the view.
"""
import syslog_model
import syslog_view

class SyslogController:
    def __init__(self, model):
        self.model: syslog_model.SyslogServerModel = model
        self.view: syslog_view.SyslogView = None
        self._sort_column = None
        self._sort_descending = False

    def set_view(self, view):
        self.view = view
        self._poll_queue()

    def _poll_queue(self):
        for row in self.model.drain_queue():
            self.view.insert_data_row(row)
        self.view.root.after(100, self._poll_queue)

    def on_tls_toggle(self):
        enabled = self.view.tls_var.get()
        self.view.set_tls_fields_state(enabled)
        if not enabled:
            self.view.mtls_var.set(False)
            self.on_mtls_toggle()

    def on_mtls_toggle(self):
        enabled = self.view.tls_var.get() and self.view.mtls_var.get()
        self.view.set_mtls_fields_state(enabled)

    def browse_cert(self):
        path = self.view.ask_open_file(
            "Select certificate file",
            [("Certificate files", "*.pem *.crt *.der *.cer"), ("All files", "*.*")],
        )
        if path:
            self.view.cert_var.set(path)

    def browse_key(self):
        path = self.view.ask_open_file(
            "Select private key file",
            [("Key files", "*.pem *.key"), ("All files", "*.*")],
        )
        if path:
            self.view.key_var.set(path)

    def browse_ca(self):
        path = self.view.ask_open_file(
            "Select client certificate file",
            [("Certificate files", "*.pem *.crt *.der *.cer"), ("All files", "*.*")],
        )
        if path:
            self.view.ca_var.set(path)

    def start_server(self):
        ip = self.view.ip_var.get().strip()
        try:
            port = int(self.view.port_var.get().strip())
        except ValueError:
            self.view.show_error("Invalid Port", "Port must be an integer.")
            return

        if self.model.is_running():
            self.view.show_info("Already Running", "Server is already running.")
            return

        tls_enabled = self.view.tls_var.get()
        mtls_enabled = self.view.mtls_var.get()
        ssl_context, error = self.model.build_ssl_context(
            tls_enabled,
            self.view.cert_var.get(),
            self.view.key_var.get(),
            mtls_enabled,
            self.view.ca_var.get(),
        )
        if error:
            self.view.show_error("TLS Error", error)
            return

        error = self.model.start_server(ip, port, ssl_context)
        if error:
            self.view.show_error("Server Error", error)
            return

        self.view.set_server_running_state(True)
        if ssl_context is not None:
            mode = "mutual TLS" if mtls_enabled else "TLS"
            self.view.add_info_row(f"Server started on {ip}:{port} ({mode})")
        else:
            self.view.add_info_row(f"Server started on {ip}:{port}")

    def stop_server(self):
        self.model.stop_server()
        self.view.set_server_running_state(False)
        self.view.add_info_row("Server stopped")

    def clear_table(self):
        self.view.clear_table()

    def sort_by_column(self, col):
        descending = (not self._sort_descending) if col == self._sort_column else False
        try:
            self.view.sort_column(col, descending)
        except Exception as e:
            self.view.show_warning(
                "Internal Error",
                f"Sorting failed due to an internal application issue:\n\n{e}",
            )
            return

        self._sort_column = col
        self._sort_descending = descending
        self.view.set_sort_indicator(col, descending)
