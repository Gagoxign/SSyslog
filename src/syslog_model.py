"""
Model: syslog message parsing, the threaded TCP/TLS server, and server
lifecycle/state management. No UI code (no tkinter) lives here.
"""
import re
import socketserver
import ssl
import threading
import queue

# ============================
# Default parameters
# ============================
default_ip = "172.16.14.15"
default_port = 6514


# ============================
# Syslog Parsing (RFC 5424 + RFC 3164)
# ============================
RFC5424_RE = re.compile(
    r'^<(?P<pri>\d{1,3})>'
    r'(?P<version>\d+)\s+'
    r'(?P<ts>\S+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<app>\S+)\s+'
    r'(?P<proc>\S+)\s+'
    r'(?P<msgid>\S+)\s+'
    r'(?P<sd>-|\[.*?\](?:\s*\[.*?\])*)\s*'
    r'(?P<msg>.*)$',
    re.DOTALL
)

RFC3164_RE = re.compile(
    r'^<(?P<pri>\d{1,3})>'
    r'(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<tag>[^:\s]+)'
    r'(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<msg>.*)$',
    re.DOTALL
)

def parse_pri(pri: int):
    return pri // 8, pri % 8  # facility, severity

def parse_syslog_bytes(b: bytes):
    """
    Try to parse bytes as RFC 5424; if not, as RFC 3164.
    Returns dict with normalized keys or None if not parseable.
    """
    s = b.decode("utf-8", errors="replace").strip()
    if not s:
        return None

    m = RFC5424_RE.match(s)
    if m:
        d = m.groupdict()
        pri = int(d["pri"])
        facility, severity = parse_pri(pri)
        return {
            "protocol": "RFC5424",
            "pri": str(pri),
            "facility": str(facility),
            "severity": str(severity),
            "version": d["version"],
            "timestamp": d["ts"],
            "hostname": d["host"],
            "app_name": d["app"] if d["app"] != "-" else "",
            "procid": d["proc"] if d["proc"] != "-" else "",
            "msgid": d["msgid"] if d["msgid"] != "-" else "",
            "structured_data": "" if d["sd"] == "-" else d["sd"],
            "message": d["msg"] or "",
            "raw": s,
        }

    m = RFC3164_RE.match(s)
    if m:
        d = m.groupdict()
        pri = int(d["pri"])
        facility, severity = parse_pri(pri)
        return {
            "protocol": "RFC3164",
            "pri": str(pri),
            "facility": str(facility),
            "severity": str(severity),
            "version": "",
            "timestamp": d["ts"],
            "hostname": d["host"],
            "app_name": d.get("tag") or "",
            "procid": d.get("pid") or "",
            "msgid": "",
            "structured_data": "",
            "message": d.get("msg") or "",
            "raw": s,
        }

    return None


def _error_row(source_ip: str, message: str):
    """Build a GUI-queue row reporting a connection/TLS error so failures are visible."""
    return {
        "protocol": "ERROR",
        "source_ip": source_ip,
        "message": message,
    }


# ============================
# TCP Server + Handler (Threaded)
# ============================
class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True  # Clean thread exit on shutdown
    ssl_context = None  # set to an ssl.SSLContext to serve syslog over TLS

    def finish_request(self, request, client_address):
        # Do the (blocking) TLS handshake here, inside the per-connection thread
        # spawned by ThreadingMixIn, instead of in get_request()/the accept loop.
        # Otherwise one slow/failed handshake stalls acceptance of every other
        # client, which can make their connections get aborted (WinError 10053).
        if self.ssl_context is not None:
            try:
                request = self.ssl_context.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError) as e:
                self.gui_queue.put(_error_row(client_address[0], f"TLS handshake failed: {e}"))
                return  # drop failed handshake; caller still closes the raw socket
        self.RequestHandlerClass(request, client_address, self)

class SyslogTCPHandler(socketserver.BaseRequestHandler):
    """
    Reads a chunk from the TCP stream and posts a parsed record to the GUI queue.
    Note: Some senders use RFC 6587 octet-counting; for that, you'd add a framing
    layer to split the stream. This demo reads per-recv; many devices send one
    message per write() which works fine in practice.
    """
    def handle(self):
        try:
            data = self.request.recv(8192)
        except OSError as e:
            # Covers ConnectionResetError/ConnectionAbortedError, ssl.SSLError,
            # and other socket-level errors (e.g. abrupt disconnect, bad TLS handshake).
            self.server.gui_queue.put(_error_row(self.client_address[0], f"Read failed: {e}"))
            return

        if not data:
            return

        parsed = parse_syslog_bytes(data)
        if parsed:
            # Add the source IP for display
            parsed["source_ip"] = self.client_address[0]
            # Send to GUI through the thread-safe queue
            self.server.gui_queue.put(parsed)

        try:
            # Drain the client's closing TLS alert (close_notify) so it completes
            # its graceful shutdown instead of seeing the connection reset.
            self.request.recv(8192)
        except OSError:
            pass


# ============================
# Server lifecycle/state model
# ============================
class SyslogServerModel:
    """Owns the server instance, its thread, and the queue of parsed rows."""

    def __init__(self):
        self.server = None
        self.server_thread = None
        self.gui_queue = queue.Queue()

    def is_running(self) -> bool:
        return self.server is not None

    def build_ssl_context(self, tls_enabled, certfile, keyfile, mtls_enabled, ca_file):
        """Returns (context, error_message). context is None when TLS is disabled."""
        if not tls_enabled:
            return None, None

        certfile = (certfile or "").strip()
        keyfile = (keyfile or "").strip()
        if not certfile or not keyfile:
            return None, "Certificate and key files are required to enable TLS."

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            # Disable TLS 1.3 post-handshake session tickets: one-shot clients that
            # send-and-close without reading them can leave unread data in their
            # receive buffer, causing the OS to send a RST (WinError 10053 on Windows)
            # instead of a graceful FIN.
            # context.num_tickets = 0
            if mtls_enabled:
                ca_file = (ca_file or "").strip()
                if not ca_file:
                    return None, (
                        "Mutual TLS requires the client's certificate file "
                        "(a self-signed client cert works: it is trusted directly)."
                    )
                # A self-signed client cert can be loaded directly as its own trust anchor.
                context.load_verify_locations(cafile=ca_file)
                context.verify_mode = ssl.CERT_REQUIRED
            else:
                context.verify_mode = ssl.CERT_NONE
        except ssl.SSLError as e:
            return None, f"Failed to load certificate/key:\n\n{e}"
        except OSError as e:
            return None, f"Cannot read certificate/key/CA file:\n\n{e}"

        return context, None

    def start_server(self, ip: str, port: int, ssl_context):
        """Returns an error message on failure, or None on success."""
        if self.server:
            return "Server is already running."

        try:
            self.server = ThreadedTCPServer((ip, port), SyslogTCPHandler)
            self.server.ssl_context = ssl_context
            self.server.gui_queue = self.gui_queue  # inject queue so handlers can post rows
        except OSError as e:
            self.server = None
            return f"Cannot start server on {ip}:{port}\n\n{e}"

        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        return None

    def stop_server(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            finally:
                self.server = None
                self.server_thread = None

    def drain_queue(self):
        """Return all rows currently queued, without blocking."""
        rows = []
        try:
            while True:
                rows.append(self.gui_queue.get_nowait())
        except queue.Empty:
            pass
        return rows
