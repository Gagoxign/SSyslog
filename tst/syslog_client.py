"""Send RFC 5424 syslog messages over TLS (RFC 5425)."""

import argparse
import datetime as dt
import socket
import ssl
import sys


def build_syslog_message(message, hostname, app_name, facility, severity):
    pri = facility * 8 + severity
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return f"<{pri}>1 {timestamp} {hostname} {app_name} - - - {message}\n".encode("utf-8")


def create_tls_context(server_cert, client_cert=None, client_key=None):
    if not server_cert:
        raise ValueError("A CA certificate is required to verify the syslog server.")

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    if client_cert or client_key:
        if not client_cert or not client_key:
            raise ValueError("mTLS requires both --client-cert and --client-key.")
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    return context


def send_syslog_message(host, port, server_name, payload, context):
    with socket.create_connection((host, port), timeout=10) as connection:
        if context is not None:
            with context.wrap_socket(connection, server_hostname=server_name) as tls_connection:
                tls_connection.sendall(payload)
                print(
                    f"Sent {len(payload)} bytes to {host}:{port} using "
                    f"{tls_connection.version()} ({tls_connection.cipher()[0]})."
                )
                try:
                    # Tell the server the session is done with a TLS close_notify,
                    # instead of abruptly closing (which can trigger a TCP RST).
                    tls_connection.unwrap()
                except (ssl.SSLError, OSError):
                    pass
        else:
            connection.sendall(payload)
            print(f"Sent {len(payload)} bytes to {host}:{port} without TLS.")


def parse_arguments():
    parser = argparse.ArgumentParser(description="Secure syslog client using TLS.")
    parser.add_argument("host", help="Syslog server IP address or hostname")
    parser.add_argument("message", help="Syslog message to send")
    parser.add_argument("--port", type=int, default=6514, help="TLS syslog port (default: 6514)")
    parser.add_argument("--server-cert", help="Certificate file of the syslog server in PEM format")
    parser.add_argument("--client-cert", help="Client certificate in PEM format for mutual TLS")
    parser.add_argument("--client-key", help="Client private key in PEM format for mutual TLS")
    parser.add_argument("--hostname", default=socket.gethostname(), help="RFC 5424 hostname field")
    parser.add_argument("--app-name", default="secure-syslog-client", help="RFC 5424 application name")
    parser.add_argument("--facility", type=int, default=1, choices=range(24), help="Syslog facility 0-23")
    parser.add_argument("--severity", type=int, default=6, choices=range(8), help="Syslog severity 0-7")
    return parser.parse_args()


def main():
    args = parse_arguments()
    try:
        if args.server_cert is None and args.client_cert is None and args.client_key is None:
            context = None
        else:
            context = create_tls_context(args.server_cert, args.client_cert, args.client_key)
        payload = build_syslog_message(
            args.message,
            args.hostname,
            args.app_name,
            args.facility,
            args.severity,
        )
        send_syslog_message(args.host, args.port, args.host, payload, context)
    except (OSError, ssl.SSLError, ValueError) as error:
        print(f"Secure syslog send failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())