import argparse
import ssl
import socket
import sys


def check_tls(server, ca_cert, sni, alpn):
    try:
        host, port = server.split(":")
        port = int(port)

        if ca_cert:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert)
            context.check_hostname = sni is not None
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        if alpn:
            context.set_alpn_protocols([p for p in alpn.split(",")])

        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                # Verify handshake and certificate
                print(f'Connected to {ssock.version()} using {ssock.cipher()}')
                print(f'Server certificate validated and details: {ssock.getpeercert()}')
                print("OK")
                return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1


def main():
    parser = argparse.ArgumentParser(description="Test TLS Server")
    parser.add_argument("--server", required=True,
                        help="Server address to test (e.g., 127.1.2.3:8443)")
    parser.add_argument("--ca", required=False, default=None,
                        help="CA certificate file used to validate the server certificate"
                        "Omit to use insecure connection")
    parser.add_argument("--sni", required=False, default=None,
                        help="SNI to send in ClientHello")
    parser.add_argument("--alpn", required=False, default='h2',
                        help="ALPN to send in ClientHello")

    args = parser.parse_args()

    exit_status = check_tls(
        server=args.server,
        ca_cert=args.ca,
        sni=args.sni,
        alpn=args.alpn)

    sys.exit(exit_status)


if __name__ == "__main__":
    main()
