#!/usr/bin/env python3
"""Inspect a server certificate: python3 sslcheck.py 5.129.242.110.

Dependency: python3 -m pip install cryptography
"""

import argparse
import ipaddress
import socket
import ssl
import sys

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
except ImportError:
    sys.exit("Установите зависимость: python3 -m pip install cryptography")


def fetch_certificate(ip, port=443, sni=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Read the certificate even when its name or trust chain does not match.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((str(ip), port), timeout=10) as connection:
        with context.wrap_socket(connection, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der)


def main():
    parser = argparse.ArgumentParser(description="Получить домены из TLS-сертификата по IPv4.")
    parser.add_argument("ip", type=ipaddress.IPv4Address, help="IPv4 сервера")
    parser.add_argument("--port", type=int, default=443, help="TLS-порт (по умолчанию 443)")
    parser.add_argument("--sni", help="имя для SNI; по умолчанию запрос без SNI")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("порт должен быть от 1 до 65535")

    try:
        certificate = fetch_certificate(args.ip, args.port, args.sni)
        common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        try:
            san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            domains = san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            domains = []
    except (OSError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1

    print(f"IP: {args.ip}:{args.port}")
    print(f"SNI: {args.sni or '(none)'}")
    print("CN: " + (", ".join(name.value for name in common_names) or "(none)"))
    print("SAN DNS: " + (", ".join(dict.fromkeys(domains)) or "(none)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
