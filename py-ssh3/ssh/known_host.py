import base64
import os
import ssl
from typing import Dict, List, Tuple

class InvalidKnownHost(Exception):
    def __init__(self, line: str):
        self.line = line

    def __str__(self):
        return f"invalid known host line: {self.line}"

def parse_known_hosts(filename: str) -> Tuple[Dict[str, List[ssl.SSLContext]], List[int], Exception]:
    known_hosts = {}
    invalid_lines = []

    if not os.path.exists(filename):
        # The known hosts file simply does not exist yet, so there is no known host
        return known_hosts, invalid_lines, None

    with open(filename, 'r') as file:
        for i, line in enumerate(file):
            known_host = line.strip()
            fields = known_host.split()
            if len(fields) != 3 or fields[1] != "x509-certificate":
                invalid_lines.append(i)
                continue

            try:
                cert_bytes = base64.b64decode(fields[2])
                cert = ssl.DER_cert_to_PEM_cert(cert_bytes)
                if fields[0] not in known_hosts:
                    known_hosts[fields[0]] = []
                known_hosts[fields[0]].append(cert)
            except (base64.binascii.Error, ValueError):
                invalid_lines.append(i)
                continue

    return known_hosts, invalid_lines, None

def append_known_host(filename: str, host: str, cert: ssl.SSLContext) -> Exception:
    encoded_cert = base64.b64encode(cert.public_bytes()).decode('utf-8')

    try:
        with open(filename, 'a') as known_hosts:
            known_hosts.write(f"{host} x509-certificate {encoded_cert}\n")
    except Exception as e:
        return e

    return None
