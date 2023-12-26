import datetime
import hashlib
from typing import Tuple, List
import contextlib
import base64
from typing import Any, Callable, Optional
import threading
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import logging
import jwt
from cryptography.hazmat.backends import default_backend
import logging

log = logging.getLogger(__name__)

class UnknownSSHPubkeyType(Exception):
    def __init__(self, pubkey):
        self.pubkey = pubkey

    def __str__(self):
        return f"unknown signing method: {type(self.pubkey)}"


# copied from "net/http/internal/ascii"
# EqualFold is strings.EqualFold, ASCII only. It reports whether s and t
# are equal, ASCII-case-insensitively.
def equal_fold(s: str, t: str) -> bool:
    if len(s) != len(t):
        return False
    for i in range(len(s)):
        if lower(s[i]) != lower(t[i]):
            return False
    return True


# lower returns the ASCII lowercase version of b.
def lower(b: bytes) -> bytes:
    if b.isascii() and b.isupper():
        return bytes([b[i] + (ord('a') - ord('A')) for i in range(len(b))])
    return b


def configure_logger(log_level: str) -> None:
    log_level = log_level.lower()
    if log_level == "debug":
        logging.log_level = logging.DEBUG
    elif log_level == "info":
        logging.log_level = logging.INFO
    elif log_level == "warning":
        logging.log_level = logging.WARN
    elif log_level == "error":
        logging.log_level = logging.ERROR
    else:
        logging.log_level = logging.WARN


class AcceptQueue:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.c = threading.Condition(self.lock)
        self.queue: List = []

    def add(self, item) -> None:
        with self.lock:
            self.queue.append(item)
            self.c.notify()

    def next(self):
        with self.lock:
            while not self.queue:
                self.c.wait()
            return self.queue.pop(0)

    def chan(self) -> threading.Condition:
        return self.c


class DatagramsQueue:
    def __init__(self, maxlen: int) -> None:
        self.c = threading.Condition()
        self.queue: List[bytes] = []
        self.maxlen = maxlen

    def add(self, datagram: bytes) -> bool:
        with self.c:
            if len(self.queue) >= self.maxlen:
                return False
            self.queue.append(datagram)
            self.c.notify()
            return True

    def wait_add(self, ctx: contextlib.AbstractContextManager, datagram: bytes) -> Optional[Exception]:
        with self.c:
            if len(self.queue) >= self.maxlen:
                return Exception("queue full")
            self.queue.append(datagram)
            self.c.notify()
            return None

    def next(self) -> Optional[bytes]:
        with self.c:
            if not self.queue:
                return None
            return self.queue.pop(0)

    def wait_next(self, ctx: contextlib.AbstractContextManager) -> Optional[bytes]:
        with self.c:
            while not self.queue:
                if ctx.exception() is not None:
                    return None
                self.c.wait()
            return self.queue.pop(0)


def jwt_signing_method_from_crypto_pubkey(pubkey) -> Tuple[str, Exception]:
    try:
        if isinstance(pubkey, rsa.RSAPublicKey):
            return "RS256", None
        elif isinstance(pubkey, Ed25519PublicKey):
            return "EdDSA", None
        else:
            return None, UnknownSSHPubkeyType(pubkey)
    except Exception as e:
        return None, e


def sha256_fingerprint(in_bytes: bytes) -> str:
    sha256_hash = hashlib.sha256()
    sha256_hash.update(in_bytes)
    return base64.b64encode(sha256_hash.digest()).decode('utf-8')

# def get_san_extension(cert_pem):
#     # Load the certificate from PEM format
#     cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

#     # Look for the Subject Alternative Name extension
#     try:
#         san_extension = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
#         return san_extension.value
#     except x509.ExtensionNotFound:
#         return None

# def for_each_san(der: bytes, callback: Callable[[int, bytes], Exception]) -> Optional[Exception]:
#     try:
#         idx = 0
#         der_len = len(der)
#         while idx < der_len:
#             tag = int(der[idx])
#             idx += 1
#             length = int(der[idx:idx + 2])
#             idx += 2
#             if idx + length > der_len:
#                 raise ValueError("x509: invalid subject alternative name")
#             data = der[idx:idx + length]
#             idx += length
#             err = callback(tag, data)
#             if err is not None:
#                 return err
#         return None
#     except Exception as e:
#         return e

# def cert_has_ip_sans(cert: x509.Certificate) -> Tuple[bool, Optional[Exception]]:
#     SANExtension = get_san_extension(cert)
#     if SANExtension is None:
#         return False, None

#     name_type_ip = 7
#     ip_addresses = []

#     def callback(tag: int, data: bytes) -> Optional[Exception]:
#         if tag == name_type_ip:
#             if len(data) == 4 or len(data) == 16:
#                 ip_addresses.append(data)
#             else:
#                 return ValueError(f"x509: cannot parse IP address of length {len(data)}")
#         return None

#     err = for_each_san(SANExtension, callback)
#     if err is not None:
#         return False, err

#     return len(ip_addresses) > 0, None

def cert_has_ip_sans(cert_pem):
    # Load the certificate from PEM format
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

    # Extract SAN extension
    try:
        san_extension = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound as e:
        log.error(f"could not find SAN extension in certificate: {e}")
        return False, e

    # Check for IP addresses in the SANs
    ip_addresses = [general_name for general_name in san_extension.value
                    if isinstance(general_name, x509.IPAddress)]
    
    return len(ip_addresses) > 0, None


def generate_key() -> Tuple[Ed25519PublicKey, Ed25519PrivateKey, Optional[Exception]]:
    try:
        private_key = Ed25519PrivateKey.generate()
        signature = private_key.sign(b"my authenticated message") # TODO
        public_key  = private_key.public_key()
        # public_key.verify(signature, b"my authenticated message")
        return public_key, private_key, None
    except Exception as e:
        log.error(f"could not generate key: {e}")
        return None, None, e


def generate_cert(priv: Ed25519PrivateKey) -> Tuple[x509.Certificate, Optional[Exception]]:
    try:
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSH3Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "elniak.com"),

        ])
        cert = x509.CertificateBuilder(
                ).subject_name(
                    subject
                ).issuer_name(
                    issuer
                ).public_key(
                    priv.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    datetime.datetime.now(datetime.timezone.utc)
                ).not_valid_after(
                    # Our certificate will be valid for 10 days
                    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
                ).add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("*"), x509.DNSName("selfsigned.ssh3")]),
                    critical=False,
                    # Sign our certificate with our private key
                ).add_extension(
                    x509.BasicConstraints(ca=True, path_length=None), 
                    critical=True,
                ).add_extension(
                    x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=True,
                                  key_agreement=False, content_commitment=False, data_encipherment=False,
                                  crl_sign=False, encipher_only=False, decipher_only=False), 
                    critical=True,
                ).add_extension(
                    x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), 
                    critical=True,
                )
        
        return cert, None
    except Exception as e:
        log.error(f"could not generate cert: {e}")
        return None, e

def dump_cert_and_key_to_files(cert: x509.Certificate, priv: Ed25519PrivateKey, cert_file: str, key_file: str) -> Optional[Exception]:
    log.info(f"dumping cert to {cert_file} and key to {key_file}")
    try:
        pem = cert.sign(priv, None).public_bytes(encoding=serialization.Encoding.PEM)
        with open(cert_file, "wb") as f:
            f.write(pem)
    except Exception as e:
        log.error(f"could not dump cert to file: {e}")
        return e
    
    try:
        # Now we want to generate a cert from that root
        # TODO check if this is correct
        key_byte = priv.private_bytes(encoding=serialization.Encoding.PEM, 
                                     format=serialization.PrivateFormat.PKCS8, 
                                     encryption_algorithm=serialization.NoEncryption())
        with open(key_file, "wb") as f:
            f.write(key_byte)
    except Exception as e:
        log.error(f"could not dump key to file: {e}")
        return e
    
def parse_ssh_string(buf):
    """ Parses an SSH formatted string from the buffer. """
    length = int.from_bytes(buf.read(4), byteorder='big')
    return buf.read(length).decode('utf-8')

def var_int_len(value):
    """ Calculates the length of a variable integer. """
    if value <= 0xFF:
        return 1
    elif value <= 0xFFFF:
        return 2
    elif value <= 0xFFFFFFFF:
        return 4
    else:
        return 8

def var_int_to_bytes(value):
    """ Converts a variable integer to bytes. """
    if value <= 0xFF:
        return value.to_bytes(1, byteorder='big')
    elif value <= 0xFFFF:
        return value.to_bytes(2, byteorder='big')
    elif value <= 0xFFFFFFFF:
        return value.to_bytes(4, byteorder='big')
    else:
        return value.to_bytes(8, byteorder='big')

def read_var_int(buf):
    """ Reads a variable-length integer from the buffer. """
    first_byte = buf.read(1)[0]
    if first_byte <= 0xFF:
        return first_byte
    elif first_byte <= 0xFFFF:
        return int.from_bytes(buf.read(1), byteorder='big', signed=False) + (first_byte << 8)
    elif first_byte <= 0xFFFFFFFF:
        return int.from_bytes(buf.read(3), byteorder='big', signed=False) + (first_byte << 24)
    else:
        return int.from_bytes(buf.read(7), byteorder='big', signed=False) + (first_byte << 56)

def write_ssh_string(buf, value):
    """ Writes an SSH formatted string into the buffer. """
    encoded_value = value.encode('utf-8')
    buf.extend(len(encoded_value).to_bytes(4, byteorder='big'))
    buf.extend(encoded_value)
    return len(encoded_value) + 4

def read_boolean(buf):
    """ Reads a boolean value from the buffer. """
    return buf.read(1)[0] != 0

def ssh_string_len(s):
    # Length of a 32-bit integer in bytes is 4
    int_length = 4
    # Length of the string
    str_length = len(s)
    # Total length is the length of the integer plus the length of the string
    return int_length + str_length