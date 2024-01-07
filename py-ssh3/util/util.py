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
    log.debug(f"equal_fold: s={s}, t={t}")
    if len(s) != len(t):
        return False
    for i in range(len(s)):
        if lower(s[i]) != lower(t[i]):
            return False
    return True


# lower returns the ASCII lowercase version of b.
def lower(b: bytes) -> bytes:
    log.debug(f"lower: b={b}")
    if b.isascii() and b.isupper():
        return bytes([b[i] + (ord('a') - ord('A')) for i in range(len(b))])
    return b


def configure_logger(log_level: str) -> None:
    log.debug(f"configure_logger: log_level={log_level}")
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
    logging.basicConfig(level=logging.log_level,format="%(asctime)s %(levelname)s %(name)s %(message)s")


class AcceptQueue:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.c = threading.Condition(self.lock)
        self.queue: List = []

    def add(self, item) -> None:
        log.debug(f"AcceptQueue.add: item={item}")
        with self.lock:
            self.queue.append(item)
            self.c.notify()

    def next(self):
        log.debug("AcceptQueue.next")
        with self.lock:
            while not self.queue:
                self.c.wait()
            return self.queue.pop(0)

    def chan(self) -> threading.Condition:
        log.debug("AcceptQueue.chan")
        return self.c


class DatagramsQueue:
    def __init__(self, maxlen: int) -> None:
        self.c = threading.Condition()
        self.queue: List[bytes] = []
        self.maxlen = maxlen

    def add(self, datagram: bytes) -> bool:
        log.debug(f"DatagramsQueue.add: datagram={datagram}")
        with self.c:
            if len(self.queue) >= self.maxlen:
                return False
            self.queue.append(datagram)
            self.c.notify()
            return True

    def wait_add(self, ctx: contextlib.AbstractContextManager, datagram: bytes) -> Optional[Exception]:
        log.debug(f"DatagramsQueue.wait_add: datagram={datagram}")
        with self.c:
            if len(self.queue) >= self.maxlen:
                return Exception("queue full")
            self.queue.append(datagram)
            self.c.notify()
            return None

    def next(self) -> Optional[bytes]:
        log.debug("DatagramsQueue.next")
        with self.c:
            if not self.queue:
                return None
            return self.queue.pop(0)

    def wait_next(self, ctx: contextlib.AbstractContextManager) -> Optional[bytes]:
        log.debug("DatagramsQueue.wait_next")
        with self.c:
            while not self.queue:
                if ctx.exception() is not None:
                    return None
                self.c.wait()
            return self.queue.pop(0)


def jwt_signing_method_from_crypto_pubkey(pubkey) -> Tuple[str, Exception]:
    log.debug(f"jwt_signing_method_from_crypto_pubkey: pubkey={pubkey}")
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
    log.debug(f"sha256_fingerprint: in_bytes={in_bytes}")
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
    log.debug(f"cert_has_ip_sans: cert_pem={cert_pem}")
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
    log.debug("generate_key()")
    try:
        private_key = Ed25519PrivateKey.generate()
        signature = private_key.sign(b"my authenticated message") # TODO
        public_key  = private_key.public_key()
        public_key.verify(signature, b"my authenticated message")
        log.debug(f"public_key={public_key}")
        log.debug(f"private_key={private_key}")
        log.debug(f"signature={signature}")
        return public_key, private_key, None
    except Exception as e:
        log.error(f"could not generate key: {e}")
        return None, None, e

# TODO cant use SHA256 for Ed25519
def generate_cert(priv: Ed25519PrivateKey, pub:Ed25519PublicKey) -> Tuple[x509.Certificate, Optional[Exception]]:
    log.info(f"generate_cert: priv={priv}")
    try:
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSH3Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "elniak.selfsigned.ssh3"), # TODO maybe change for interop

        ])
        cert = x509.CertificateBuilder(
                ).subject_name(
                    subject
                ).issuer_name(
                    issuer
                ).public_key(
                    pub
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    datetime.datetime.now(datetime.timezone.utc)
                ).not_valid_after(
                    # Our certificate will be valid for 10 days
                    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
                ).add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("*"), x509.DNSName("elniak.selfsigned.ssh3")]),
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
                ).sign(priv, hashes.SHA256(), default_backend())
        log.debug(f"cert={cert}")
        return cert, None
    except Exception as e:
        log.error(f"could not generate cert: {e}")
        return None, e

def dump_cert_and_key_to_files(cert: x509.Certificate, priv: Ed25519PrivateKey, cert_file: str, key_file: str) -> Optional[Exception]:
    log.info(f"dump_cert_to_file: cert_file={cert_file}, key_file={key_file}")
    try:
        pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
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
    log.debug(f"parse_ssh_string: buf={buf}")
    """ Parses an SSH formatted string from the buffer. """
    length = int.from_bytes(buf.read(4), byteorder='big')
    return buf.read(length).decode('utf-8')

def write_ssh_string(buf, value):
    log.debug(f"write_ssh_string: value={value}")
    """ Writes an SSH formatted string into the buffer. """
    encoded_value = value.encode('utf-8')
    buf.extend(len(encoded_value).to_bytes(4, byteorder='big'))
    buf.extend(encoded_value)
    return len(encoded_value) + 4

def read_boolean(buf):
    log.debug("read_boolean")
    """ Reads a boolean value from the buffer. """
    return buf.read(1)[0] != 0

def ssh_string_len(s):
    log.debug(f"ssh_string_len: s={s}")
    # Length of a 32-bit integer in bytes is 4
    int_length = 4
    # Length of the string
    str_length = len(s)
    # Total length is the length of the integer plus the length of the string
    return int_length + str_length