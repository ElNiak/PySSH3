import jwt
from typing import Tuple, List
import contextlib
import base64
import crypto
import os
import random
import struct
import time
from datetime import timedelta
from typing import Any, Callable, Optional
import threading

import jwt
import rsa
from Crypto.Util.asn1 import x509
from asn1crypto.cryptobyte import wrap
from asn1crypto.util import int_from_bytes, read_full

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PrivateFormat, NoEncryption

import logging


def build_jwt_bearer_token(key, username: str, conversation) -> str:
    # Implement JWT token generation logic
    pass

def get_config_for_host(host: str) -> Tuple[str, int, str, List]:
    # Parse SSH config for the given host
    pass

class UnknownSSHPubkeyType(Exception):
    def __init__(self, pubkey: crypto.PublicKey):
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


class AcceptQueue(Generic[T]):
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.c = threading.Condition(self.lock)
        self.queue: List[T] = []

    def add(self, item: T) -> None:
        with self.lock:
            self.queue.append(item)
            self.c.notify()

    def next(self) -> T:
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


def jwt_signing_method_from_crypto_pubkey(pubkey: crypto.PublicKey) -> Tuple[jwt.algorithms.SigningAlgorithm, Exception]:
    try:
        if isinstance(pubkey, rsa.RSAPublicKey):
            return jwt.algorithms.RSAAlgorithm(), None
        elif isinstance(pubkey, Ed25519PrivateKey.public_key):
            return jwt.algorithms.Ed25519Algorithm(), None
        else:
            return None, UnknownSSHPubkeyType(pubkey)
    except Exception as e:
        return None, e


def sha256_fingerprint(in_bytes: bytes) -> str:
    sha256_hash = hashlib.sha256()
    sha256_hash.update(in_bytes)
    return base64.b64encode(sha256_hash.digest()).decode('utf-8')


def get_san_extension(cert: x509.Certificate) -> Optional[bytes]:
    oid_extension_subject_alt_name = x509.ExtensionIdentifier.from_string("2.5.29.17")
    for ext in cert.extensions:
        if ext['extn_id'] == oid_extension_subject_alt_name:
            return ext['extn_value'].native
    return None


def for_each_san(der: bytes, callback: Callable[[int, bytes], Exception]) -> Optional[Exception]:
    try:
        idx = 0
        der_len = len(der)
        while idx < der_len:
            tag = int(der[idx])
            idx += 1
            length = int_from_bytes(der[idx:idx + 2])
            idx += 2
            if idx + length > der_len:
                raise ValueError("x509: invalid subject alternative name")
            data = der[idx:idx + length]
            idx += length
            err = callback(tag, data)
            if err is not None:
                return err
        return None
    except Exception as e:
        return e


def cert_has_ip_sans(cert: x509.Certificate) -> Tuple[bool, Optional[Exception]]:
    SANExtension = get_san_extension(cert)
    if SANExtension is None:
        return False, None

    name_type_ip = 7
    ip_addresses = []

    def callback(tag: int, data: bytes) -> Optional[Exception]:
        if tag == name_type_ip:
            if len(data) == 4 or len(data) == 16:
                ip_addresses.append(data)
            else:
                return ValueError(f"x509: cannot parse IP address of length {len(data)}")
        return None

    err = for_each_san(SANExtension, callback)
    if err is not None:
        return False, err

    return len(ip_addresses) > 0, None


def generate_key() -> Tuple[crypto.PublicKey, crypto.PrivateKey, Optional[Exception]]:
    try:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return public_key, private_key, None
    except Exception as e:
        return None, None, e


def generate_cert(priv: crypto.PrivateKey) -> Tuple[x509.Certificate, Optional[Exception]]:
    try:
        serial_number = random.randint(1, 2 ** 128)
        subject = x509.Name.build({
            'organization_name': "SSH3Organization"
        })
        not_before = time.gmtime()
        not_after = time.gmtime(time.time() + timedelta(days=10 * 365).total_seconds())

        cert = x509.C
    except Exception as e:
        return None, e
