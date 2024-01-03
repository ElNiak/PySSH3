import os
import jwt
import logging
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from util.type import *
from auth.openid_connect import *

class Identity:
    def verify(self, candidate, base64_conversation_id):
        pass

class PubKeyIdentity(Identity):
    def __init__(self, username, pubkey):
        self.username = username
        self.pubkey = pubkey

    def verify(self, candidate, base64_conversation_id):
        if isinstance(candidate, JWTTokenString):
            try:
                token = jwt.decode(candidate.token, self.pubkey, algorithms=["RS256", "EdDSA"], issuer=self.username, subject="ssh3", audience="unused")
                # Perform additional checks on claims here
                claims = token.get("claims", {})
                if "exp" not in claims:
                    return False
                if "client_id" not in claims or claims["client_id"] != f"ssh3-{self.username}":
                    return False
                if "jti" not in claims or claims["jti"] != base64_conversation_id:
                    logging.error("RSA verification failed: the jti claim does not contain the base64-encoded conversation ID")
                    return False
                return True
            except Exception as e:
                logging.error(f"Invalid private key token: {str(e)}")
                return False
        else:
            return False


class OpenIDConnectIdentity(Identity):
    def __init__(self, client_id, issuer_url, email):
        self.client_id = client_id
        self.issuer_url = issuer_url
        self.email = email

    def verify(self, candidate, base64_conversation_id):
        if isinstance(candidate, JWTTokenString):
            try:
                token = verify_raw_token(self.client_id, self.issuer_url, candidate.token)
                if token.issuer != self.issuer_url or not token.email_verified or token.email != self.email:
                    return False
                return True
            except Exception as e:
                logging.error(f"Cannot verify raw token: {str(e)}")
                return False
        return False

def default_identities_file_names(user):
    return [
        os.path.join(user.dir, ".ssh3", "authorized_identities"),
        os.path.join(user.dir, ".ssh", "authorized_keys")
    ]

def parse_identity(user, identity_str):
    try:
        pubkey = load_ssh_public_key(identity_str.encode(), backend=default_backend())
        return PubKeyIdentity(user.username, pubkey)
    except Exception as e:
        if identity_str.startswith("oidc"):
            tokens = identity_str.split()
            if len(tokens) != 4:
                raise ValueError("Bad identity format for oidc identity")
            client_id, issuer_url, email = tokens[1:4]
            return OpenIDConnectIdentity(client_id, issuer_url, email)
        raise ValueError("Unknown identity format")

def parse_authorized_identities_file(user, file_path):
    identities = []
    with open(file_path, 'r') as file:
        for line_number, line in enumerate(file, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                identity = parse_identity(user, line)
                identities.append(identity)
            except Exception as e:
                logging.error(f"Cannot parse identity line {line_number}: {str(e)}")
    return identities

# Define classes or functions as needed, for example, JWTTokenString or verify_raw_token
