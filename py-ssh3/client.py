import os
import base64
import jwt
import paramiko
from http import HTTPStatus
from typing import Tuple, List
from ssh.identity import Identity
import time

class OIDCAuthMethod:
    def __init__(self, do_pkce: bool, config):
        self.do_pkce = do_pkce
        self.config = config

    def oidc_config(self):
        return self.config

    def into_identity(self, bearer_token: str) -> 'Identity':
        return RawBearerTokenIdentity(bearer_token)

class PasswordAuthMethod:
    def __init__(self):
        pass
    
    def into_identity(self, password: str) -> 'Identity':
        return PasswordBasedIdentity(password)

class PrivkeyFileAuthMethod:
    def __init__(self, filename: str):
        self.filename = filename

    def filename(self) -> str:
        return self.filename

    def into_identity_without_passphrase(self) -> 'Identity':
        # Implement logic to read the private key file
        pass

    def into_identity_with_passphrase(self, passphrase: str) -> 'Identity':
        # Implement logic to read the private key file with passphrase
        pass

class AgentAuthMethod:
    def __init__(self, pubkey):
        self.pubkey = pubkey

    def into_identity(self, agent):
        return AgentBasedIdentity(self.pubkey, agent)

class AgentBasedIdentity(Identity):
    def __init__(self, pubkey, agent: paramiko.Agent):
        self.pubkey = pubkey
        self.agent = agent

    def set_authorization_header(self, req, username: str, conversation):
        # Implement logic to use SSH agent for signing
        # and setting the Authorization header
        pass

    def auth_hint(self) -> str:
        return "pubkey"

    def __str__(self):
        return f"agent-identity: {self.pubkey.get_name()}"

class PasswordBasedIdentity(Identity):
    def __init__(self, password:str):
        self.password = password

    def set_authorization_header(self, req, username: str, conversation):
        # Implement logic to use SSH agent for signing
        # and setting the Authorization header
        pass

    def auth_hint(self):
        return "password"

    def __str__(self):
        return "password-identity"


class RawBearerTokenIdentity(Identity):
    def __init__(self, bearer_token: str):
        self.bearer_token = bearer_token

    def set_authorization_header(self, req, username: str, conversation):
        req.headers['Authorization'] = f"Bearer {self.bearer_token}"

    def auth_hint(self) -> str:
        return "jwt"

    def __str__(self):
        return "raw-bearer-identity"

def build_jwt_bearer_token(signing_method, key, username: str, conversation) -> str:
    # Implement JWT token generation logic
    try:
        conv_id = conversation.conversation_id()
        b64_conv_id = base64.b64encode(conv_id).decode('utf-8')

        # Prepare the token claims
        claims = {
            "iss": username,
            "iat": int(time.time()),
            "exp": int(time.time()) + 10,  # Token expiration 10 seconds from now
            "sub": "ssh3",
            "aud": "unused",
            "client_id": f"ssh3-{username}",
            "jti": b64_conv_id
        }

        # Sign the token
        encoded_jwt = jwt.encode(claims, key, algorithm=signing_method)
        return encoded_jwt

    except Exception as e:
        return None, str(e)

def get_config_for_host(host: str, config) -> Tuple[str, int, str, List]:
    # Parse SSH config for the given host
    if config is None:
        return None, -1, None, []

    hostname = config.lookup(host).get("hostname", host)
    port     = int(config.lookup(host).get("port", -1))
    user     = config.lookup(host).get("user")
    auth_methods_to_try = []

    identity_files = config.lookup(host).get("IdentityFile", [])
    for identity_file in identity_files:
        identity_file_path = os.path.expanduser(identity_file)
        if os.path.exists(identity_file_path):
            auth_methods_to_try.append(identity_file_path)

    return hostname, port, user, auth_methods_to_try
