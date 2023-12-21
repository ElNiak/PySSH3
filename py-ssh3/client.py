import os
import base64
import logging
import pathlib
import jwt
import paramiko
from http import HTTPStatus
from typing import Tuple, List
from identity import Identity

class OUDCAuthMethod:
    def __init__(self, do_pkce: bool, config):
        self.do_pkce = do_pkce
        self.config = config

    def oidc_config(self):
        return self.config

    def into_identity(self, bearer_token: str) -> 'Identity':
        return RawBearerTokenIdentity(bearer_token)

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

class AgentBasedIdentity:
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

class RawBearerTokenIdentity:
    def __init__(self, bearer_token: str):
        self.bearer_token = bearer_token

    def set_authorization_header(self, req, username: str, conversation):
        req.headers['Authorization'] = f"Bearer {self.bearer_token}"

    def auth_hint(self) -> str:
        return "jwt"

    def __str__(self):
        return "raw-bearer-identity"
