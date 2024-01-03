import os
from typing import Tuple, Callable
import base64
import logging
from http3.http3_server import HttpRequestHandler
from util.linux_util.linux_user import *
from linux_server.authorized_identities import *

def bearer_auth(headers: dict) -> Tuple[str, bool]:
    """
    Extracts the bearer token from the Authorization header.
    """
    auth = headers.get("authorization", "")
    if not auth:
        return "", False
    return parse_bearer_auth(auth)

def parse_bearer_auth(auth: str) -> Tuple[str, bool]:
    """
    Parses an HTTP Bearer Authentication string.
    """
    prefix = "Bearer "
    if not auth.lower().startswith(prefix.lower()):
        return "", False
    return auth[len(prefix):], True

def handle_bearer_auth(username: str, base64_conv_id: str, handler_func: Callable) -> Callable:
    """
    HTTP handler function to handle Bearer authentication.
    """
    async def inner_handler(request_handler: HttpRequestHandler):
        bearer_string, ok = bearer_auth(request_handler.scope["headers"])
        if not ok:
            request_handler.send_unauthorized_response()
            return
        await handler_func(bearer_string, base64_conv_id, request_handler)

    return inner_handler

def handle_jwt_auth(username: str, new_conv: object, handler_func: Callable) -> Callable:
    """
    Validates JWT token and calls the handler function if authentication is successful.
    """
    async def inner_handler(unauth_bearer_string: str, base64_conv_id: str, request_handler: HttpRequestHandler):
        user = get_user(username)  # Replace with your user retrieval method
        if user is None:
            request_handler.send_unauthorized_response()
            return

        filenames = default_identities_file_names(user)
        identities = []
        for filename in filenames:
            try:
                with open(filename, 'r') as identities_file:
                    new_identities = parse_authorized_identities_file(user, identities_file)
                    identities.extend(new_identities)
            except FileNotFoundError:
                pass  # File not found, continue with the next file
            except Exception as e:
                logging.error(f"Error could not open {filename}: {e}")
                request_handler.send_unauthorized_response()
                return

        for identity in identities:
            if identity.verify(unauth_bearer_string, base64_conv_id):
                await handler_func(username, new_conv, request_handler)
                return

        request_handler.send_unauthorized_response()

    return inner_handler
