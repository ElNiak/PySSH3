import os
from typing import Tuple, Callable
import base64
import logging
from http3.http3_server import HttpRequestHandler
from util.linux_util.linux_user import *
from linux_server.authorized_identities import *
import util.globals as glob
from starlette.responses import PlainTextResponse, Response

logger = logging.getLogger(__name__)

def bearer_auth(headers: dict) -> Tuple[str, bool]:
    """
    Extracts the bearer token from the Authorization header.
    """
    auth = headers.get(":authorization", "")
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

def handle_bearer_auth(username: str, base64_conv_id: str) -> Callable:
    """
    HTTP handler function to handle Bearer authentication.
    """
    async def inner_handler(request_handler: HttpRequestHandler):
        bearer_string, ok = bearer_auth(request_handler.scope["headers"])
        if not ok:
            request_handler.send_unauthorized_response()
            return
        await glob.HANDLER_FUNC(bearer_string, base64_conv_id, request_handler)

    return inner_handler

async def handle_jwt_auth(username: str, new_conv: object) -> Callable:
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
                await glob.HANDLER_FUNC(username, new_conv, request_handler)
                return

        request_handler.send_unauthorized_response()

    return inner_handler


async def handle_basic_auth(request, conv):
    # Extract Basic Auth credentials
    username, password, ok = extract_basic_auth(request)
    if not ok:
        logger.error(f"Invalid basic auth credentials extraction")
        status = 401
        return Response(status_code=status)

    # Replace this with your own authentication method
    ok = user_password_authentication(username, password)
    if not ok:
        logger.error(f"Invalid basic auth credentials")
        status = 401
        return Response(status_code=status)

    return await glob.HANDLER_FUNC(username, conv, request)

def extract_basic_auth(request):
    auth_header = request.headers.get('authorization')
    logger.info(f"Received authorization header {auth_header}")
    if not auth_header:
        return None, None, False

    # Basic Auth Parsing
    try:
        auth_type, auth_info = auth_header.split(' ', 1)
        if auth_type.lower() != 'basic':
            logger.error(f"Invalid auth type {auth_type}")
            return None, None, False

        username, password = base64.b64decode(auth_info).decode().split(':', 1)
        logger.info(f"Received username {username} and password {password}")
        return username, password, True
    except Exception as e:
        return None, None, False