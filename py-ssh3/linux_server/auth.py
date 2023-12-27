import base64
import logging
from typing import Callable
from util.linux_util.linux_user import *
from http3.http3_server import HttpRequestHandler
from linux_server.handlers import *
from ssh.version import *

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


async def handle_auths(
    enable_password_login: bool,
    default_max_packet_size: int,
    handler_func: callable,
    request_handler: HttpRequestHandler
):
    """
    Handle different types of authentication for a given HTTP request.
    """
    # Set response server header
    request_handler.send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"server", b"MySSH3Server")]  # Replace with your server version
    })

    # Check SSH3 version
    user_agent = request_handler.scope["headers"].get(b"user-agent", b"").decode()
    major, minor, patch = parse_version(user_agent)  # Implement this function
    if major != MAJOR or minor != MINOR:  
        request_handler.send({
            "type": "http.response.body",
            "body": b"Unsupported version",
            "more_body": False,
        })
        return

    # Check if connection is complete
    if not isinstance(request_handler.connection._quic, QuicConnection) or not request_handler.connection._quic._handshake_complete:
        request_handler.send({
            "type": "http.response.start",
            "status": 425,  # HTTP StatusTooEarly
            "headers": []
        })
        return

    # Create a new conversation
    # Implement NewServerConversation based on your protocol's specifics
    conv = await NewServerConversation(
        request_handler.connection._quic,
        default_max_packet_size
    )

    # Handle authentication
    authorization = request_handler.scope["headers"].get(b"authorization", b"").decode()
    if enable_password_login and authorization.startswith("Basic "):
        await handle_basic_auth(handler_func, conv, request_handler)
    elif authorization.startswith("Bearer "):
        username = request_handler.scope["headers"].get(b":path").decode().split("?", 1)[0].lstrip("/")
        conv_id = base64.b64encode(conv.id).decode()
        await HandleBearerAuth(username, conv_id, handler_func, request_handler)
    else:
        request_handler.send({
            "type": "http.response.start",
            "status": 401,
            "headers": [(b"www-authenticate", b"Basic")]
        })

    await request_handler.transmit()

async def handle_basic_auth(request, handler_func, conv, request_handler):
    # Extract Basic Auth credentials
    username, password, ok = extract_basic_auth(request)
    if not ok:
        return web.Response(status=401)

    # Replace this with your own authentication method
    ok = await user_password_authentication(username, password)
    if not ok:
        return web.Response(status=401)

    return await handler_func(username, conv, request)

def extract_basic_auth(request):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None, None, False

    # Basic Auth Parsing
    try:
        auth_type, auth_info = auth_header.split(' ', 1)
        if auth_type.lower() != 'basic':
            return None, None, False

        username, password = base64.b64decode(auth_info).decode().split(':', 1)
        return username, password, True
    except Exception as e:
        return None, None, False