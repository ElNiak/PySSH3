import base64
import logging
from typing import Callable
from util.linux_util.linux_user import *
from aioquic.asyncio.server import QuicServer
from linux_server.handlers import *
from ssh3.version import *
from http3.http3_server import HttpServerProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    DataReceived,
    H3Event,
    HeadersReceived,
    WebTransportStreamDataReceived,
)
from aioquic.quic.events import DatagramFrameReceived, ProtocolNegotiated, QuicEvent
from ssh3.version import *

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

SERVER_NAME = get_current_version()


class AuthHttpServerProtocol(HttpServerProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def http_event_received(self, event: H3Event) -> None:
        for header, value in event.headers:
                if header == b"user-agent":
                    try:
                        major, minor, patch = parse_version(value.decode())
                    except InvalidSSHVersion:
                        logger.debug(f"Received invalid SSH version: {value}")
                        return
        logger.debug(f"Received HTTP event: {event} with version {major}.{minor}.{patch}")
        super().http_event_received(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        super().quic_event_received(event)



# async def handle_auths(
#     enable_password_login: bool,
#     default_max_packet_size: int,
#     handler_func: callable,
#     quic_server: QuicServer,
# ):
#     """
#     Handle different types of authentication for a given HTTP request.
#     """
#     # Set response server header
#     # request_handler = quic_server._create_protocol.request_handler
#     request_handler.send({
#         "type": "http.response.start",
#         "status": 200,
#         "headers": [(b"server", b"MySSH3Server")]  # Replace with your server version
#     })

#     # Check SSH3 version
#     user_agent = request_handler.scope["headers"].get(b"user-agent", b"").decode()
#     major, minor, patch = parse_version(user_agent)  # Implement this function
#     if major != MAJOR or minor != MINOR:  
#         request_handler.send({
#             "type": "http.response.body",
#             "body": b"Unsupported version",
#             "more_body": False,
#         })
#         return

#     # Check if connection is complete
#     if not isinstance(request_handler.connection._quic, QuicConnection) or not request_handler.connection._quic._handshake_complete:
#         request_handler.send({
#             "type": "http.response.start",
#             "status": 425,  # HTTP StatusTooEarly
#             "headers": []
#         })
#         return

#     # Create a new conversation
#     # Implement NewServerConversation based on your protocol's specifics
#     conv = await NewServerConversation(
#         request_handler.connection._quic,
#         default_max_packet_size
#     )

#     # Handle authentication
#     authorization = request_handler.scope["headers"].get(b"authorization", b"").decode()
#     if enable_password_login and authorization.startswith("Basic "):
#         await handle_basic_auth(handler_func, conv, request_handler)
#     elif authorization.startswith("Bearer "):
#         username = request_handler.scope["headers"].get(b":path").decode().split("?", 1)[0].lstrip("/")
#         conv_id = base64.b64encode(conv.id).decode()
#         await HandleBearerAuth(username, conv_id, handler_func, request_handler)
#     else:
#         request_handler.send({
#             "type": "http.response.start",
#             "status": 401,
#             "headers": [(b"www-authenticate", b"Basic")]
#         })

#     await request_handler.transmit()

# async def handle_basic_auth(request, handler_func, conv, request_handler):
#     # Extract Basic Auth credentials
#     username, password, ok = extract_basic_auth(request)
#     if not ok:
#         return web.Response(status=401)

#     # Replace this with your own authentication method
#     ok = await user_password_authentication(username, password)
#     if not ok:
#         return web.Response(status=401)

#     return await handler_func(username, conv, request)

# def extract_basic_auth(request):
    # auth_header = request.headers.get('Authorization')
    # if not auth_header:
    #     return None, None, False

    # # Basic Auth Parsing
    # try:
    #     auth_type, auth_info = auth_header.split(' ', 1)
    #     if auth_type.lower() != 'basic':
    #         return None, None, False

    #     username, password = base64.b64decode(auth_info).decode().split(':', 1)
    #     return username, password, True
    # except Exception as e:
    #     return None, None, False