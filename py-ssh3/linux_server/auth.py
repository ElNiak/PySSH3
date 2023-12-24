import base64
import logging
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.asyncio.server import HttpRequestHandler, HttpServerProtocol, Route
from aioquic.quic.events import ProtocolNegotiated
from typing import Callable
import util.linux_util as linux_util

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def handle_auths(enablePasswordLogin: bool, defaultMaxPacketSize: int) -> Callable:
    async def handle_request(handler: HttpRequestHandler, event: ProtocolNegotiated):
        request = handler._http_request_received
        logger.debug(f"Received request from User-Agent {request.headers.get('user-agent')}")

        # Add your version check and logic here

        if not handler._quic._is_handshake_complete:
            handler._quic.send_response(status_code=425)  # 425 Too Early
            return

        # Process the request and perform authentication
        authorization = request.headers.get('authorization')
        if enablePasswordLogin and authorization.startswith('Basic '):
            await handle_basic_auth(handler, request)
        elif authorization.startswith('Bearer '):
            # Handle bearer authentication
            pass
        else:
            handler._quic.send_response(status_code=401)  # 401 Unauthorized

    return handle_request


def handle_basic_auth(handler: HttpRequestHandler, request):
    auth = request.headers.get('authorization')
    username, password = base64.b64decode(auth.split(' ')[1]).decode().split(':')
    if not linux_util.UserPasswordAuthentication(username, password):
        handler._quic.send_response(status_code=401)  # 401 Unauthorized
        return

    # Continue with the authenticated request processing

def check_credentials(username, password):
    # Placeholder for checking username and password
    return True  # Assuming credentials are valid
