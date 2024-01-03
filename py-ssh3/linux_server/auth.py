import base64
import logging
import util.globals as glob
from typing import Callable
from util.linux_util.linux_user import *
from aioquic.asyncio.server import QuicServer
from linux_server.handlers import *
from ssh3.version import *
from ssh3.conversation import *
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
from starlette.responses import PlainTextResponse, Response
from aioquic.tls import *
from http3.http3_hijacker import *
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

SERVER_NAME = get_current_version()

class AuthHttpServerProtocol(HttpServerProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.hijacker = Hijacker(self)

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



async def handle_auths(
    request
):
    """
    Handle different types of authentication for a given HTTP request.
    enable_password_login: bool,
    default_max_packet_size: int,
    handler_func: callable,
    quic_server: QuicServer
    """
   
    # Set response server header
    content = ""
    status = 200
    header = [(b"Server", SERVER_NAME)] 

    # Check SSH3 version
    user_agent = b""
    for h,v in request["headers"]:
        if h == b"user-agent":
            try:
                user_agent = v.decode()
            except InvalidSSHVersion:
                logger.debug(f"Received invalid SSH version: {v}")
                status = 400
                return Response(content=b"Invalid version", 
                        headers=header,
                        status_code=status)
        
    major, minor, patch = parse_version(user_agent)  # Implement this function
    if major != MAJOR or minor != MINOR:  
        return Response(content=b"Unsupported version", 
                        headers=header,
                        status_code=status)
    
    protocols_keys = list(glob.QUIC_SERVER._protocols.keys())
    tls_state = glob.QUIC_SERVER._protocols[protocols_keys[-1]]._quic.tls.state # TODO should be more modular, if if there is multiple protocols
    logger.info(f"TLS state is {tls_state}")
    # Check if connection is complete
    if not tls_state == State.SERVER_POST_HANDSHAKE:
        status = 425
        return Response(content="", 
                        headers=header,
                        status_code=status)

    # Create a new conversation
    # Implement NewServerConversation based on your protocol's specifics
    conv = await new_server_conversation(
        max_packet_size=glob.DEFAULT_MAX_PACKET_SIZE,
        queue_size=10,
        tls_state= tls_state
    )
    logger.info(f"Created new conversation {conv}")
    # Handle authentication
    authorization = b""
    for h,v in request["headers"]:
        if h == b"authorization":
            try:
                authorization = v.decode()
            except Exception:
                logger.debug(f"Received invalid authorization version: {v}")
                status = 400
                return Response(content=b"Invalid authorization", 
                        headers=header,
                        status_code=status)
    logger.info(f"Received authorization {authorization}")
    if glob.ENABLE_PASSWORD_LOGIN and authorization.startswith("Basic "):
        logger.info("Handling basic auth")
        return await handle_basic_auth(request=request, conv=conv)
    elif authorization.startswith("Bearer "):
        logger.info("Handling bearer auth")
        username = request.headers.get(b":path").decode().split("?", 1)[0].lstrip("/")
        conv_id = base64.b64encode(conv.id).decode()
        return await handle_bearer_auth(username, conv_id)
    else:
        logger.info("Handling no auth")
        header.append((b"www-authenticate", b"Basic"))
        status = 401
        return Response(content=content, 
                    headers=header,
                    status_code=status)
