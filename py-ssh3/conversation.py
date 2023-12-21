import asyncio
import base64
import ssl
import os
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompletedEvent, StreamDataReceived
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import H3Event, HeadersReceived, DataReceived
import logging
import contextlib
from typing import Callable, Tuple
import util.util as util
import http 
from quic_client import QuicClientProtocol
from quic_round_trip import RoundTripper, HTTP3Client
import channel as channel

class ConversationID:
    def __init__(self, value: bytes):
        self.value = value # 32 bytes
        assert len(value) <= 32

    def __str__(self):
        return base64.b64encode(self.value).decode('utf-8')

class ChannelsManager:
    # Define your channels manager logic here
    pass

class Conversation(QuicConnectionProtocol):
    def __init__(self, control_stream, max_packet_size, default_datagrams_queue_size, stream_creator, message_sender, channels_manager, conversation_id):
        self.control_stream = control_stream
        self.max_packet_size = max_packet_size
        self.default_datagrams_queue_size = default_datagrams_queue_size
        self.stream_creator = stream_creator
        self.message_sender = message_sender
        self.channels_manager = channels_manager
        self.context = None  # Will be set using context manager
        self.cancel_context = None  # Will be set using context manager
        self.conversation_id = conversation_id
        self.channels_accept_queue = None  # Set to an appropriate queue type

    def __init__(self, max_packet_size, default_datagrams_queue_size, tls: ssl.SSLContext):
        self.conv_id, err = self.generate_conversation_id(tls)
        if err:
            logging.error(f"could not generate conversation ID: {err}")
            raise err

        self.control_stream = None
        self.channels_accept_queue = util.NewAcceptQueue()  # Assuming a suitable implementation
        self.stream_creator = None
        self.max_packet_size = max_packet_size
        self.default_datagrams_queue_size = default_datagrams_queue_size
        self.channels_manager = self.new_channels_manager()  # Assuming a suitable implementation
        self.context, self.cancel_context = contextlib.ExitStack().enter_context(contextlib.closing(contextlib.ExitStack()))
        self.conversation_id = self.conv_id
        
    @contextlib.contextmanager
    def manage_context(self):
        self.context, self.cancel_context = contextlib.ExitStack().enter_context(contextlib.closing(contextlib.ExitStack()))
        yield
        self.cancel_context()

    def generate_conversation_id(self, tls_connection_state: ssl.SSLObject) -> Tuple[bytes, Exception]:
        try:
            key_material = tls_connection_state.export_keying_material("EXPORTER-SSH3", 32)
            if len(key_material) != 32:
                raise ValueError(f"TLS returned a tls-exporter with the wrong length ({len(key_material)} instead of 32)")
            return key_material, None
        except Exception as e:
            return b'', e
        
    async def establish_client_conversation(self, req: http.client.HTTPRequest, round_tripper: HTTP3Client):
        round_tripper.stream_hijacker = self.stream_hijacker

        response = await round_tripper.round_trip("GET", req.url, headers=req.headers)
        if response is None:
            return "Request failed"

        server_version = response.headers.get("server")
        # Parse version and handle server version check
        # ...

        if response.status_code == 200:
            self.control_stream = response.http_stream
            self.stream_creator = response.stream_creator
            self.context = response.context
            asyncio.create_task(self.handle_datagrams(response.connection))
            return None
        elif response.status_code == 401:
            return "Unauthorized"
        else:
            return f"Unexpected status code: {response.status_code}"

    def stream_hijacker(self, frame_type, connection, stream, error):
        if error is not None:
            return False, error
        if frame_type != util.SSH_FRAME_TYPE:
            return False, None

        # Asynchronously read from the stream to get the header data
        async def read_header():
            try:
                header_data = await stream.receive_some()
                # Parse the header data
                # TODO complete
                control_stream_id, channel_type, max_packet_size = channel.parse_header(header_data)
                # Validate and process the header data
                if control_stream_id != self.control_stream_id:
                    raise ValueError(f"Wrong conversation control stream ID: {control_stream_id}")
                # Handle the new channel based on the parsed information
                # ...
                return True, None
            except Exception as e:
                return False, e

        return read_header()

    async def handle_datagrams(self, connection):
        while True:
            try:
                datagram = await connection.receive_datagram()
                # Process datagram
                # ...
            except asyncio.CancelledError:
                break
            
async def new_client_conversation(max_packet_size, queue_size, tls_state):
    conv_id = ConversationID.generate_conversation_id(tls_state)
    # Additional logic for creating a new client conversation
    return Conversation(None, max_packet_size, queue_size)

