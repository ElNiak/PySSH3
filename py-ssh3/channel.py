import asyncio
import struct
from typing import Tuple
import ipaddress

class ChannelOpenFailure(Exception):
    def __init__(self, reason_code, error_msg):
        self.reason_code = reason_code
        self.error_msg = error_msg
        super().__init__(f"Channel open failure: reason: {reason_code}: {error_msg}")

class MessageOnNonConfirmedChannel(Exception):
    def __init__(self, message):
        super().__init__(f"A message of type {type(message)} has been received on a non-confirmed channel")

# ... Similarly translate other error classes ...

class ChannelInfo:
    def __init__(self, max_packet_size, conv_stream_id, conv_id, channel_id, channel_type):
        self.max_packet_size = max_packet_size
        self.conv_stream_id = conv_stream_id
        self.conv_id = conv_id
        self.channel_id = channel_id
        self.channel_type = channel_type


class Channel:
    def __init__(self, channel_info: ChannelInfo):
        self.channel_info = channel_info
        # Initialize other attributes

    # Define methods as per the Golang interface
    async def next_message(self):
        # Implementation of the message handling
        pass

    # ... Other methods ...

class UDPForwardingChannelImpl(Channel):
    def __init__(self, channel_info, remote_addr):
        super().__init__(channel_info)
        self.remote_addr = remote_addr
        # Additional initialization

class TCPForwardingChannelImpl(Channel):
    def __init__(self, channel_info, remote_addr):
        super().__init__(channel_info)
        self.remote_addr = remote_addr
        # Additional initialization

class ChannelImpl(Channel):
    def __init__(self, channel_info, recv_stream, send_stream):
        super().__init__(channel_info)
        self.recv_stream = recv_stream
        self.send_stream = send_stream
        # Initialize other attributes and handlers

    # Implement all required methods from the Channel interface
    # ...

def build_header(conv_stream_id, channel_type, max_packet_size, additional_bytes):
    # Implement header building logic
    pass

def parse_header(channel_id, reader):
    # Implement header parsing logic
    pass

def parse_forwarding_header(channel_id, reader) -> Tuple[ipaddress.ip_address, int]:
    # Parse the header and return an IP address and port
    pass

def parse_udp_forwarding_header(channel_id, reader):
    address, port = parse_forwarding_header(channel_id, reader)
    return ipaddress.ip_address(address), port

def parse_tcp_forwarding_header(channel_id, reader):
    address, port = parse_forwarding_header(channel_id, reader)
    return ipaddress.ip_address(address), port
