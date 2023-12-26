 
import struct
from typing import Tuple, Optional, Callable
import ipaddress
from util import *
from abc import ABC, abstractmethod
import util.type as stype
import util.util as util
import util.wire as wire
from ssh.conversation import *
from message.message import *
from message.channel_request import *
from aioquic.quic.stream import QuicStreamReceiver
import socket

SSH_FRAME_TYPE = 0xaf3627e6

class ChannelOpenFailure(Exception):
    def __init__(self, reason_code, error_msg):
        self.reason_code = reason_code # uint64
        self.error_msg   = error_msg   # string
        super().__init__(f"Channel open failure: reason: {reason_code}: {error_msg}")

class MessageOnNonConfirmedChannel(Exception):
    def __init__(self, message: Message):
        self.message = message
        super().__init__(f"A message of type {type(self.message)} has been received on a non-confirmed channel")

class MessageOnNonConfirmedChannel(Exception):
    def __init__(self, channel_id: int):
        self.channel_id = channel_id
        super().__init__(f"A datagram has been received on non-datagram channel {self.channel_id}")

class SentDatagramOnNonDatagramChannel(Exception):
    def __init__(self, channel_id: int):
        self.channel_id = channel_id
        super().__init__(f"A datagram has been sent on non-datagram channel {self.channel_id}")

 
class ChannelInfo:
    def __init__(self, 
                 max_packet_size, 
                 conv_stream_id, 
                 conv_id, 
                 channel_id, 
                 channel_type):
        self.max_packet_size = max_packet_size
        self.conv_stream_id = conv_stream_id
        self.conv_id = conv_id
        self.channel_id = channel_id
        self.channel_type = channel_type


class Channel(ABC):
    @abstractmethod
    def channel_id(self) -> stype.ChannelID:
        pass

    @abstractmethod
    def conversation_id(self) -> ConversationID:
        pass

    @abstractmethod
    def conversation_stream_id(self) -> int:
        pass

    @abstractmethod
    def next_message(self) -> Message:
        pass

    @abstractmethod
    def receive_datagram(self) -> bytes:
        pass

    @abstractmethod
    def send_datagram(self, datagram: bytes) -> None:
        pass

    @abstractmethod
    def send_request(self, r: ChannelRequestMessage) -> None:
        pass

    @abstractmethod
    def cancel_read(self) -> None:
        pass

    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
    def max_packet_size(self) -> int:
        pass

    @abstractmethod
    def write_data(self, data_buf: bytes, data_type: SSHDataType) -> int:
        pass

    @abstractmethod
    def channel_type(self) -> str:
        pass

    @abstractmethod
    def confirm_channel(self, max_packet_size: int) -> None:
        pass

    @abstractmethod
    def set_datagram_sender(self, sender: Callable[[bytes], None]) -> None:
        pass

    @abstractmethod
    def wait_add_datagram(self, datagram: bytes) -> None:
        pass

    @abstractmethod
    def add_datagram(self, datagram: bytes) -> bool:
        pass

    @abstractmethod
    def maybe_send_header(self) -> None:
        pass

    @abstractmethod
    def set_datagram_queue(self, queue: util.DatagramsQueue) -> None:
        pass


class ChannelImpl(Channel):
    def __init__(self, channel_info: ChannelInfo, recv: QuicStreamReceiver, send):
        self.channel_info = channel_info
        self.confirm_sent = False
        self.confirm_received = False
        self.header = []
        self.datagram_sender = None
        self.channel_close_listener = None
        self.recv = recv
        self.send = send
        self.datagrams_queue = None

        # Handlers and data handling attributes
        self.pty_req_handler = None
        self.x11_req_handler = None
        self.shell_req_handler = None
        self.exec_req_handler = None
        self.subsystem_req_handler = None
        self.window_change_req_handler = None
        self.signal_req_handler = None
        self.exit_status_req_handler = None
        self.exit_signal_req_handler = None
        self.channel_data_handler = None
        
    def __init__(self, conversation_stream_id: int, conversation_id: ConversationID, channel_id: int,
                 channel_type: str, max_packet_size: int, recv: QuicStreamReceiver, send,
                 datagram_sender: Callable, channel_close_listener: Callable, send_header: bool,
                 confirm_sent: bool, confirm_received: bool, datagrams_queue_size: int, additional_header_bytes: bytes):
        self.channel_info = ChannelInfo(max_packet_size, conversation_stream_id, conversation_id, channel_id, channel_type)
        self.recv = recv
        self.send = send
        self.datagrams_queue = stype.DatagramsQueue(datagrams_queue_size)  
        self.datagram_sender = datagram_sender
        self.channel_close_listener = channel_close_listener
        self.header = build_header(conversation_stream_id, channel_type, max_packet_size, additional_header_bytes) if send_header else None
        self.confirm_sent = confirm_sent
        self.confirm_received = confirm_received
        
        # Handlers and data handling attributes
        self.pty_req_handler = None
        self.x11_req_handler = None
        self.shell_req_handler = None
        self.exec_req_handler = None
        self.subsystem_req_handler = None
        self.window_change_req_handler = None
        self.signal_req_handler = None
        self.exit_status_req_handler = None
        self.exit_signal_req_handler = None
        self.channel_data_handler = None
        
    def channel_id(self):
        return self.channel_info.channel_id

    def conversation_stream_id(self):
        return self.channel_info.conversation_stream_id

    def conversation_id(self):
        return self.channel_info.conversation_id

    def next_message(self):
        # The error is EOF only if no bytes were read. If an EOF happens
        # after reading some but not all the bytes, next_message returns
        # ErrUnexpectedEOF.
        return parse_message(self.recv)  # Assuming parse_message is defined

    def next_message(self):
        generic_message, err = self.next_message()
        if err:
            return None, err

        if isinstance(generic_message, ChannelOpenConfirmationMessage):
            self.confirm_received = True
            return self.next_message()
        elif isinstance(generic_message, ChannelOpenFailureMessage):
            return None, ChannelOpenFailure(generic_message.reason_code, generic_message.error_message_utf8)

        if not self.confirm_sent:
            return None, MessageOnNonConfirmedChannel(generic_message)
        return generic_message, None

    def maybe_send_header(self):
        if self.header:
            written, err = self.send.write(self.header)
            if err:
                return err
            self.header = self.header[written:]
        return None

    def write_data(self, data_buf, data_type):
        err = self.maybe_send_header()
        if err:
            return 0, err
        written = 0
        while data_buf:
            data_msg = DataOrExtendedDataMessage(data_type, "")
            empty_msg_len = data_msg.length()
            msg_len = min(self.channel_info.max_packet_size - empty_msg_len, len(data_buf))

            data_msg.data = data_buf[:msg_len]
            data_buf = data_buf[msg_len:]

            msg_buf = data_msg.write()
            n, err = self.send.write(msg_buf)
            written += n
            if err:
                return written, err
        return written, None

    def confirm_channel(self, max_packet_size):
        err = self.send_message(ssh3.ChannelOpenConfirmationMessage(max_packet_size))
        if not err:
            self.confirm_sent = True
        return err

    def send_message(self, message):
        err = self.maybe_send_header()
        if err:
            return err
        buf = message.write()
        self.send.write(buf)
        return None

    def wait_add_datagram(self, datagram):
        return self.datagrams_queue.wait_add(datagram)

    def add_datagram(self, datagram):
        return self.datagrams_queue.add(datagram)

    def receive_datagram(self):
        return self.datagrams_queue.wait_next()

    def send_datagram(self, datagram):
        self.maybe_send_header()
        if not self.datagram_sender:
            return SentDatagramOnNonDatagramChannel(self.channel_id())
        return self.datagram_sender(datagram)

    def send_request(self, request):
        # TODO: make it thread safe
        return self.send_message(request)

    def cancel_read(self):
        self.recv.cancel_read(42)

    def close(self):
        self.send.close()

    def max_packet_size(self):
        return self.channel_info.max_packet_size

    def channel_type(self):
        return self.channel_info.channel_type

    def set_datagram_sender(self, datagram_sender):
        self.datagram_sender = datagram_sender

    def set_datagram_queue(self, queue):
        self.datagrams_queue = queue
    
class UDPForwardingChannelImpl(ChannelImpl):
    def __init__(self, channel_info, remote_addr):
        super().__init__(channel_info)
        self.remote_addr = remote_addr
        # Additional initialization

class TCPForwardingChannelImpl(ChannelImpl):
    def __init__(self, channel_info, remote_addr):
        super().__init__(channel_info)
        self.remote_addr = remote_addr
        # Additional initialization
            
def build_header(conversation_stream_id: int, channel_type: str, max_packet_size: int, additional_bytes: Optional[bytes]) -> bytes:
    channel_type_buf = util.write_ssh_string(channel_type)
    buf = wire.AppendVarInt(b'', SSH_FRAME_TYPE)
    buf += wire.AppendVarInt(buf, conversation_stream_id)
    buf += channel_type_buf
    buf += wire.AppendVarInt(buf, max_packet_size)
    if additional_bytes:
        buf += additional_bytes
    return buf


def build_forwarding_channel_additional_bytes(remote_addr: ipaddress.IPv4Address, port: int) -> bytes:
    buf = b''
    address_family = stype.SSHAFIpv4 if len(remote_addr) == 4 else stype.SSHAFIpv6
    buf += wire.AppendVarInt(buf, address_family)
    buf += remote_addr
    port_buf = struct.pack('>H', port)  # Big-endian format for uint16
    buf += port_buf
    return buf

def parse_header(channel_id: int, reader) -> Tuple[int, str, int, Optional[Exception]]:
    conversation_control_stream_id, err = util.read_var_int(reader)
    if err:
        return 0, "", 0, err
    channel_type, err = util.parse_ssh_string(reader)
    if err:
        return 0, "", 0, err
    max_packet_size, err = util.read_var_int(reader)
    if err:
        return 0, "", 0, err
    return conversation_control_stream_id, channel_type, max_packet_size, None

def parse_forwarding_header(channel_id, buf):
    address_family, err = util.read_var_int(buf)
    if err:
        return None, 0, err

    if address_family == stype.SSHAFIpv4:
        address = buf.read(4)
    elif address_family == stype.SSHAFIpv6:
        address = buf.read(16)
    else:
        return None, 0, ValueError(f"Invalid address family: {address_family}")

    port_buf = buf.read(2)
    if not port_buf:
        return None, 0, ValueError("Port buffer read failed")
    
    port = struct.unpack('>H', port_buf)[0]  # Unpack big-endian uint16
    return address, port, None


def parse_udp_forwarding_header(channel_id, buf):
    address, port, err = parse_forwarding_header(channel_id, buf)
    if err:
        return None, err
    return socket.getaddrinfo(address, port, socket.AF_UNSPEC, socket.SOCK_DGRAM), None

def parse_tcp_forwarding_header(channel_id, buf):
    address, port, err = parse_forwarding_header(channel_id, buf)
    if err:
        return None, err
    return socket.getaddrinfo(address, port, socket.AF_UNSPEC, socket.SOCK_STREAM), None

# Define types for SSH channel request handlers
PtyReqHandler = Callable[[Channel, PtyRequest, bool], None]
X11ReqHandler = Callable[[Channel, X11Request, bool], None]
ShellReqHandler = Callable[[Channel, ShellRequest, bool], None]
ExecReqHandler = Callable[[Channel, ExecRequest, bool], None]
SubsystemReqHandler = Callable[[Channel, SubsystemRequest, bool], None]
WindowChangeReqHandler = Callable[[Channel, WindowChangeRequest, bool], None]
SignalReqHandler = Callable[[Channel, SignalRequest, bool], None]
ExitStatusReqHandler = Callable[[Channel, ExitStatusRequest, bool], None]
ExitSignalReqHandler = Callable[[Channel, ExitSignalRequest, bool], None]

# Define a type for handling SSH channel data
ChannelDataHandler = Callable[[Channel, SSHDataType, str], None]

# Define an interface for channel close listeners
class ChannelCloseListener:
    def onChannelClose(self, channel: Channel):
        pass
   