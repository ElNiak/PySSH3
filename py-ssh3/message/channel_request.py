import struct
import io
import util.util as util
import util.type as stype
from message import message
from typing import Tuple
import ipaddress

class ChannelRequestMessage:
    def __init__(self, want_reply, channel_request):
        self.want_reply = want_reply
        self.channel_request = channel_request

    def length(self):
        # msg type + request type + wantReply + request content
        return len(util.var_int_len(message.SSH_MSG_CHANNEL_REQUEST)) + \
               util.ssh_string_len(self.channel_request.request_type_str()) + 1 + \
               self.channel_request.length()

    def write(self, buf):
        if len(buf) < self.length():
            raise ValueError(f"Buffer too small to write message for channel request of type {type(self.channel_request)}: {len(buf)} < {self.length()}")

        consumed = 0
        msg_type_buf = util.append_var_int(None, message.SSH_MSG_CHANNEL_REQUEST)
        buf[consumed:consumed+len(msg_type_buf)] = msg_type_buf
        consumed += len(msg_type_buf)

        n = util.write_ssh_string(buf[consumed:], self.channel_request.request_type_str())
        consumed += n

        buf[consumed] = 1 if self.want_reply else 0
        consumed += 1

        n = self.channel_request.write(buf[consumed:])
        consumed += n

        return consumed

def parse_request_message(buf):
    request_type, err = util.parse_ssh_string(buf)
    if err:
        return None, err

    want_reply = struct.unpack('>b', buf.read(1))[0]
    parse_func = channel_request_parse_funcs.get(request_type)
    if not parse_func:
        return None, ValueError(f"Invalid request message type {request_type}")

    channel_request, err = parse_func(buf)
    if err and not isinstance(err, io.EOFError):
        return None, err

    return ChannelRequestMessage(want_reply, channel_request), err

class PtyRequest:
    def __init__(self, term, char_width, char_height, pixel_width, pixel_height, encoded_terminal_modes):
        self.term = term
        self.char_width = char_width
        self.char_height = char_height
        self.pixel_width = pixel_width
        self.pixel_height = pixel_height
        self.encoded_terminal_modes = encoded_terminal_modes

    def length(self):
        return util.ssh_string_len(self.term) + \
               util.var_int_len(self.char_width) + \
               util.var_int_len(self.char_height) + \
               util.var_int_len(self.pixel_width) + \
               util.var_int_len(self.pixel_height) + \
               util.ssh_string_len(self.encoded_terminal_modes)

    def write(self, buf):
        if len(buf) < self.length():
            raise ValueError("Buffer too small to write PTY request")

        consumed = 0
        n = util.write_ssh_string(buf, self.term)
        consumed += n

        for attr in [self.char_width, self.char_height, self.pixel_width, self.pixel_height]:
            buf[consumed:consumed+util.var_int_len(attr)] = util.var_int_to_bytes(attr)
            consumed += util.var_int_len(attr)

        n = util.write_ssh_string(buf[consumed:], self.encoded_terminal_modes)
        consumed += n

        return consumed

    def request_type_str(self):
        return "pty-req"

def parse_pty_request(buf):
    term = util.parse_ssh_string(buf)
    char_width = util.read_var_int(buf)
    char_height = util.read_var_int(buf)
    pixel_width = util.read_var_int(buf)
    pixel_height = util.read_var_int(buf)
    encoded_terminal_modes = util.parse_ssh_string(buf)
    return PtyRequest(term, char_width, char_height, pixel_width, pixel_height, encoded_terminal_modes)

class X11Request:
    def __init__(self, single_connection, x11_authentication_protocol, x11_authentication_cookie, x11_screen_number):
        self.single_connection = single_connection
        self.x11_authentication_protocol = x11_authentication_protocol
        self.x11_authentication_cookie = x11_authentication_cookie
        self.x11_screen_number = x11_screen_number

    def length(self):
        return 1 + \
               util.ssh_string_len(self.x11_authentication_protocol) + \
               util.ssh_string_len(self.x11_authentication_cookie) + \
               util.var_int_len(self.x11_screen_number)

    def write(self, buf):
        if len(buf) < self.length():
            raise ValueError("Buffer too small to write X11 request")

        consumed = 0
        buf[consumed] = 1 if self.single_connection else 0
        consumed += 1

        n = util.write_ssh_string(buf[consumed:], self.x11_authentication_protocol)
        consumed += n

        n = util.write_ssh_string(buf[consumed:], self.x11_authentication_cookie)
        consumed += n

        buf[consumed:consumed+util.var_int_len(self.x11_screen_number)] = util.var_int_to_bytes(self.x11_screen_number)
        consumed += util.var_int_len(self.x11_screen_number)

        return consumed

    def request_type_str(self):
        return "x11-req"

def parse_x11_request(buf):
    single_connection = util.read_boolean(buf)
    x11_authentication_protocol = util.parse_ssh_string(buf)
    x11_authentication_cookie = util.parse_ssh_string(buf)
    x11_screen_number = util.read_var_int(buf)
    return X11Request(single_connection, x11_authentication_protocol, x11_authentication_cookie, x11_screen_number)

class ShellRequest:
    def length(self):
        return 0

    def request_type_str(self):
        return "shell"

    def write(self, buf):
        return 0

def parse_shell_request(buf):
    return ShellRequest()

class ExecRequest:
    def __init__(self, command):
        self.command = command

    def length(self):
        return util.ssh_string_len(self.command)

    def request_type_str(self):
        return "exec"

    def write(self, buf):
        return util.write_ssh_string(buf, self.command)

def parse_exec_request(buf):
    command = util.parse_ssh_string(buf)
    return ExecRequest(command)

class SubsystemRequest:
    def __init__(self, subsystem_name):
        self.subsystem_name = subsystem_name

    def length(self):
        return util.ssh_string_len(self.subsystem_name)

    def request_type_str(self):
        return "subsystem"

    def write(self, buf):
        return util.write_ssh_string(buf, self.subsystem_name)

def parse_subsystem_request(buf):
    subsystem_name = util.parse_ssh_string(buf)
    return SubsystemRequest(subsystem_name)

class WindowChangeRequest:
    def __init__(self, char_width, char_height, pixel_width, pixel_height):
        self.char_width = char_width
        self.char_height = char_height
        self.pixel_width = pixel_width
        self.pixel_height = pixel_height

    def length(self):
        return sum(util.var_int_len(attr) for attr in [self.char_width, self.char_height, self.pixel_width, self.pixel_height])

    def request_type_str(self):
        return "window-change"

    def write(self, buf):
        consumed = 0
        for attr in [self.char_width, self.char_height, self.pixel_width, self.pixel_height]:
            buf[consumed:consumed+util.var_int_len(attr)] = util.var_int_to_bytes(attr)
            consumed += util.var_int_len(attr)
        return consumed

def parse_window_change_request(buf):
    char_width = util.read_var_int(buf)
    char_height = util.read_var_int(buf)
    pixel_width = util.read_var_int(buf)
    pixel_height = util.read_var_int(buf)
    return WindowChangeRequest(char_width, char_height, pixel_width, pixel_height)

class SignalRequest:
    def __init__(self, signal_name_without_sig):
        self.signal_name_without_sig = signal_name_without_sig

    def length(self):
        return util.ssh_string_len(self.signal_name_without_sig)

    def request_type_str(self):
        return "signal"

    def write(self, buf):
        return util.write_ssh_string(buf, self.signal_name_without_sig)

def parse_signal_request(buf):
    signal_name_without_sig = util.parse_ssh_string(buf)
    return SignalRequest(signal_name_without_sig)

class ExitStatusRequest:
    def __init__(self, exit_status):
        self.exit_status = exit_status

    def length(self):
        return util.var_int_len(self.exit_status)

    def request_type_str(self):
        return "exit-status"

    def write(self, buf):
        buf[:util.var_int_len(self.exit_status)] = util.var_int_to_bytes(self.exit_status)
        return util.var_int_len(self.exit_status)

def parse_exit_status_request(buf):
    exit_status = util.read_var_int(buf)
    return ExitStatusRequest(exit_status)

class ExitSignalRequest:
    def __init__(self, signal_name_without_sig, core_dumped, error_message_utf8, language_tag):
        self.signal_name_without_sig = signal_name_without_sig
        self.core_dumped = core_dumped
        self.error_message_utf8 = error_message_utf8
        self.language_tag = language_tag

    def length(self):
        return util.ssh_string_len(self.signal_name_without_sig) + 1 + \
               util.ssh_string_len(self.error_message_utf8) + util.ssh_string_len(self.language_tag)

    def request_type_str(self):
        return "exit-signal"

    def write(self, buf):
        consumed = util.write_ssh_string(buf, self.signal_name_without_sig)
        buf[consumed] = 1 if self.core_dumped else 0
        consumed += 1
        consumed += util.write_ssh_string(buf[consumed:], self.error_message_utf8)
        consumed += util.write_ssh_string(buf[consumed:], self.language_tag)
        return consumed

def parse_exit_signal_request(buf):
    signal_name_without_sig = util.parse_ssh_string(buf)
    core_dumped = util.read_boolean(buf)
    error_message_utf8 = util.parse_ssh_string(buf)
    language_tag = util.parse_ssh_string(buf)
    return ExitSignalRequest(signal_name_without_sig, core_dumped, error_message_utf8, language_tag)


class ForwardingRequest:
    def __init__(self, protocol, address_family, ip_address, port):
        self.protocol = protocol
        self.address_family = address_family
        self.ip_address = ip_address
        self.port = port

    def length(self) -> int:
        return util.var_int_len(self.protocol) + \
               util.var_int_len(self.address_family) + \
               len(self.ip_address.packed) + \
               2  # Length of port

    def request_type_str(self) -> str:
        return "forward-port"

    def write(self, buf: bytearray) -> int:
        consumed = 0
        buf.extend(util.var_int_to_bytes(self.protocol))
        consumed += util.var_int_len(self.protocol)

        buf.extend(util.var_int_to_bytes(self.address_family))
        consumed += util.var_int_len(self.address_family)

        buf.extend(self.ip_address.packed)
        consumed += len(self.ip_address.packed)

        buf.extend(struct.pack('!H', self.port))  # Network byte order (big endian)
        consumed += 2

        return consumed

def parse_forwarding_request(buf: io.BytesIO) -> Tuple[ForwardingRequest, Exception]:
    protocol, err = util.read_var_int(buf)
    if err:
        return None, err

    if protocol not in [stype.SSHForwardingProtocolTCP, stype.SSHProtocolUDP]:
        return None, ValueError(f"Invalid protocol number: {protocol}")

    address_family, err = util.read_var_int(buf)
    if err:
        return None, err

    if address_family == util.SSHAFIpv4:
        address_bytes = buf.read(4)
    elif address_family == util.SSHAFIpv6:
        address_bytes = buf.read(16)
    else:
        return None, ValueError(f"Invalid address family: {address_family}")

    address = ipaddress.ip_address(address_bytes)

    port_buf = buf.read(2)
    port = struct.unpack('!H', port_buf)[0]  # Network byte order (big endian)

    return ForwardingRequest(protocol, address_family, address, port), None


channel_request_parse_funcs = {
    "pty-req": parse_pty_request,
    "x11-req": parse_x11_request,
    "shell": parse_shell_request,
    "exec": parse_exec_request,
    "subsystem": parse_subsystem_request,
    "window-change": parse_window_change_request,
    "signal": parse_signal_request,
    "exit-status": parse_exit_status_request,
    "exit-signal": parse_exit_signal_request,
    "forward-port": parse_forwarding_request
}

