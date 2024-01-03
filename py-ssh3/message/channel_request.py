import struct
import io
import util.util as util
import util.quic_util as quic_util
import util.type as stype
from typing import Tuple
import ipaddress
import logging
logger = logging.getLogger(__name__)

class PtyRequest:
    def __init__(self, term, char_width, char_height, pixel_width, pixel_height, encoded_terminal_modes):
        logger.debug("Creating PtyRequest object")
        self.term = term
        self.char_width = char_width
        self.char_height = char_height
        self.pixel_width = pixel_width
        self.pixel_height = pixel_height
        self.encoded_terminal_modes = encoded_terminal_modes

    def length(self):
        logger.debug("Calculating length of PtyRequest")
        return util.ssh_string_len(self.term) + \
               quic_util.var_int_len(self.char_width) + \
               quic_util.var_int_len(self.char_height) + \
               quic_util.var_int_len(self.pixel_width) + \
               quic_util.var_int_len(self.pixel_height) + \
               util.ssh_string_len(self.encoded_terminal_modes)

    def write(self, buf):
        logger.debug("Writing PtyRequest to buffer")
        if len(buf) < self.length():
            raise ValueError("Buffer too small to write PTY request")

        consumed = 0
        n = util.write_ssh_string(buf, self.term)
        consumed += n

        for attr in [self.char_width, self.char_height, self.pixel_width, self.pixel_height]:
            buf[consumed:consumed+quic_util.var_int_len(attr)] = quic_util.var_int_to_bytes(attr)
            consumed += quic_util.var_int_len(attr)

        n = util.write_ssh_string(buf[consumed:], self.encoded_terminal_modes)
        consumed += n

        return consumed

    def request_type_str(self):
        logger.debug("Getting request type string for PtyRequest")
        return "pty-req"

def parse_pty_request(buf):
    logger.debug("Parsing PtyRequest from buffer")
    term = util.parse_ssh_string(buf)
    char_width = quic_util.read_var_int(buf)
    char_height = quic_util.read_var_int(buf)
    pixel_width = quic_util.read_var_int(buf)
    pixel_height = quic_util.read_var_int(buf)
    encoded_terminal_modes = util.parse_ssh_string(buf)
    return PtyRequest(term, char_width, char_height, pixel_width, pixel_height, encoded_terminal_modes)

class X11Request:
    def __init__(self, single_connection, x11_authentication_protocol, x11_authentication_cookie, x11_screen_number):
        logger.debug("Creating X11Request object")
        self.single_connection = single_connection
        self.x11_authentication_protocol = x11_authentication_protocol
        self.x11_authentication_cookie = x11_authentication_cookie
        self.x11_screen_number = x11_screen_number

    def length(self):
        logger.debug("Calculating length of X11Request")
        return 1 + \
               util.ssh_string_len(self.x11_authentication_protocol) + \
               util.ssh_string_len(self.x11_authentication_cookie) + \
               quic_util.var_int_len(self.x11_screen_number)

    def write(self, buf):
        logger.debug("Writing X11Request to buffer")
        if len(buf) < self.length():
            raise ValueError("Buffer too small to write X11 request")

        consumed = 0
        buf[consumed] = 1 if self.single_connection else 0
        consumed += 1

        n = util.write_ssh_string(buf[consumed:], self.x11_authentication_protocol)
        consumed += n

        n = util.write_ssh_string(buf[consumed:], self.x11_authentication_cookie)
        consumed += n

        buf[consumed:consumed+quic_util.var_int_len(self.x11_screen_number)] = quic_util.var_int_to_bytes(self.x11_screen_number)
        consumed += quic_util.var_int_len(self.x11_screen_number)

        return consumed

    def request_type_str(self):
        logger.debug("Getting request type string for X11Request")
        return "x11-req"

def parse_x11_request(buf):
    logger.debug("Parsing X11Request from buffer")
    single_connection = util.read_boolean(buf)
    x11_authentication_protocol = util.parse_ssh_string(buf)
    x11_authentication_cookie = util.parse_ssh_string(buf)
    x11_screen_number = quic_util.read_var_int(buf)
    return X11Request(single_connection, x11_authentication_protocol, x11_authentication_cookie, x11_screen_number)

class ShellRequest:
    def length(self):
        logger.debug("Calculating length of ShellRequest")
        return 0

    def request_type_str(self):
        logger.debug("Getting request type string for ShellRequest")
        return "shell"

    def write(self, buf):
        logger.debug("Writing ShellRequest to buffer")
        return 0

def parse_shell_request(buf):
    logger.debug("Parsing ShellRequest from buffer")
    return ShellRequest()

class ExecRequest:
    def __init__(self, command):
        logger.debug("Creating ExecRequest object")
        self.command = command

    def length(self):
        logger.debug("Calculating length of ExecRequest")
        return util.ssh_string_len(self.command)

    def request_type_str(self):
        logger.debug("Getting request type string for ExecRequest")
        return "exec"

    def write(self, buf):
        logger.debug("Writing ExecRequest to buffer")
        return util.write_ssh_string(buf, self.command)

def parse_exec_request(buf):
    logger.debug("Parsing ExecRequest from buffer")
    command = util.parse_ssh_string(buf)
    return ExecRequest(command)

class SubsystemRequest:
    def __init__(self, subsystem_name):
        logger.debug("Creating SubsystemRequest object")
        self.subsystem_name = subsystem_name

    def length(self):
        logger.debug("Calculating length of SubsystemRequest")
        return util.ssh_string_len(self.subsystem_name)

    def request_type_str(self):
        logger.debug("Getting request type string for SubsystemRequest")
        return "subsystem"

    def write(self, buf):
        logger.debug("Writing SubsystemRequest to buffer")
        return util.write_ssh_string(buf, self.subsystem_name)

def parse_subsystem_request(buf):
    logger.debug("Parsing SubsystemRequest from buffer")
    subsystem_name = util.parse_ssh_string(buf)
    return SubsystemRequest(subsystem_name)

class WindowChangeRequest:
    def __init__(self, char_width, char_height, pixel_width, pixel_height):
        logger.debug("Creating WindowChangeRequest object")
        self.char_width = char_width
        self.char_height = char_height
        self.pixel_width = pixel_width
        self.pixel_height = pixel_height

    def length(self):
        logger.debug("Calculating length of WindowChangeRequest")
        return sum(quic_util.var_int_len(attr) for attr in [self.char_width, self.char_height, self.pixel_width, self.pixel_height])

    def request_type_str(self):
        logger.debug("Getting request type string for WindowChangeRequest")
        return "window-change"

    def write(self, buf):
        logger.debug("Writing WindowChangeRequest to buffer")
        consumed = 0
        for attr in [self.char_width, self.char_height, self.pixel_width, self.pixel_height]:
            buf[consumed:consumed+quic_util.var_int_len(attr)] = quic_util.var_int_to_bytes(attr)
            consumed += quic_util.var_int_len(attr)
        return consumed

def parse_window_change_request(buf):
    logger.debug("Parsing WindowChangeRequest from buffer")
    char_width = quic_util.read_var_int(buf)
    char_height = quic_util.read_var_int(buf)
    pixel_width = quic_util.read_var_int(buf)
    pixel_height = quic_util.read_var_int(buf)
    return WindowChangeRequest(char_width, char_height, pixel_width, pixel_height)

class SignalRequest:
    def __init__(self, signal_name_without_sig):
        logger.debug("Creating SignalRequest object")
        self.signal_name_without_sig = signal_name_without_sig

    def length(self):
        logger.debug("Calculating length of SignalRequest")
        return util.ssh_string_len(self.signal_name_without_sig)

    def request_type_str(self):
        logger.debug("Getting request type string for SignalRequest")
        return "signal"

    def write(self, buf):
        logger.debug("Writing SignalRequest to buffer")
        return util.write_ssh_string(buf, self.signal_name_without_sig)

def parse_signal_request(buf):
    logger.debug("Parsing SignalRequest from buffer")
    signal_name_without_sig = util.parse_ssh_string(buf)
    return SignalRequest(signal_name_without_sig)

class ExitStatusRequest:
    def __init__(self, exit_status):
        logger.debug("Creating ExitStatusRequest object")
        self.exit_status = exit_status

    def length(self):
        logger.debug("Calculating length of ExitStatusRequest")
        return quic_util.var_int_len(self.exit_status)

    def request_type_str(self):
        logger.debug("Getting request type string for ExitStatusRequest")
        return "exit-status"

    def write(self, buf):
        logger.debug("Writing ExitStatusRequest to buffer")
        buf[:quic_util.var_int_len(self.exit_status)] = quic_util.var_int_to_bytes(self.exit_status)
        return quic_util.var_int_len(self.exit_status)

def parse_exit_status_request(buf):
    logger.debug("Parsing ExitStatusRequest from buffer")
    exit_status = quic_util.read_var_int(buf)
    return ExitStatusRequest(exit_status)

class ExitSignalRequest:
    def __init__(self, signal_name_without_sig, core_dumped, error_message_utf8, language_tag):
        logger.debug("Creating ExitSignalRequest object")
        self.signal_name_without_sig = signal_name_without_sig
        self.core_dumped = core_dumped
        self.error_message_utf8 = error_message_utf8
        self.language_tag = language_tag

    def length(self):
        logger.debug("Calculating length of ExitSignalRequest")
        return util.ssh_string_len(self.signal_name_without_sig) + 1 + \
               util.ssh_string_len(self.error_message_utf8) + util.ssh_string_len(self.language_tag)

    def request_type_str(self):
        logger.debug("Getting request type string for ExitSignalRequest")
        return "exit-signal"

    def write(self, buf):
        logger.debug("Writing ExitSignalRequest to buffer")
        consumed = util.write_ssh_string(buf, self.signal_name_without_sig)
        buf[consumed] = 1 if self.core_dumped else 0
        consumed += 1
        consumed += util.write_ssh_string(buf[consumed:], self.error_message_utf8)
        consumed += util.write_ssh_string(buf[consumed:], self.language_tag)
        return consumed

def parse_exit_signal_request(buf):
    logger.debug("Parsing ExitSignalRequest from buffer")
    signal_name_without_sig = util.parse_ssh_string(buf)
    core_dumped = util.read_boolean(buf)
    error_message_utf8 = util.parse_ssh_string(buf)
    language_tag = util.parse_ssh_string(buf)
    return ExitSignalRequest(signal_name_without_sig, core_dumped, error_message_utf8, language_tag)


class ForwardingRequest:
    def __init__(self, protocol, address_family, ip_address, port):
        logger.debug("Creating ForwardingRequest object")
        self.protocol = protocol
        self.address_family = address_family
        self.ip_address = ip_address
        self.port = port

    def length(self) -> int:
        logger.debug("Calculating length of ForwardingRequest")
        return quic_util.var_int_len(self.protocol) + \
               quic_util.var_int_len(self.address_family) + \
               len(self.ip_address.packed) + \
               2  # Length of port

    def request_type_str(self) -> str:
        logger.debug("Getting request type string for ForwardingRequest")
        return "forward-port"

    def write(self, buf: bytearray) -> int:
        logger.debug("Writing ForwardingRequest to buffer")
        consumed = 0
        buf.extend(quic_util.var_int_to_bytes(self.protocol))
        consumed += quic_util.var_int_len(self.protocol)

        buf.extend(quic_util.var_int_to_bytes(self.address_family))
        consumed += quic_util.var_int_len(self.address_family)

        buf.extend(self.ip_address.packed)
        consumed += len(self.ip_address.packed)

        buf.extend(struct.pack('!H', self.port))  # Network byte order (big endian)
        consumed += 2

        return consumed

def parse_forwarding_request(buf: io.BytesIO) -> Tuple[ForwardingRequest, Exception]:
    logger.debug("Parsing ForwardingRequest from buffer")
    protocol, err = quic_util.read_var_int(buf)
    if err:
        return None, err

    if protocol not in [stype.SSHForwardingProtocolTCP, stype.SSHProtocolUDP]:
        return None, ValueError(f"Invalid protocol number: {protocol}")

    address_family, err = quic_util.read_var_int(buf)
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
