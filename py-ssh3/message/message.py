import io
import struct
from util.util import parse_ssh_string, ssh_string_len, var_int_len, append_var_int, write_ssh_string

# Constants for SSH message types
SSH_MSG_DISCONNECT = 1
SSH_MSG_IGNORE = 2
SSH_MSG_UNIMPLEMENTED = 3
SSH_MSG_DEBUG = 4
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_SERVICE_ACCEPT = 6
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_USERAUTH_FAILURE = 51
SSH_MSG_USERAUTH_SUCCESS = 52
SSH_MSG_USERAUTH_BANNER = 53
SSH_MSG_GLOBAL_REQUEST = 80
SSH_MSG_REQUEST_SUCCESS = 81
SSH_MSG_REQUEST_FAILURE = 82
SSH_MSG_CHANNEL_OPEN = 90
SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
SSH_MSG_CHANNEL_OPEN_FAILURE = 92
SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
SSH_MSG_CHANNEL_DATA = 94
SSH_MSG_CHANNEL_EXTENDED_DATA = 95
SSH_MSG_CHANNEL_EOF = 96
SSH_MSG_CHANNEL_CLOSE = 97
SSH_MSG_CHANNEL_REQUEST = 98
SSH_MSG_CHANNEL_SUCCESS = 99
SSH_MSG_CHANNEL_FAILURE = 100

# Enum for SSH data types
class SSHDataType:
    SSH_EXTENDED_DATA_NONE = 0
    SSH_EXTENDED_DATA_STDERR = 1

class Message:
    def write(self, buf):
        pass

    def length(self):
        pass

class ChannelRequestMessage(Message):
    def __init__(self, want_reply, channel_request):
        self.want_reply = want_reply
        self.channel_request = channel_request

    def length(self):
        # msg type + request type + wantReply + request content
        return len(var_int_len(SSH_MSG_CHANNEL_REQUEST)) + \
               ssh_string_len(self.channel_request.request_type_str()) + 1 + \
               self.channel_request.length()

    def write(self, buf):
        if len(buf) < self.length():
            raise ValueError(f"Buffer too small to write message for channel request of type {type(self.channel_request)}: {len(buf)} < {self.length()}")

        consumed = 0
        msg_type_buf = append_var_int(None, SSH_MSG_CHANNEL_REQUEST)
        buf[consumed:consumed+len(msg_type_buf)] = msg_type_buf
        consumed += len(msg_type_buf)

        n = write_ssh_string(buf[consumed:], self.channel_request.request_type_str())
        consumed += n

        buf[consumed] = 1 if self.want_reply else 0
        consumed += 1

        n = self.channel_request.write(buf[consumed:])
        consumed += n

        return consumed


class ChannelOpenConfirmationMessage(Message):
    def __init__(self, max_packet_size):
        self.max_packet_size = max_packet_size

    def write(self, buf):
        msg_type = SSH_MSG_CHANNEL_OPEN_CONFIRMATION
        buf.write(struct.pack('>Q', msg_type))
        buf.write(struct.pack('>Q', self.max_packet_size))

    def length(self):
        return 2 * struct.calcsize('>Q')

class ChannelOpenFailureMessage(Message):
    def __init__(self, reason_code, error_message_utf8, language_tag):
        self.reason_code = reason_code
        self.error_message_utf8 = error_message_utf8
        self.language_tag = language_tag

    def write(self, buf):
        msg_type = SSH_MSG_CHANNEL_OPEN_FAILURE
        buf.write(struct.pack('>Q', msg_type))
        buf.write(struct.pack('>Q', self.reason_code))
        self._write_ssh_string(buf, self.error_message_utf8)
        self._write_ssh_string(buf, self.language_tag)

    def length(self):
        msg_type_len = struct.calcsize('>Q')
        reason_code_len = struct.calcsize('>Q')
        error_message_len = self._ssh_string_length(self.error_message_utf8)
        language_tag_len = self._ssh_string_length(self.language_tag)
        return msg_type_len + reason_code_len + error_message_len + language_tag_len

    def _write_ssh_string(self, buf, value):
        encoded_value = value.encode('utf-8')
        buf.write(struct.pack('>I', len(encoded_value)))
        buf.write(encoded_value)

    def _ssh_string_length(self, value):
        return struct.calcsize('>I') + len(value.encode('utf-8'))

class DataOrExtendedDataMessage(Message):
    def __init__(self, data_type, data):
        self.data_type = data_type
        self.data = data

    def write(self, buf):
        if self.data_type == SSHDataType.SSH_EXTENDED_DATA_NONE:
            msg_type = SSH_MSG_CHANNEL_DATA
        else:
            msg_type = SSH_MSG_CHANNEL_EXTENDED_DATA
            buf.write(struct.pack('>Q', self.data_type))
        buf.write(struct.pack('>Q', msg_type))
        self._write_ssh_string(buf, self.data)

    def length(self):
        msg_type_len = struct.calcsize('>Q')
        if self.data_type == SSHDataType.SSH_EXTENDED_DATA_NONE:
            return msg_type_len + self._ssh_string_length(self.data)
        data_type_len = struct.calcsize('>Q')
        return msg_type_len + data_type_len + self._ssh_string_length(self.data)

    def _write_ssh_string(self, buf, value):
        encoded_value = value.encode('utf-8')
        buf.write(struct.pack('>I', len(encoded_value)))
        buf.write(encoded_value)

    def _ssh_string_length(self, value):
        return struct.calcsize('>I') + len(value.encode('utf-8'))

def parse_channel_open_confirmation_message(buf):
    max_packet_size = struct.unpack('>Q', buf.read(8))[0]
    return ChannelOpenConfirmationMessage(max_packet_size)

def parse_channel_open_failure_message(buf):
    reason_code = struct.unpack('>Q', buf.read(8))[0]
    error_message_utf8 = parse_ssh_string(buf)
    language_tag = parse_ssh_string(buf)
    return ChannelOpenFailureMessage(reason_code, error_message_utf8, language_tag)

def parse_data_message(buf):
    data = parse_ssh_string(buf)
    return DataOrExtendedDataMessage(SSHDataType.SSH_EXTENDED_DATA_NONE, data)

def parse_extended_data_message(buf):
    data_type = struct.unpack('>Q', buf.read(8))[0]
    data = parse_ssh_string(buf)
    return DataOrExtendedDataMessage(data_type, data)

def parse_message(r):
    type_id = struct.unpack('>Q', r.read(8))[0]
    if type_id == SSH_MSG_CHANNEL_REQUEST:
        pass  # Implement ParseRequestMessage function here
    elif type_id == SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        return parse_channel_open_confirmation_message(r)
    elif type_id == SSH_MSG_CHANNEL_OPEN_FAILURE:
        return parse_channel_open_failure_message(r)
    elif type_id in (SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA):
        if type_id == SSH_MSG_CHANNEL_DATA:
            return parse_data_message(r)
        else:
            return parse_extended_data_message(r)
    else:
        raise ValueError("Not implemented")

# Example usage:
if __name__ == "__main__":
    # You can test the code here
    pass
