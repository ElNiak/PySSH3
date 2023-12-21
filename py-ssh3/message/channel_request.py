import struct
import io
import net

# Define constants
SSH_MSG_CHANNEL_REQUEST = 98

SSHForwardingProtocol = {
    "SSHProtocolUDP": 0,
    "SSHForwardingProtocolTCP": 1,
}

SSHForwardingAddressFamily = {
    "SSHAFIpv4": 4,
    "SSHAFIpv6": 6,
}

# Define ChannelRequest interface
class ChannelRequest:
    def Write(self, buf):
        pass

    def Length(self):
        pass

    def RequestTypeStr(self):
        pass

# ChannelRequest implementations
class PtyRequest(ChannelRequest):
    def __init__(self, term, charWidth, charHeight, pixelWidth, pixelHeight, encodedTerminalModes):
        self.Term = term
        self.CharWidth = charWidth
        self.CharHeight = charHeight
        self.PixelWidth = pixelWidth
        self.PixelHeight = pixelHeight
        self.EncodedTerminalModes = encodedTerminalModes

    def Write(self, buf):
        # Write the attributes
        term_buf = self.Term.encode('utf-8')
        char_width_buf = struct.pack('>Q', self.CharWidth)
        char_height_buf = struct.pack('>Q', self.CharHeight)
        pixel_width_buf = struct.pack('>Q', self.PixelWidth)
        pixel_height_buf = struct.pack('>Q', self.PixelHeight)
        modes_buf = self.EncodedTerminalModes.encode('utf-8')

        buf.write(struct.pack('>B', len(term_buf)))
        buf.write(term_buf)
        buf.write(char_width_buf)
        buf.write(char_height_buf)
        buf.write(pixel_width_buf)
        buf.write(pixel_height_buf)
        buf.write(struct.pack('>B', len(modes_buf)))
        buf.write(modes_buf)

    def Length(self):
        term_len = len(self.Term.encode('utf-8'))
        modes_len = len(self.EncodedTerminalModes.encode('utf-8'))
        return 1 + term_len + 8 + 8 + 8 + 8 + 1 + modes_len

    def RequestTypeStr(self):
        return "pty-req"

class X11Request(ChannelRequest):
    def __init__(self, singleConnection, x11AuthenticationProtocol, x11AuthenticationCookie, x11ScreenNumber):
        self.SingleConnection = singleConnection
        self.X11AuthenticationProtocol = x11AuthenticationProtocol
        self.X11AuthenticationCookie = x11AuthenticationCookie
        self.X11ScreenNumber = x11ScreenNumber

    def Write(self, buf):
        buf.write(struct.pack('B', self.SingleConnection))
        protocol_buf = self.X11AuthenticationProtocol.encode('utf-8')
        cookie_buf = self.X11AuthenticationCookie.encode('utf-8')
        buf.write(struct.pack('>B', len(protocol_buf)))
        buf.write(protocol_buf)
        buf.write(struct.pack('>B', len(cookie_buf)))
        buf.write(cookie_buf)
        buf.write(struct.pack('>Q', self.X11ScreenNumber))

    def Length(self):
        protocol_len = len(self.X11AuthenticationProtocol.encode('utf-8'))
        cookie_len = len(self.X11AuthenticationCookie.encode('utf-8'))
        return 1 + protocol_len + 1 + cookie_len + 8

    def RequestTypeStr(self):
        return "x11-req"

class ShellRequest(ChannelRequest):
    def Write(self, buf):
        pass

    def Length(self):
        return 0

    def RequestTypeStr(self):
        return "shell"

class ExecRequest(ChannelRequest):
    def __init__(self, command):
        self.Command = command

    def Write(self, buf):
        command_buf = self.Command.encode('utf-8')
        buf.write(struct.pack('>B', len(command_buf)))
        buf.write(command_buf)

    def Length(self):
        return len(self.Command.encode('utf-8'))

    def RequestTypeStr(self):
        return "exec"

# ... (continue with other ChannelRequest implementations)

class ChannelRequestMessage:
    def __init__(self, wantReply, channelRequest):
        self.WantReply = wantReply
        self.ChannelRequest = channelRequest

    def Length(self):
        return 1 + len(self.ChannelRequest.RequestTypeStr()) + 1 + self.ChannelRequest.Length()

    def Write(self, buf):
        msg_type = struct.pack('>B', SSH_MSG_CHANNEL_REQUEST)
        request_type = self.ChannelRequest.RequestTypeStr().encode('utf-8')
        want_reply = struct.pack('B', self.WantReply)

        buf.write(msg_type)
        buf.write(struct.pack('>B', len(request_type)))
        buf.write(request_type)
        buf.write(want_reply)

        self.ChannelRequest.Write(buf)

# Define error types
class UserNotFound(Exception):
    def __init__(self, username):
        self.Username = username

    def __str__(self):
        return "User not found: " + self.Username

class ChannelNotFound(Exception):
    def __init__(self, channelID):
        self.ChannelID = channelID

    def __str__(self):
        return "Channel not found: " + str(self.ChannelID)

class InvalidSSHString(Exception):
    def __init__(self, reason):
        self.Reason = reason

    def __str__(self):
        return "Invalid SSH string: " + str(self.Reason)

class Unauthorized(Exception):
    def __str__(self):
        return "Unauthorized"

class BytesReadCloser:
    def __init__(self, reader):
        self.Reader = reader

    def Close(self):
        return None

# ... (continue with other error types and implementations)
