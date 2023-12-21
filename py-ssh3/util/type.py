import bytes
import fmt

# A JWT bearer token, encoded following the JWT specification
class JWTTokenString:
    def __init__(self, token):
        self.Token = token

class SSHForwardingProtocol:
    pass

class SSHForwardingAddressFamily:
    pass

class ChannelID:
    pass

# SSH forwarding protocols
SSHProtocolUDP = SSHForwardingProtocol(0)
SSHForwardingProtocolTCP = SSHForwardingProtocol(1)

# SSH forwarding address families
SSHAFIpv4 = SSHForwardingAddressFamily(4)
SSHAFIpv6 = SSHForwardingAddressFamily(6)

class UserNotFound:
    def __init__(self, username):
        self.Username = username

    def Error(self):
        return "User not found: " + self.Username

class ChannelNotFound:
    def __init__(self, channelID):
        self.ChannelID = channelID

    def Error(self):
        return "Channel not found: " + str(self.ChannelID)

class InvalidSSHString:
    def __init__(self, reason):
        self.Reason = reason

    def Error(self):
        return "Invalid SSH string: " + str(self.Reason)

class Unauthorized:
    def Error(self):
        return "Unauthorized"

class BytesReadCloser:
    def __init__(self, reader):
        self.Reader = reader

    def Close(self):
        return None

# Sends an SSH3 datagram. The function must know the ID of the channel.
class SSH3DatagramSenderFunc:
    def __init__(self, func):
        self.Func = func

# MessageSender interface
class MessageSender:
    def __init__(self, send_func):
        self.SendMessage = send_func
