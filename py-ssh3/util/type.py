import io

# A JWT bearer token, encoded following the JWT specification
class JWTTokenString:
    def __init__(self, token:str):
        self.token = token

class SSHForwardingProtocol:
    def __init__(self, value:int):
        self.value = value

class SSHForwardingAddressFamily:
    def __init__(self, value:int):
        self.value = value

class ChannelID:
    def __init__(self, value:int):
        self.value = value

# SSH forwarding protocols
SSHProtocolUDP           = SSHForwardingProtocol(0)
SSHForwardingProtocolTCP = SSHForwardingProtocol(1)

# SSH forwarding address families
SSHAFIpv4 = SSHForwardingAddressFamily(4)
SSHAFIpv6 = SSHForwardingAddressFamily(6)

class UserNotFound(Exception):
    def __init__(self, username):
        super().__init__("User not found: " + username)
        self.username = username

class ChannelNotFound(Exception):
    def __init__(self, channelID):
        super().__init__("Channel not found: " + str(channelID))
        self.channel_id = channelID

class InvalidSSHString(Exception):
    def __init__(self, reason):
        super().__init__("Invalid SSH string: " + str(reason))
        self.reason = reason

class Unauthorized(Exception):
    def __init__(self):
        super().__init__("Unauthorized")

# class BytesReadCloser(io.BufferedReader):
#     def __init__(self, reader):
#         super().__init__(reader)
#         self.reader = reader

#     def read(self):
#         return None

# Sends an SSH3 datagram. The function must know the ID of the channel.
class SSH3DatagramSenderFunc:
    def __init__(self, func):
        self.Func = func

# MessageSender interface
class MessageSender:
    def __init__(self, send_func):
        self.SendMessage = send_func
