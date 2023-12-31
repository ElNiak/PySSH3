import os
import signal
# import asyncio
import signal
import fcntl
import struct
import termios
import logging
# import asyncio
import os
import logging
from util.linux_util import *
import message.message as ssh3_message
import message.channel_request as ssh3_channel
import argparse
import sys
import util.waitgroup as sync
from http3.http3_server import *
from aioquic.quic.configuration import QuicConfiguration
from ssh3.ssh3_server import SSH3Server
from ssh3.conversation import Conversation
from ssh3.channel import *
from util.linux_util.linux_user import User, get_user
from linux_server.auth import *
import util.globals as glob
from http3.http3_server import *

from starlette.applications import Router
from starlette.applications import Starlette
from starlette.types import Receive, Scope, Send
from starlette.routing import Route

log = logging.getLogger(__name__)

# Define signal mappings
signals = {
    "SIGABRT": signal.SIGABRT,
    "SIGALRM": signal.SIGALRM,
    "SIGBUS": signal.SIGBUS,
    "SIGCHLD": signal.SIGCHLD,
    "SIGCONT": signal.SIGCONT,
    "SIGFPE": signal.SIGFPE,
    "SIGHUP": signal.SIGHUP,
    "SIGILL": signal.SIGILL,
    "SIGINT": signal.SIGINT,
    "SIGIO": signal.SIGIO,
    "SIGIOT": signal.SIGIOT,
    "SIGKILL": signal.SIGKILL,
    "SIGPIPE": signal.SIGPIPE,
    "SIGPOLL": signal.SIGPOLL,
    "SIGPROF": signal.SIGPROF,
    "SIGPWR": signal.SIGPWR,
    "SIGQUIT": signal.SIGQUIT,
    "SIGRTMAX": signal.SIGRTMAX,
    "SIGRTMIN": signal.SIGRTMIN,
    "SIGSEGV": signal.SIGSEGV,
    "SIGSTOP": signal.SIGSTOP,
    "SIGSYS": signal.SIGSYS,
    "SIGTERM": signal.SIGTERM,
    "SIGTRAP": signal.SIGTRAP,
    "SIGTSTP": signal.SIGTSTP,
    "SIGTTIN": signal.SIGTTIN,
    "SIGTTOU": signal.SIGTTOU,
    "SIGURG": signal.SIGURG,
    "SIGUSR1": signal.SIGUSR1,
    "SIGUSR2": signal.SIGUSR2,
    "SIGVTALRM": signal.SIGVTALRM,
    "SIGWINCH": signal.SIGWINCH,
    "SIGXCPU": signal.SIGXCPU,
    "SIGXFSZ": signal.SIGXFSZ
}

    
class ChannelType:
    LARVAL = 0
    OPEN = 1

channel_type = ChannelType()

class OpenPty:
    def __init__(self, pty, tty, win_size, term):
        self.pty = pty
        self.tty = tty
        self.win_size = win_size
        self.term = term

class RunningCommand:
    def __init__(self, stdout_r, stderr_r, stdin_w):
        self.stdout_r = stdout_r
        self.stderr_r = stderr_r
        self.stdin_w = stdin_w

class RunningSession:
    def __init__(self):
        self.channel_state = None
        self.pty = None
        self.running_cmd = None
        self.auth_agent_socket_path = None

running_sessions = {}

def set_winsize(f, char_width, char_height, pix_width, pix_height):
    winsize = struct.pack("HHHH", char_height, char_width, pix_width, pix_height)
    fcntl.ioctl(f, termios.TIOCSWINSZ, winsize)

def setup_env(user, running_command, auth_agent_socket_path):
    # Set up the environment variables for the subprocess
    running_command.cmd.env.append(f"HOME={user.dir}")
    running_command.cmd.env.append(f"USER={user.username}")
    running_command.cmd.env.append("PATH=/usr/bin:/bin:/usr/sbin:/sbin")
    if auth_agent_socket_path != "":
        running_command.cmd.env.append(f"SSH_AUTH_SOCK={auth_agent_socket_path}")

async def forward_udp_in_background(ctx, channel, conn):
    async def receive_datagram():
        while True:
            try:
                datagram, err = await channel.receive_datagram(ctx)
                if err is not None:
                    log.error(f"could not receive datagram: {err}")
                    return
                await conn.write(datagram)
            except asyncio.CancelledError:
                return

    async def send_datagram():
        buf = bytearray(1500)
        while True:
            try:
                n, err = await conn.read(buf)
                if err is not None:
                    log.error(f"could read datagram on UDP socket: {err}")
                    return
                await channel.send_datagram(buf[:n])
            except asyncio.CancelledError:
                return

    receive_task = asyncio.create_task(receive_datagram())
    send_task = asyncio.create_task(send_datagram())

    try:
        await asyncio.gather(receive_task, send_task)
    finally:
        receive_task.cancel()
        send_task.cancel()
        await asyncio.gather(receive_task, send_task, return_exceptions=True)

async def forward_tcp_in_background(ctx, channel, conn):
    async def read_from_tcp_socket():
        try:
            while True:
                data = await conn.recv(4096)
                if not data:
                    break
                await channel.send_data(data)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error(f"could read data on TCP socket: {e}")

    async def read_from_ssh_channel():
        buf = bytearray(channel.max_packet_size())
        try:
            while True:
                data = await channel.receive_data()
                if not data:
                    break
                await conn.sendall(data)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error(f"could send data on channel: {e}")

    read_tcp_task = asyncio.create_task(read_from_tcp_socket())
    read_ssh_task = asyncio.create_task(read_from_ssh_channel())

    try:
        await asyncio.gather(read_tcp_task, read_ssh_task)
    finally:
        read_tcp_task.cancel()
        read_ssh_task.cancel()
        await asyncio.gather(read_tcp_task, read_ssh_task, return_exceptions=True)

async def exec_cmd_in_background(channel, open_pty, user, running_command, auth_agent_socket_path):
    # Execute command in background and handle its output
    pass

def new_pty_req(user, channel, request, want_reply):
    # Handle PTY request
    pass

def new_x11_req(user, channel, request, want_reply):
    # Handle X11 request (if applicable)
    pass

def new_command(user, channel, login_shell, command, args):
    # Execute a new command
    pass

def new_shell_req(user, channel, want_reply):
    # Handle shell request
    pass

def new_command_in_shell_req(user, channel, want_reply, command):
    # Execute command within shell
    pass

def new_subsystem_req(user, channel, request, want_reply):
    # Handle subsystem request
    pass

def new_window_change_req(user, channel, request, want_reply):
    # Handle window change request
    pass

def new_signal_req(user, channel, request, want_reply):
    # Handle signal request
    pass

def new_exit_status_req(user, channel, request, want_reply):
    # Handle exit status request
    pass

def new_exit_signal_req(user, channel, request, want_reply):
    # Handle exit signal request
    pass

async def handle_udp_forwarding_channel(user: User, conv: Conversation, channel: UDPForwardingChannelImpl):
    """
    Handle UDP forwarding for a specific channel in an SSH3 conversation.

    Args:
    user: The user object containing user information. # TODO seems not used
    conv: The SSH3 conversation object.                # TODO seems not used
    channel: The UDP forwarding channel implementation.

    Returns:
    None if successful, or an error if any occurs.
    """
    # Note: Rights for socket creation are not checked
    # The socket is opened with the process's uid and gid
    try:
        # Create a UDP socket
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Connect the socket to the remote address
        conn.connect(channel.remote_addr)

        # Start forwarding UDP in background
        await forward_udp_in_background(channel, conn)
    except Exception as e:
        return e
    return None

async def handle_tcp_forwarding_channel(user: User, conv: Conversation, channel:TCPForwardingChannelImpl):
    """
    Handle TCP forwarding for a specific channel in an SSH3 conversation.

    Args:
    user: The user object containing user information.
    conv: The SSH3 conversation object.
    channel: The TCP forwarding channel implementation.

    Returns:
    None if successful, or an error if any occurs.
    """
    # Note: Rights for socket creation are not checked
    # The socket is opened with the process's uid and gid
    try:
        # Create a TCP socket
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect the socket to the remote address
        conn.connect(channel.remote_addr)

        # Start forwarding TCP in background
        await forward_tcp_in_background(channel, conn)
    except Exception as e:
        return e
    return None

def new_data_req(user, channel, request):
    # Handle data request
    running_session, ok = running_sessions[channel]
    if not ok:
        return Exception("could not find running session for channel")
    if running_session.channel_state == channel_type.LARVAL:
        return Exception("invalid data on ssh channel with LARVAL state")
    if channel.channel_type =="session":
        if running_session.running_cmd != None:
            if request.data_type == ssh3_message.SSHDataType.SSH_EXTENDED_DATA_NONE:
                running_session.running_cmd.stdin_w.write(request.data)
            else:
                return Exception("invalid data type on ssh channel with session channel type pty")
        else:
            return Exception("could not find running command for channel")
    return None

async def handle_auth_agent_socket_conn(conn, conversation):
    # Handle authentication agent socket connection
    pass

async def listen_and_accept_auth_sockets(conversation, listener):
    # Listen and accept authentication agent sockets
    pass

async def open_agent_socket_and_forward_agent(conv, user):
    # Open an agent socket and forward agent
    pass

def file_exists(path):
    # Check if a file exists
    return os.path.exists(path)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="[::]:443", help="the address:port pair to listen to, e.g. 0.0.0.0:443")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode, if set")
    parser.add_argument("--enablePasswordLogin", action="store_true", help="if set, enable password authentication (disabled by default)")
    parser.add_argument("--urlPath", default="/ssh3-term", help="the secret URL path on which the ssh3 server listens")
    parser.add_argument("--generateSelfSignedCert", action="store_true", help="if set, generates a self-self-signed cerificate and key that will be stored at the paths indicated by the -cert and -key args (they must not already exist)")
    parser.add_argument("--certPath", default="./cert.pem", help="the filename of the server certificate (or fullchain)")
    parser.add_argument("--keyPath",  default="./priv.pem", help="the filename of the certificate private key")
    parser.add_argument("-l","--secrets-log", type=str, help="log secrets to a file, for use with Wireshark")
    args = parser.parse_args()
    
    router = Starlette(
        debug=True,
        routes=[
             Route(path=args.urlPath, 
                   endpoint=handle_auths, 
                   methods=["CONNECT"])
                ]
    )

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        log.info(f"Received scope: {scope}")
        log.info(f"Received receive: {receive}")
        log.info(f"Received send: {send}")
        log.info(f"Nb Router: {len(router.router.routes)}")  
        for route in router.router.routes:
            log.info(f"Route: {route.path}")
        await router(scope, receive, send)

    glob.APPLICATION = app
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        util.configure_logger("debug")
    else:
        log_level = os.getenv("SSH3_LOG_LEVEL")
        if log_level:
            util.configure_logger(log_level)
            numeric_level = getattr(log, log_level.upper(), None)
            if not isinstance(numeric_level, int):
                raise ValueError(f"Invalid log level: {log_level}")
            logging.basicConfig(level=numeric_level)

        logFileName = os.getenv("SSH3_LOG_FILE")
        if not logFileName or logFileName == "":
            logFileName = "ssh3_server.log"
        logging.basicConfig(filename=logFileName, level=logging.INFO)

    if not args.enablePasswordLogin:
        log.error("password login is currently disabled")

    certPathExists = file_exists(args.certPath)
    keyPathExists  = file_exists(args.keyPath)

    if not args.generateSelfSignedCert:
        if not certPathExists:
            log.error(f"the \"{args.certPath}\" certificate file does not exist")
        if not keyPathExists:
            log.error(f"the \"{args.keyPath}\" certificate private key file does not exist")
        if not certPathExists or not keyPathExists:
            log.error("If you have no certificate and want a security comparable to traditional SSH host keys, you can generate a self-signed certificate using the -generate-selfsigned-cert arg or using the following script:")
            log.error("https://github.com/ElNiak/py-ssh3/blob/main/generate_openssl_selfsigned_certificate.sh")
            sys.exit(-1)
        log.info(f"Using certificate \"{args.certPath}\" and private key \"{args.keyPath}\"")
    else:
        if certPathExists:
            log.error(f"asked for generating a certificate but the \"{args.certPath}\" file already exists")
        if keyPathExists:
            log.error(f"asked for generating a private key but the \"{args.keyPath}\" file already exists")
        if certPathExists or keyPathExists:
            #sys.exit(-1)
            pass
        pubkey, privkey, err = util.generate_key()
        if err != None:
            log.error(f"could not generate private key: {err}")
            sys.exit(-1)
        cert, err = util.generate_cert(privkey, pubkey)
        if err != None:
            log.error(f"could not generate certificate: {err}")
            sys.exit(-1)

        err = util.dump_cert_and_key_to_files(cert, privkey, args.certPath, args.keyPath)
        if err != None:
            log.error(f"could not save certificate and key to files: {err}")
            sys.exit(-1)
    
    # TODO aioquic does not support this yet (disable or not 0rtt)
   
    # quicConf = defaults.
    
    # open SSL log file
    if args.secrets_log:
        secrets_log_file = open(args.secrets_log, "a")
    else:
        secrets_log_file = None
    
    defaults = QuicConfiguration(is_client=False)
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_datagram_frame_size=65536,
        max_datagram_size=defaults.max_datagram_size,
        quic_logger = QuicFileLogger("qlogs/"),
        secrets_log_file=secrets_log_file
    )

    # load SSL certificate and key
    configuration.load_cert_chain(args.certPath, args.keyPath)
    
    glob.CONFIGURATION = configuration
    
    wg = sync.WaitGroup()
    wg.add(1)
    
    log.info(f"Starting server on {args.bind}")

        
    async def handle_conv(authenticatedUsername: str, conv: Conversation):
        log.info(f"Handling authentification for {authenticatedUsername}")
        authUser = get_user(authenticatedUsername)
        
        log.info(f"Handling conversation {conv}")
        channel, err = await conv.accept_channel()
        if err != None:
            log.error(f"could not accept channel: {err}")
            return
        
        if channel.isinstance(UDPForwardingChannelImpl):
            handle_udp_forwarding_channel(authUser, conv, channel)
        elif channel.isinstance(TCPForwardingChannelImpl):
            handle_tcp_forwarding_channel(authUser, conv, channel)
        
        # Default 
        running_sessions[channel] = RunningSession(
            channel_state=channel_type.LARVAL,
            pty=None,
            running_cmd=None
        )
        
        def handle_session_channel():
            generic_message, err = channel.next_message()
            if err != None:
                log.error(f"could not get next message: {err}")
                return
            if generic_message is None:
                return
            if generic_message.isinstance(ssh3_message.ChannelRequestMessage):
                if generic_message.channel_request.isinstance(ssh3_channel.PtyRequest):
                    err = new_pty_req(authUser, channel, generic_message.channel_request, generic_message.want_reply)
                elif generic_message.channel_request.isinstance(ssh3_channel.X11Request):
                    err = new_x11_req(authUser, channel, generic_message.channel_request, generic_message.want_reply)
                elif generic_message.channel_request.isinstance(ssh3_channel.ExecRequest):
                    err = new_command(authUser, channel, False, generic_message.channel_request.command, generic_message.channel_request.args)
                elif generic_message.channel_request.isinstance(ssh3_channel.ShellRequest):
                    err = new_shell_req(authUser, channel, generic_message.want_reply)
                elif generic_message.channel_request.isinstance(ssh3_channel.CommandInShellRequest):
                    err = new_command_in_shell_req(authUser, channel, generic_message.want_reply, generic_message.channel_request.command)
                elif generic_message.channel_request.isinstance(ssh3_channel.SubsystemRequest):
                    err = err = new_subsystem_req(authUser, channel, generic_message.channel_request, generic_message.want_reply)
                elif generic_message.channel_request.isinstance(ssh3_channel.WindowChangeRequest):
                    err = new_window_change_req(authUser, channel, generic_message.channel_request, generic_message.want_reply)
                elif generic_message.channel_request.isinstance(ssh3_channel.SignalRequest):
                    err = new_signal_req(authUser, channel, generic_message.channel_request, generic_message.want_reply)
                elif generic_message.channel_request.isinstance(ssh3_channel.ExitStatusRequest):
                    err = new_exit_status_req(authUser, channel, generic_message.channel_request, generic_message.want_reply)
            elif generic_message.isinstance(ssh3_message.DataOrExtendedDataMessage):
                running_session, ok = running_sessions[channel]
                if not ok:
                    log.error("could not find running session for channel")
                    return 
                if running_session.channel_state == channel_type.LARVAL:
                    if generic_message.data == "forward)agent":
                        running_session.auth_agent_socket_path, err = open_agent_socket_and_forward_agent(conv, authUser)
                    else:
                        err = Exception("invalid data on ssh channel with LARVAL state")
                else:
                    err = new_data_req(authUser, channel, generic_message)      
            if err != None:
                log.error(f"error while processing message: {generic_message}: {err}",)
                return
        
        handle_session_channel()   
    
    log.info(f"Nb Router: {len(router.router.routes)}")  
    for route in router.router.routes:
        log.info(f"Route: {route.path}")
    
    # authenticated_username, new_conv, request_handler
    # asyncio.create_task(ssh3Handler(qconn, new_conv, conversations_manager))
    session_ticket_store = SessionTicketStore()
    glob.SESSION_TICKET_HANDLER = session_ticket_store.add
    quic_server = await serve(
        args.bind.split(":")[0],
        args.bind.split(":")[1],
        configuration=configuration,
        create_protocol=AuthHttpServerProtocol,
        session_ticket_fetcher=session_ticket_store.pop,
        session_ticket_handler=glob.SESSION_TICKET_HANDLER,
    )
   
    ssh3Server  = SSH3Server(
        30000,quic_server, 
        10, 
        conversation_handler=handle_conv)
    ssh3Handler = ssh3Server.get_http_handler_func()
                    
    glob.ENABLE_PASSWORD_LOGIN = args.enablePasswordLogin
    glob.HANDLER_FUNC          = ssh3Handler
    glob.QUIC_SERVER           = quic_server

    log.info(f"Listening on {args.bind} with URL path {args.urlPath}")
    
    await asyncio.Future()
    
    # if err != None:
    #     log.error(f"could not serve: {err}")
    #     sys.exit(-1)
        
    wg.done()
    
    wg.wait()

   
if __name__ == "__main__":
    asyncio.run(main())
