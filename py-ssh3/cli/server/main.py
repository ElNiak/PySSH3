import os
import signal
import subprocess
import asyncio
import socket
import contextlib
import signal
import fcntl
import struct
import termios
import logging
import asyncio
import os
import logging
import util.linux_util
import message.message as ssh3
import message.channel_request as ssh3Messages
import argparse

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
    "SIGSTKFLT": signal.SIGSTKFLT,
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
    "SIGXFSZ": signal.SIGXFSZ,
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
    parser.add_argument("-bind", default="[::]:443", help="the address:port pair to listen to, e.g. 0.0.0.0:443")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode, if set")
    parser.add_argument("-enable-password-login", action="store_true", help="if set, enable password authentication (disabled by default)")
    parser = argparse.ArgumentParser()
    parser.add_argument("-url-path", default="/ssh3-term", help="the secret URL path on which the ssh3 server listens")
    parser.add_argument("-generate-selfsigned-cert", action="store_true", help="if set, generates a self-self-signed cerificate and key that will be stored at the paths indicated by the -cert and -key args (they must not already exist)")
    parser.add_argument("-cert", default="./cert.pem", help="the filename of the server certificate (or fullchain)")
    parser.add_argument("-key", default="./priv.key", help="the filename of the certificate private key")
    args = parser.parse_args()

    if not args.enablePasswordLogin:
        logging.error("password login is currently disabled")

    certPathExists = file_exists(args.certPath)
    keyPathExists = file_exists(args.keyPath)

    if not args.generateSelfSignedCert:
        if not certPathExists:
            logging.error(f"the \"{args.certPath}\" certificate file does not exist")
        if not keyPathExists:
            logging.error(f"the \"{args.keyPath}\" certificate private key file does not exist")
        if not certPathExists or not keyPathExists:
            logging.error("If you have no certificate and want a security comparable to traditional SSH host keys, you can generate a self-signed certificate using the -generate-selfsigned-cert arg or using the following script:")
            logging.error("https://github.com/francoismichel/ssh3/blob/main/generate_openssl_selfsigned_certificate.sh")
            os.Exit(-1)
    else:
        if certPathExists:
            logging.error(f"asked for generating a certificate but the \"{args.certPath}\" file already exists")
        if keyPathExists:
            logging.error(f"asked for generating a private key but the \"{args.keyPath}\" file already exists")
        if certPathExists or keyPathExists:
            os.Exit(-1)
        pubkey, privkey, err = util.generate_key()
        if err != None:
            logging.error(f"could not generate private key: {err}")
            os.Exit(-1)
        cert, err = util.GenerateCert(privkey)
        if err != None:
            logging.error(f"could not generate certificate: {err}")
            os.Exit(-1)

        err = util.DumpCertAndKeyToFiles(cert, pubkey, privkey, args.certPath, args.keyPath)
        if err != None:
            logging.error(f"could not save certificate and key to files: {err}")
            os.Exit(-1)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        log_level = os.getenv("SSH3_LOG_LEVEL")
        if log_level:
            numeric_level = getattr(logging, log_level.upper(), None)
            if not isinstance(numeric_level, int):
                raise ValueError(f"Invalid log level: {log_level}")
            logging.basicConfig(level=numeric_level)

        logFileName = os.getenv("SSH3_LOG_FILE")
        if logFileName == "":
            logFileName = "/var/log/ssh3.log"
        logFile = open(logFileName, "a")
        logging.basicConfig(filename=logFile, level=logging.INFO)

    # quicConf = &quic.Config{
    #     Allow0RTT: True,
    # }

   
    if __name__ == "__main__":
        asyncio.run(main())
