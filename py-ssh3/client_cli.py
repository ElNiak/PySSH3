import ipaddress
import json
import os
import sys
import asyncio
import logging
import argparse
# Other necessary imports
from winsize.winsize import get_winsize_unix
from winsize.winsize_windows import get_winsize_windows
import util.util as util
from ssh.known_host import *
import socket
import re
from paramiko.config import SSHConfig
from aioquic.quic.configuration import QuicConfiguration
from http3.http3_client import *
import urllib
from client import *
from cryptography.hazmat.primitives import serialization
from ssh.version import *
from auth.openid_connect import connect as oicd_connect
from ssh.conversation import *
from ssh.channel import *

log = logging.getLogger(__name__)

def homedir():
    return os.path.expanduser('~')

import platform

def get_winsize():
    if platform.system() == "Windows":
        return get_winsize_windows()
    else:
        return get_winsize_unix()

# Forwarding Functions
def forward_agent(channel):
    pass

def forward_tcp_in_background(channel, conn):
    pass

def forward_udp_in_background(channel, conn):
    pass

def parse_addr_port(addr_port_str:str):
    # Split the string to get the local port and the rest
    array = addr_port_str.split('/')
    if len(array) != 2:
        raise ValueError("Invalid format for addrPort string")

    # Parse the local port
    try:
        local_port = int(array[0])
        if not 0 <= local_port <= 0xFFFF:
            raise ValueError("UDP port out of range: {}".format(local_port))
    except ValueError as e:
        raise ValueError("Could not convert {} to int: {}".format(array[0], e))

    # Split the rest to get the remote IP and port
    array = array[1].split('@')
    if len(array) != 2:
        raise ValueError("Invalid format for remote IP and port")

    # Validate and parse the remote IP
    remote_ip_str = array[0]
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', remote_ip_str) and not re.match(r'^[a-fA-F0-9:]+$', remote_ip_str):
        raise ValueError("Invalid IP address format: {}".format(remote_ip_str))

    remote_ip = socket.inet_aton(remote_ip_str) if ':' not in remote_ip_str else socket.inet_pton(socket.AF_INET6, remote_ip_str)

    # Parse the remote port
    try:
        remote_port = int(array[1])
        if not 0 <= remote_port <= 0xFFFF:
            raise ValueError("UDP port out of range: {}".format(remote_port))
    except ValueError as e:
        raise ValueError("Could not convert {} to int: {}".format(array[1], e))

    return local_port, remote_ip, remote_port

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keylog", help="Write QUIC TLS keys and master secret in the specified keylog file: only for debugging purpose")
    parser.add_argument("--privkey", help="private key file")
    parser.add_argument("--pubkeyForAgent", help="if set, use an agent key whose public key matches the one in the specified path")
    parser.add_argument("--usePassword", action='store_true', help="if set, do classical password authentication")
    parser.add_argument("--insecure", action='store_true', help="if set, skip server certificate verification")
    parser.add_argument("--useOidc", help="if set, force the use of OpenID Connect with the specified issuer url as parameter (it opens a browser window)")
    parser.add_argument("--oidcConfig", help="OpenID Connect json config file containing the 'client_id' and 'client_secret' fields needed for most identity providers")
    parser.add_argument("-v", "--verbose", action='store_true', help="if set, enable verbose mode")
    parser.add_argument("--doPkce", action='store_true', help="if set perform PKCE challenge-response with oidc")
    parser.add_argument("--forwardAgent", action='store_true', help="if set, forwards ssh agent to be used with sshv2 connections on the remote host")
    parser.add_argument("--forwardUDP", help="if set, take a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport")
    parser.add_argument("--forwardTCP", help="if set, take a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport")
    parser.add_argument("--url", help="URL to connect to")
    args = parser.parse_args()
    
    
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
            logFileName = "ssh3_client.log"
        logging.basicConfig(filename=logFileName, level=logging.INFO)

    # Create .ssh3 directory
    ssh3_dir = homedir() + "/" + ".ssh3"
    os.makedirs(ssh3_dir, exist_ok=True)

    # Parse known hosts
    known_hosts_path = ssh3_dir + "/" + "known_hosts"
    known_hosts, skipped_lines, err = parse_known_hosts(known_hosts_path)
    if skipped_lines:
        log.warning(f"the following lines in {known_hosts_path} are invalid: {', '.join(map(str, skipped_lines))}")
    if err:
        log.error(f"there was an error when parsing known hosts: {err}")
    log.info(f"Parsed known hosts file {known_hosts_path}, found {len(known_hosts)} hosts ({known_hosts}), skipped {len(skipped_lines)} lines, and got error {err}")
    # Handling tty
    try:
        tty = open("/dev/tty", "r+")
    except OSError:
        tty = None

    # Processing URL and command
    url_from_param = args.url
    if not url_from_param.startswith("https://"):
        url_from_param = f"https://{url_from_param}"
    command = " ".join(sys.argv)
    
    log.info(f"Connecting to {url_from_param} with command {command}")

    # Parse and validate forwarding addresses
    local_udp_addr = None
    remote_udp_addr = None
    local_tcp_addr = None
    remote_tcp_addr = None

    if args.forwardUDP:
        # Parse and validate the UDP addresses
        try:
            local_port, remote_ip, remote_port = parse_addr_port(url_from_param)
            remote_udp_addr = (remote_ip, remote_port)

            # Determine if the IP is IPv4 or IPv6 and set the corresponding local address
            try:
                socket.inet_pton(socket.AF_INET, remote_ip)
                local_udp_addr = ('127.0.0.1', local_port)
            except socket.error:
                try:
                    socket.inet_pton(socket.AF_INET6, remote_ip)
                    local_udp_addr = ('::1', local_port)
                except socket.error:
                    log.error(f"Unrecognized IP address format: {remote_ip}")
                    exit(-1)

        except Exception as e:
            log.error(f"UDP forwarding parsing error: {e}")
            exit(-1)

    if args.forwardTCP:
        # Parse and validate the TCP addresses
        try:
            local_port, remote_ip, remote_port = parse_addr_port(forward_tcp)
            remote_tcp_addr = (socket.inet_ntop(socket.AF_INET if len(remote_ip) == 4 else socket.AF_INET6, remote_ip), remote_port)

            # Check if the remote IP is IPv4 or IPv6 and set the corresponding local address
            if len(remote_ip) == 4:  # IPv4
                local_tcp_addr = ('127.0.0.1', local_port)
            elif len(remote_ip) == 16:  # IPv6
                local_tcp_addr = ('::1', local_port)
            else:
                log.error(f"Unrecognized IP length {len(remote_ip)}")
                exit(-1)

        except Exception as e:
            log.error(f"TCP forwarding parsing error: {e}")
            exit(-1)
    
    # Read SSH config file
    config_path = homedir() + "/" + ".ssh" + "/" + "config"
    try:
        # Assuming you have a way to decode SSH config in Python
        ssh_config = SSHConfig()
        with open(config_path) as f:
            ssh_config.parse(f)
    except FileNotFoundError:
        log.warning(f"could not open {config_path}: File not found, ignoring config")
        ssh_config = None
    except Exception as e:
        log.warning(f"could not parse {config_path}: {e}, ignoring config")
        ssh_config = None

    # Read OIDC config file (TODO)
    oidc_config = None
    if args.useOidc:
        log.error("OIDC not implementation")
        # exit(-1)
        if not args.oidcConfig:
            default_file_name = ssh3_dir / "oidc_config.json"
            try:
                with open(default_file_name, 'r') as file:
                    oidc_config = json.load(file)
            except FileNotFoundError:
                log.warning(f"could not open {default_file_name}: File not found")
            except Exception as e:
                log.error(f"could not read or parse oidc config file: {e}")
                exit(-1)
        else:
            try:
                with open(args.oidcConfig, 'r') as file:
                    oidc_config = json.load(file)
            except Exception as e:
                log.error(f"could not open or parse {args.oidcConfig}: {e}")
                exit(-1)

    # Read key log file
    key_log = None
    if args.keylog:
        key_log = open(args.keylog, 'a')   
        
    # Parse URL
    parsed_url = urllib.parse.urlparse(url_from_param)
    log.info(f"URL from param {url_from_param}")
    log.info(f"URL parsed as {parsed_url}")

    hostname, port = parsed_url.hostname, parsed_url.port
    config_hostname, config_port, config_user, config_auth_methods = get_config_for_host(hostname, ssh_config)
    log.info(f"Configuration parameters for host are {config_hostname}, {config_port}, {config_user}, {config_auth_methods}")
    hostname = config_hostname or hostname
    port = port or config_port or 443
    
    log.info(f"Hostname is {hostname} and port is {port}")

    username = parsed_url.username or dict(urllib.parse.parse_qsl(parsed_url.query)).get("user") or config_user
    if not username:
        username = config_user

    if not username:
        log.error("No username could be found")
        exit(-1) 
    
    log.info(f"Username is {username}")
    
    # Setup TLS configuration
    
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        # TODO Invalid payload length
        # max_datagram_frame_size=65536,
        # max_datagram_size=30000
    )
    configuration.verify_mode = ssl.CERT_REQUIRED if not args.insecure else ssl.CERT_NONE
    # load SSL certificate and key
    if hostname in known_hosts:
        for cert in known_hosts[hostname]:
            configuration.load_verify_locations(cadata=cert.public_bytes(serialization.Encoding.PEM))

    if key_log:
        configuration.keylog_file = key_log
        
    ssh_auth_sock = os.getenv('SSH_AUTH_SOCK')
    log.debug(f"SSH_AUTH_SOCK is {ssh_auth_sock}")
    agent_keys = []
    if ssh_auth_sock:
        try:
            agent = paramiko.Agent()
            agent_keys_t = agent.get_keys()
            for key in agent_keys_t:
                # Here you can process each key. For example, print the key fingerprint.
                log.info(f"Key: {key.get_fingerprint()}")
                agent_keys.append(key)
        except Exception as e:
            # Handle errors...
            log.error(f"Failed to open SSH_AUTH_SOCK or list agent keys: {e}")
            exit(-1)
    
    logging.debug(f"Dialing QUIC host at {hostname}:{port}")
    
    async def dial_quic_host(hostname, port, quic_config, known_hosts_path):
        try:
            # Check if hostname is an IP address and format it appropriately
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.version == 6:
                    hostname = f"[{hostname}]"
            except ValueError:
                log.error(f"Not a valid IP address {ip}")  # Hostname is not an IP address
                pass
            log.info(f"Connecting to {hostname}:{port}")
            # Attempt to establish a QUIC connection
            async with connect(hostname, port, configuration=quic_config, create_protocol=HttpClient) as client:
                # Connection established
                return client

        except ssl.SSLError as e:
            logging.error("TLS error: %s", e)
            if hostname in known_hosts:
                # Server certificate cannot be verified
                logging.error("The server certificate cannot be verified.")
                return -1
            else:
                # Handle bad certificates like OpenSSH
                quic_config.verify_mode = ssl.CERT_NONE
                quic_config.check_hostname = False
                peer_cert = None  # Placeholder for peer certificate

                async with connect(hostname, port, 
                                   create_protocol=HttpClient,
                                   configuration=quic_config) as client:
                    peer_cert = client.connection.tls._peer_certificate

                # Check if the certificate is self-signed
                # TODO 
                # if not is_self_signed(peer_cert):
                #     log.error("The peer provided an unknown, insecure certificate.")
                #     return -1

                # Prompt user to accept the certificate
                log.info("Received an unknown self-signed certificate from the server.")
                answer = input("Do you want to add this certificate to ~/.ssh3/known_hosts (yes/no)? ").strip()
                if answer.lower() != "yes":
                    log.info("Connection aborted.")
                    return 0

                # Append certificate to known hosts
                if not append_known_host(known_hosts_path, hostname, peer_cert):
                    log.error("Could not append known host.")
                    return -1

                log.info("Successfully added the certificate. Please rerun the command.")
                return 0

        except Exception as e:
            log.error("Could not establish client QUIC connection: %s", e)
            return -1

        
    log.info(f"Starting client to {url_from_param}")
    client = await dial_quic_host(
                        hostname=hostname,
                        port=port,
                        quic_config=configuration,
                        known_hosts_path=known_hosts_path
                    )
    
    if not client or client == -1:
        return exit(-1)
    
    tls_state = client._quic.tls.state
    log.info(f"TLS state is {tls_state}")
    conv = await new_client_conversation(30000,10, tls_state)
    
    log.info(f"Conversation is {conv}")
    
    # HTTP request over QUIC
    # perform request
    req = HttpRequest(method="CONNECT", url=URL(url_from_param))
    log.info(f"Request is {req}")
    # await asyncio.gather(*coros)
    # req.Proto = "ssh3" # TODO
    # process http pushes
    # process_http_pushes(client=client)

    # Handle authentication methods
    auth_methods = []
    priv_key_file = args.privkey
    if not args.privkey:
        priv_key_file = '~/.ssh/id_rsa'
    pubkey_for_agent = '' # TODO
    
    if not args.useOidc:
        # Private key and agent authentication
        if priv_key_file:
            # Add private key auth method
            auth_methods.append(PrivkeyFileAuthMethod(priv_key_file))  # Implement based on your application logic

        if pubkey_for_agent:
            agent = paramiko.Agent()
            agent_keys = agent.get_keys()
            # Compare and add agent keys to auth methods
            # TODO
            pass  # Implement based on your application logic

        if args.usePassword:
            # Add password auth method
            auth_methods.append(PasswordAuthMethod())  # Implement based on your application logic
    else:
        # OIDC authentication
        # TODO
        issuer_url = args.useOidc
        if issuer_url:
            # Add OIDC auth method based on issuer URL
            for issuer_config in oidc_config:
                if issuer_url == issuer_config.issuer_url:
                    auth_methods.append(OIDCAuthMethod(args.doPkce,issuer_config))
                
        else:
            log.error("OIDC was asked explicitly but did not find suitable issuer URL")
            exit(-1)

    auth_methods.append(config_auth_methods)
    
    if oidc_config:
        for issuer_config in oidc_config:
            if issuer_url == issuer_config.issuer_url:
                auth_methods.append(OIDCAuthMethod(args.doPkce,issuer_config))
    
    log.debug(f"Try the following auth methods: {auth_methods}")
    
    identity = None
    for method in auth_methods:
        if isinstance(method, PasswordAuthMethod):
            password = input(f"Password: ")
            identity = method.into_identity(password)
        elif isinstance(method, PrivkeyFileAuthMethod):
            try:
                identity = method.into_identity_without_passphrase()
            except Exception as e:  # Replace with specific passphrase missing exception
                # Handle passphrase protected key
                passphrase = input(f"Passphrase for private key stored in {method.filename()}: ")
                identity = method.into_identity_passphrase(passphrase)
                if identity is None:
                    log.error("Could not load private key with passphrase")
        elif isinstance(method, AgentAuthMethod):
            # Assuming an SSH agent is already connected
            # identity = method.into_identity(agent_client)
            pass # TODO
        elif isinstance(method, OIDCAuthMethod): 
            # Assuming an OIDC connection method
            # TODO
            token, err = oicd_connect(method.oidc_config(), method.oidc_config().issuer_url, method.do_pkce)
            if err:
                log.error(f"Could not get token: {err}")
            else:
                identity = method.into_identity(token)

        if identity:
            break  # Exit the loop once an identity is found

    if identity is None:
        log.error("No suitable identity found")
        # Handle the error or exit
        exit(-1)
    
    log.debug(f"Try the following Identity: {identity}")

    try:
        identity.set_authorization_header(req, username, conv)
    except Exception as e:
        log.error(f"Could not set authorization header in HTTP request: {e}")
        exit(-1)

    log.debug("Send CONNECT request to the server")

    try:
        ret, err = await conv.establish_client_conversation(req, client)
        if ret ==  "Unauthorized":  # Replace with your specific error class
            log.error("Access denied from the server: unauthorized")
            exit(-1)
    except Exception as e:
        log.error(f"Could not open channel: {e}")
        exit(-1)


    try:
        channel = conv.open_channel("session", 30000, 0)
    except Exception as e:
        log.error(f"Could not open channel: {e}")
        exit(-1)

    log.debug("Opened new session channel")

    if args.forwardAgent:
        # TODO
        try:
            await channel.write_data(b"forward-agent")
        except Exception as e:
            log.error(f"Could not forward agent: {e}")
            return -1
        
        async def accept_and_forward_channels():
            while True:
                try:
                    forward_channel = await conv.accept_channel()
                    if forward_channel.channel_type != "agent-connection":
                        log.error(f"Unexpected server-initiated channel: {forward_channel.channel_type}")
                        return

                    log.debug("New agent connection, forwarding")
                    asyncio.create_task(forward_agent(forward_channel))

                except asyncio.CancelledError:
                    # Context was cancelled, exit the loop
                    return
                except Exception as e:
                    log.error(f"Could not accept forwarding channel: {e}")
                    # Close the conversation on error
                    await conv.close()
                    return

        asyncio.create_task(accept_and_forward_channels())
    
    if len(command) == 0:
        is_atty = sys.stdin.isatty()
        if is_atty:
            window_size = get_winsize_windows()
            err = channel.send_request(
                ChannelRequestMessage(
                    want_reply=True,
                    channel_request=PtyRequest(
                        term=os.getenv("TERM"),
                        char_width=window_size.ncols,
                        char_height=window_size.nrows,
                        pixel_width=window_size.pixel_width,
                        pixel_height=window_size.pixel_height
                    )
                )
            )
            if err != None:
                log.error(f"Could send pty request {err}")
                exit(-1)
            log.info("Sent PTY request for sessions")
            
        # Send shell request
        err = channel.send_request(
            ChannelRequestMessage(
                want_reply=True,
                channel_request=ShellRequest()
            )
        )
        log.debug("Sent shell request")

        # Make terminal raw if stdin is TTY
        # TODO
        # if is_atty:
        #     old_attr = termios.tcgetattr(sys.stdin.fileno())
        #     new_attr = termios.tcgetattr(sys.stdin.fileno())
        #     new_attr[3] = new_attr[3] & ~termios.ICANON & ~termios.ECHO
        #     termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, new_attr)
        #     # Restore terminal settings at the end
        #     def restore_terminal():
        #         termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_attr)
        #     atexit.register(restore_terminal)
    else:
        # Send exec request
        exec_command = " ".join(command)
        err =  channel.send_request(ChannelRequestMessage(
                want_reply=True,
                channel_request=ExecRequest(
                    command=exec_command
                )
            ))
        log.debug(f"Sent exec request for command \"{exec_command}\"")
    
    if err != None:
        log.error("Could not sebd shell request")
        
    async def transfer_stdin_to_channel(channel):
        try:
            while True:
                buf = await asyncio.to_thread(sys.stdin.buffer.read, channel.max_packet_size())
                if buf:
                    await asyncio.to_thread(channel.write_data, buf)
        except Exception as e:
            log.info(f"Error: {e}", file=sys.stderr)
            return
        
    await transfer_stdin_to_channel(channel)


    async def udp_forwarding(local_udp_addr, remote_udp_addr, conv):
        log.debug(f"Start forwarding from {local_udp_addr} to {remote_udp_addr}")

        # Create a UDP socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(local_udp_addr)
            forwardings = {}
            async def handle_remote_dgram(channel, addr):
                while True:
                    try:
                        # Assuming `channel.receive_datagram` is an async method to receive datagrams
                        dgram = await channel.receive_datagram()
                        sock.sendto(dgram, addr)
                    except Exception as e:
                        log.error(f"Could not write datagram on socket: {e}")
                        return
            while True:
                try:
                    dgram, addr = await asyncio.get_event_loop().sock_recvfrom(sock, 1500)
                    if addr not in forwardings:
                        # Open a new UDP forwarding channel
                        # Assuming `conv.open_udp_forwarding_channel` is an async method to open a channel
                        channel = await conv.open_udp_forwarding_channel(local_udp_addr, remote_udp_addr)
                        forwardings[addr] = channel
                        # Start a new task to handle incoming datagrams from the remote side
                        asyncio.create_task(handle_remote_dgram(channel, addr))
                    # Send the datagram to the remote side
                    await channel.send_datagram(dgram)
                except Exception as e:
                    log.error(f"Could not handle UDP socket: {e}")
                    return
    
    async def forward_tcp_in_background(channel, client_conn):
        """
        Handles forwarding of TCP data between client and remote server through an SSH channel.
        """
        try:
            data = await asyncio.get_event_loop().sock_recv(client_conn, 4096)
            if not data:
               await forward_tcp_in_background(channel, client_conn) 
            # Assuming 'channel.send_data' is an async method to send data through the channel
            await channel.send_data(data)
            
            # Assuming 'channel.receive_data' is an async method to receive data from the channel
            remote_data = await channel.receive_data()
            if remote_data:
                await asyncio.get_event_loop().sock_sendall(client_conn, remote_data)
        except Exception as e:
            logging.error(f"Error in TCP forwarding: {e}")
        finally:
            client_conn.close()

    async def tcp_forwarding(local_tcp_addr, remote_tcp_addr, conv):
        logging.debug(f"Start forwarding from {local_tcp_addr} to {remote_tcp_addr}")

        server = await asyncio.start_server(
            lambda r, w: handle_client(conv, remote_tcp_addr, r, w), 
            local_tcp_addr[0], local_tcp_addr[1])

        async def handle_client(conv, remote_tcp_addr, reader, writer):
            forwarding_channel = await conv.open_tcp_forwarding_channel(remote_tcp_addr)
            await forward_tcp_in_background(forwarding_channel, (reader, writer))

        await server.serve_forever()
    
    if local_udp_addr != None and remote_udp_addr != None:
        await udp_forwarding(local_udp_addr=local_udp_addr, remote_udp_addr=remote_udp_addr, conv=conv)
    
    if local_tcp_addr != None and remote_tcp_addr != None:
        await tcp_forwarding(local_tcp_addr=local_tcp_addr, remote_tcp_addr=remote_tcp_addr, conv=conv)

    conv.close()  
    
    async def read_channel_messages(channel):
        try:
            while True:
                message = await channel.next_message()  # Assuming 'next_message' is an async method
                if isinstance(message, ChannelRequestMessage):  
                    if isinstance(message.channel_request, PtyRequest):  
                        log.info("Receiving a pty request on the client is not implemented")
                    elif isinstance(message.channel_request, X11Request):  
                        log.info("Receiving a x11 request on the client is not implemented")
                    elif isinstance(message.channel_request, ShellRequest):  
                        log.info("Receiving a shell request on the client is not implemented")
                    elif isinstance(message.channel_request, ExecRequest):  
                        log.info("Receiving a exec request on the client is not implemented")
                    elif isinstance(message.channel_request, SubsystemRequest):  
                        log.info("Receiving a subsystem request on the client is not implemented")
                    elif isinstance(message.channel_request, WindowChangeRequest):  
                        log.info("Receiving a windowchange request on the client is not implemented")
                    elif isinstance(message.channel_request, SignalRequest):  
                        log.info("Receiving a signal request on the client is not implemented")
                    elif isinstance(message.channel_request, ExitStatusRequest):  
                        log.info(f"SSH3: Process exited with status: {message.channel_request.exit_status}")
                        return message.channel_request.exit_status
                    elif isinstance(message.channel_request, ExitSignalRequest):  
                        log.info(f"SSH3: Process exited with signal: {message.channel_request.signal_name_without_sig}: {message.channel_request.error_message_utf8}")
                        return -1

                elif isinstance(message, DataOrExtendedDataMessage):  
                    if message.data_type == SSHDataType.SSH_EXTENDED_DATA_NONE:  # Replace with the actual constant
                        log.info(message.data.decode())
                    elif message.data_type == SSHDataType.SSH_EXTENDED_DATA_STDERR:  # Replace with the actual constant
                        log.error(message.data.decode())

        except Exception as e:
            log.info(f"Could not get message: {e}", file=sys.stderr)
            exit(-1)
            
    await read_channel_messages(channel)
    
if __name__ == "__main__":
    asyncio.run(main())
