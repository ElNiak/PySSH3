import argparse
import asyncio
import logging
import os
import pickle
import ssl
import time
from collections import deque
from typing import BinaryIO, Callable, Deque, Dict, List, Optional, Union, cast, Tuple
from urllib.parse import urlparse

import aioquic
import wsproto
import wsproto.events
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
    DatagramReceived
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.logger import QuicFileLogger
from aioquic.tls import CipherSuite, SessionTicket

try:
    import uvloop
except ImportError:
    uvloop = None

logger = logging.getLogger("client")

HttpConnection = Union[H0Connection, H3Connection]

from ssh3.version import get_current_version

USER_AGENT = get_current_version()


class URL:
    def __init__(self, url: str) -> None:
        self.url = url
        parsed = urlparse(url)
        self.authority = parsed.netloc
        self.full_path = parsed.path or "/"
        if parsed.query:
            self.full_path += "?" + parsed.query
        self.scheme = parsed.scheme
        logger.debug(f"URL initialized with authority: {self.authority}, full_path: {self.full_path}, scheme: {self.scheme}")
    
    def __str__(self) -> str:
        return self.url

class HttpRequest:
    def __init__(
        self,
        method: str,
        url: URL,
        content: bytes = b"",
        headers: Optional[Dict] = None,
    ) -> None:
        if headers is None:
            headers = {}
        self.content = content
        self.headers = headers
        self.method = method
        self.url = url
        logger.debug(f"HttpRequest initialized with method: {self.method}, url: {self.url}, content: {self.content}, headers: {self.headers}")
        
    def __str__(self):
        return f"HttpRequest(method={self.method}, url={self.url}, content={self.content}, headers={self.headers})"

class WebSocket:
    def __init__(
        self, http: HttpConnection, stream_id: int, transmit: Callable[[], None]
    ) -> None:
        self.http = http
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.stream_id = stream_id
        self.subprotocol: Optional[str] = None
        self.transmit = transmit
        self.websocket = wsproto.Connection(wsproto.ConnectionType.CLIENT)
        logger.debug(f"WebSocket initialized with stream_id: {self.stream_id}, subprotocol: {self.subprotocol}")

    async def close(self, code: int = 1000, reason: str = "") -> None:
        """
        Perform the closing handshake.
        """
        data = self.websocket.send(
            wsproto.events.CloseConnection(code=code, reason=reason)
        )
        self.http.send_data(stream_id=self.stream_id, data=data, end_stream=True)
        self.transmit()
        logger.debug(f"WebSocket closed with code: {code}, reason: {reason}")

    async def recv(self) -> str:
        """
        Receive the next message.
        """
        logger.debug(f"WebSocket received message")
        return await self.queue.get()

    async def send(self, message: str) -> None:
        """
        Send a message.
        """
        assert isinstance(message, str)

        data = self.websocket.send(wsproto.events.TextMessage(data=message))
        self.http.send_data(stream_id=self.stream_id, data=data, end_stream=False)
        self.transmit()
        logger.debug(f"WebSocket sent message: {message}")

    def http_event_received(self, event: H3Event) -> None:
        logger.debug(f"WebSocket received HTTP event: {event}")
        if isinstance(event, HeadersReceived):
            for header, value in event.headers:
                if header == b"sec-websocket-protocol":
                    self.subprotocol = value.decode()
        elif isinstance(event, DataReceived):
            self.websocket.receive_data(event.data)

        for ws_event in self.websocket.events():
            self.websocket_event_received(ws_event)

    def websocket_event_received(self, event: wsproto.events.Event) -> None:
        logger.debug(f"WebSocket received websocket event: {event}")
        if isinstance(event, wsproto.events.TextMessage):
            self.queue.put_nowait(event.data)


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.pushes: Dict[int, Deque[H3Event]] = {}
        self._http: Optional[HttpConnection] = None
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self._websockets: Dict[int, WebSocket] = {}

        if self._quic.configuration.alpn_protocols[0].startswith("hq-"):
            self._http = H0Connection(self._quic)
        else:
            self._http = H3Connection(self._quic)
        logger.debug(f"HttpClient initialized with pushes: {self.pushes}, _http: {self._http}, _request_events: {self._request_events}, _request_waiter: {self._request_waiter}, _websockets: {self._websockets}")

    async def get(self, url: str, headers: Optional[Dict] = None) -> Deque[H3Event]:
        """
        Perform a GET request.
        """
        logger.debug(f"HttpClient get called with url: {url}, headers: {headers}")
        return await self._request(
            HttpRequest(method="GET", url=URL(url), headers=headers)
        )

    async def post(
        self, url: str, data: bytes, headers: Optional[Dict] = None
    ) -> Deque[H3Event]:
        """
        Perform a POST request.
        """
        logger.debug(f"HttpClient post called with url: {url}, data: {data}, headers: {headers}")
        return await self._request(
            HttpRequest(method="POST", url=URL(url), content=data, headers=headers)
        )
        
    async def co(
        self, url: str, headers: Optional[Dict] = None
    ) -> Deque[H3Event]:
        """
        Perform a POST request.
        """
        logger.debug(f"HttpClient connect called with url: {url}, headers: {headers}")
        return await self._request(
            HttpRequest(method="CONNECT", url=URL(url), headers=headers)
        )
        
    async def websocket(
        self, url: str, subprotocols: Optional[List[str]] = None
    ) -> WebSocket:
        """
        Open a WebSocket.
        """
        request = HttpRequest(method="CONNECT", url=URL(url))
        stream_id = self._quic.get_next_available_stream_id()
        websocket = WebSocket(
            http=self._http, stream_id=stream_id, transmit=self.transmit
        )

        self._websockets[stream_id] = websocket

        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", request.url.authority.encode()),
            (b":path", request.url.full_path.encode()),
            (b":protocol", b"websocket"),
            (b"user-agent", USER_AGENT.encode()),
            (b"sec-websocket-version", b"13"),
        ]
        if subprotocols:
            headers.append(
                (b"sec-websocket-protocol", ", ".join(subprotocols).encode())
            )
        self._http.send_headers(stream_id=stream_id, headers=headers)

        self.transmit()
        logger.debug(f"HttpClient websocket called with url: {url}, subprotocols: {subprotocols}")
        return websocket

    def http_event_received(self, event: H3Event) -> None:
        logger.debug(f"HttpClient received HTTP event: {event}")
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(self._request_events.pop(stream_id))

            elif stream_id in self._websockets:
                # websocket
                websocket = self._websockets[stream_id]
                websocket.http_event_received(event)

            elif event.push_id in self.pushes:
                # push
                self.pushes[event.push_id].append(event)

        elif isinstance(event, PushPromiseReceived):
            self.pushes[event.push_id] = deque()
            self.pushes[event.push_id].append(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        #  pass event to the HTTP layer
        logger.debug(f"HttpClient received QUIC event: {event}")   
        if isinstance(event, DatagramReceived):
            self.handle_datagram(event.data)
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def _request(self, request: HttpRequest) -> Deque[H3Event]:
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", request.method.encode()),
                (b":scheme", request.url.scheme.encode()),
                (b":authority", request.url.authority.encode()),
                (b":path", request.url.full_path.encode())
            ]
            + [(k.encode(), v.encode()) for (k, v) in request.headers.items()] 
            + [(b"user-agent", USER_AGENT.encode())],
            end_stream=not request.content,
        )
        if request.content:
            self._http.send_data(
                stream_id=stream_id, data=request.content, end_stream=True
            )

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()
        head = [  # For debug
                (b":method", request.method.encode()),
                (b":scheme", request.url.scheme.encode()),
                (b":authority", request.url.authority.encode()),
                (b":path", request.url.full_path.encode())
            ] + [(k.encode(), v.encode()) for (k, v) in request.headers.items()]  + [(b"user-agent", USER_AGENT.encode())]
        logger.debug(f"HttpClient _request called with request: {request} and header: {head}")
        return await asyncio.shield(waiter)

class RoundTripOpt:
    def __init__(self, only_cached_conn: bool = False, dont_close_request_stream: bool = False):
        """
        Options for the RoundTripOpt method.

        :param only_cached_conn: Controls whether the RoundTripper may create a new QUIC connection.
                                 If set true and no cached connection is available, RoundTripOpt will return an error.
        :param dont_close_request_stream: Controls whether the request stream is closed after sending the request.
                                          If set, context cancellations have no effect after the response headers are received.
        """
        self.only_cached_conn = only_cached_conn
        self.dont_close_request_stream = dont_close_request_stream


class RoundTripper:
    # TODO add locks to this class
    def __init__(self, quic_config: Optional[QuicConfiguration] = None,
                 tls_config: Optional[ssl.SSLContext] = None,
                 dial: Optional[Callable] = None,
                 save_session_ticket: Optional[Callable[[SessionTicket], None]] = None,
                 hijack_stream: Optional[Callable] = None):
        self.quic_config = quic_config or QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        self.tls_config = tls_config or ssl.create_default_context()
        self.dial = dial
        self.save_session_ticket = save_session_ticket or self._default_save_session_ticket
        self.hijack_stream = hijack_stream or self._default_hijack_stream
        self.connections: Dict[Tuple[str, int], QuicConnectionProtocol] = {}
        self.last_used = {}
        
    async def _get_or_create_client(self, host: str, port: int) -> QuicConnectionProtocol:
        key = (host, port)
        if key not in self.connections:
            # Create a new connection
            async with connect(
                host=host,
                port=port,
                configuration=self.quic_config,
                create_protocol=HttpClient,
                session_ticket_handler=self.save_session_ticket,
                local_port=0,  # Replace with desired local port if needed
                wait_connected=True,
            ) as connection:
                await connection.wait_connected()
                self.connections[key] = connection
        self.last_used[key] = time.time()
        return self.connections[key]

    def _cleanup_connections(self):
        """Close connections that have been idle for a certain threshold."""
        idle_threshold = 60  # seconds
        current_time = time.time()
        for key, last_used_time in list(self.last_used.items()):
            if current_time - last_used_time > idle_threshold:
                self.connections[key].close()
                del self.connections[key]
                del self.last_used[key]
                         
    # TODO merge with round_trip
    async def round_trip_opt(self, request: HttpRequest, opt: RoundTripOpt) -> Deque[H3Event]:
        """
        Perform an HTTP request with additional options.

        :param request: The HTTP request to perform.
        :param opt: Options for the request.
        :return: A deque of H3Event objects representing the response.
        """
        # Parse the URL from the request
        url = request.url.url
        parsed = urlparse(url)
        logger.debug(f"RoundTripper round_trip_opt called with request: {request}, opt: {opt}, url: {url}, parsed: {parsed}")
        if parsed.scheme != "https" and parsed.scheme != "ssh3":
            raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
        
        # Extract the hostname and port
        host = parsed.hostname
        port = parsed.port or 443

        # Handle the RoundTripOpt options
        if opt.only_cached_conn and (host, port) not in self.connections:
            raise ValueError("No cached connection is available")

        # Get or create a QUIC client for the given host and port
        client = await self._get_or_create_client(host, port)
        client = cast(HttpClient, client)  # Cast to the appropriate type

        # Use the client to perform an HTTP request
        if request.method == "GET":
            return await client.get(url)
        elif request.method == "POST":
            return await client.post(url, request.content, request.headers)
        elif request.method == "CONNECT":
            return await client.co(url,request.headers)
        else:
            raise ValueError("Unsupported HTTP method")
        
    async def round_trip(self, request: HttpRequest) -> Deque[H3Event]:
        self._cleanup_connections()  # Clean up idle connections
        url = request.url
        parsed = urlparse(url)
        assert parsed.scheme == "https", "Only https:// URLs are supported."
        host = parsed.hostname
        port = parsed.port or 443

        # Get or create a QUIC client for the given host and port
        client = await self._get_or_create_client(host, port)
        client = cast(HttpClient, client)

        # Use the client to perform an HTTP request
        if request.method == "GET":
            return await client.get(url)
        elif request.method == "POST":
            return await client.post(url, request.content, request.headers)
        elif request.method == "CONNECT":
            return await client.co(url,request.headers)
        else:
            raise ValueError("Unsupported HTTP method")

    def _default_save_session_ticket(self, ticket: SessionTicket) -> None:
        # Implement session ticket saving logic if needed
        # TODO 
        logger.info("New session ticket received")
        with open("client_session_ticket.bin", "wb") as fp:
            pickle.dump(ticket, fp)

    async def send_datagram(self, data: bytes, host: str, port: int):
        client = await self._get_or_create_client(host, port)
        client = cast(HttpClient, client)
        client._quic.send_datagram_frame(data)

    async def _default_hijack_stream(self, stream_id: int, host: str, port: int):
        client = await self._get_or_create_client(host, port)
        client = cast(HttpClient, client)
        
        # Example: reading directly from a stream
        stream = client._quic._get_or_create_stream_for_receive(stream_id)
        data = await stream.receive_some()
        # Process data...

        # Similar methods can be implemented for writing to a stream.
        
async def perform_http_request(
    client: HttpClient,
    url: str,
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
) -> None:
    # perform request
    start = time.time()
    logger.info("Sending %s request" % ("POST" if data else "GET"))
    if data is not None:
        data_bytes = data.encode()
        logger.info("Sending %d-byte request body" % len(data_bytes))
        http_events = await client.post(
            url,
            data=data_bytes,
            headers={
                "content-length": str(len(data_bytes)),
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        method = "POST"
    else:
        logger.info("Sending GET request")
        http_events = await client.get(url)
        method = "GET"
    elapsed = time.time() - start

    # print speed
    octets = 0
    for http_event in http_events:
        if isinstance(http_event, DataReceived):
            octets += len(http_event.data)
    logger.info(
        "Response received for %s %s : %d bytes in %.1f s (%.3f Mbps)"
        % (method, urlparse(url).path, octets, elapsed, octets * 8 / elapsed / 1000000)
    )

    # output response
    if output_dir is not None:
        output_path = os.path.join(
            output_dir, os.path.basename(urlparse(url).path) or "index.html"
        )
        with open(output_path, "wb") as output_file:
            write_response(
                http_events=http_events, include=include, output_file=output_file
            )


def process_http_pushes(
    client: HttpClient,
    include: bool,
    output_dir: Optional[str],
) -> None:
    logger.debug(f"HttpClient process_http_pushes called with include: {include}, output_dir: {output_dir}")
    for _, http_events in client.pushes.items():
        method = ""
        octets = 0
        path = ""
        for http_event in http_events:
            if isinstance(http_event, DataReceived):
                octets += len(http_event.data)
            elif isinstance(http_event, PushPromiseReceived):
                for header, value in http_event.headers:
                    if header == b":method":
                        method = value.decode()
                    elif header == b":path":
                        path = value.decode()
        logger.info("Push received for %s %s : %s bytes", method, path, octets)

        # output response
        if output_dir is not None:
            output_path = os.path.join(
                output_dir, os.path.basename(path) or "index.html"
            )
            with open(output_path, "wb") as output_file:
                write_response(
                    http_events=http_events, include=include, output_file=output_file
                )


def write_response(
    http_events: Deque[H3Event], output_file: BinaryIO, include: bool
) -> None:
    logger.debug(f"HttpClient write_response called with include: {include}")
    for http_event in http_events:
        if isinstance(http_event, HeadersReceived) and include:
            headers = b""
            for k, v in http_event.headers:
                headers += k + b": " + v + b"\r\n"
            if headers:
                output_file.write(headers + b"\r\n")
        elif isinstance(http_event, DataReceived):
            output_file.write(http_event.data)


def save_session_ticket(ticket: SessionTicket) -> None:
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


async def main(
    configuration: QuicConfiguration,
    urls: List[str],
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
    local_port: int,
    zero_rtt: bool,
) -> None:
    # parse URL
    parsed = urlparse(urls[0])
    assert parsed.scheme in (
        "https",
        "wss",
    ), "Only https:// or wss:// URLs are supported."
    host = parsed.hostname
    if parsed.port is not None:
        port = parsed.port
    else:
        port = 443

    # check validity of 2nd urls and later.
    for i in range(1, len(urls)):
        _p = urlparse(urls[i])

        # fill in if empty
        _scheme = _p.scheme or parsed.scheme
        _host = _p.hostname or host
        _port = _p.port or port

        assert _scheme == parsed.scheme, "URL scheme doesn't match"
        assert _host == host, "URL hostname doesn't match"
        assert _port == port, "URL port doesn't match"

        # reconstruct url with new hostname and port
        _p = _p._replace(scheme=_scheme)
        _p = _p._replace(netloc="{}:{}".format(_host, _port))
        _p = urlparse(_p.geturl())
        urls[i] = _p.geturl()

    async with connect(
        host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
        session_ticket_handler=save_session_ticket,
        local_port=local_port,
        wait_connected=not zero_rtt,
    ) as client:
        client = cast(HttpClient, client)

        if parsed.scheme == "wss":
            ws = await client.websocket(urls[0], subprotocols=["chat", "superchat"])

            # send some messages and receive reply
            for i in range(2):
                message = "Hello {}, WebSocket!".format(i)
                print("> " + message)
                await ws.send(message)

                message = await ws.recv()
                print("< " + message)

            await ws.close()
        else:
            # perform request
            coros = [
                perform_http_request(
                    client=client,
                    url=url,
                    data=data,
                    include=include,
                    output_dir=output_dir,
                )
                for url in urls
            ]
            await asyncio.gather(*coros)

            # process http pushes
            process_http_pushes(client=client, include=include, output_dir=output_dir)
        client._quic.close(error_code=ErrorCode.H3_NO_ERROR)


if __name__ == "__main__":
    defaults = QuicConfiguration(is_client=True)

    parser = argparse.ArgumentParser(description="HTTP/3 client")
    parser.add_argument(
        "url", type=str, nargs="+", help="the URL to query (must be HTTPS)"
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )
    parser.add_argument(
        "--cipher-suites",
        type=str,
        help=(
            "only advertise the given cipher suites, e.g. `AES_256_GCM_SHA384,"
            "CHACHA20_POLY1305_SHA256`"
        ),
    )
    parser.add_argument(
        "--congestion-control-algorithm",
        type=str,
        default="reno",
        help="use the specified congestion control algorithm",
    )
    parser.add_argument(
        "-d", "--data", type=str, help="send the specified data in a POST request"
    )
    parser.add_argument(
        "-i",
        "--include",
        action="store_true",
        help="include the HTTP response headers in the output",
    )
    parser.add_argument(
        "--max-data",
        type=int,
        help="connection-wide flow control limit (default: %d)" % defaults.max_data,
    )
    parser.add_argument(
        "--max-stream-data",
        type=int,
        help="per-stream flow control limit (default: %d)" % defaults.max_stream_data,
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument("--legacy-http", action="store_true", help="use HTTP/0.9")
    parser.add_argument(
        "--output-dir",
        type=str,
        help="write downloaded files to this directory",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )
    parser.add_argument(
        "--local-port",
        type=int,
        default=0,
        help="local port to bind for connections",
    )
    parser.add_argument(
        "--max-datagram-size",
        type=int,
        default=defaults.max_datagram_size,
        help="maximum datagram size to send, excluding UDP or IP overhead",
    )
    parser.add_argument(
        "--zero-rtt", action="store_true", help="try to send requests using 0-RTT"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    if args.output_dir is not None and not os.path.isdir(args.output_dir):
        raise Exception("%s is not a directory" % args.output_dir)

    # prepare configuration
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H0_ALPN if args.legacy_http else H3_ALPN,
        congestion_control_algorithm=args.congestion_control_algorithm,
        max_datagram_size=args.max_datagram_size,
    )
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.cipher_suites:
        configuration.cipher_suites = [
            CipherSuite[s] for s in args.cipher_suites.split(",")
        ]
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.max_data:
        configuration.max_data = args.max_data
    if args.max_stream_data:
        configuration.max_stream_data = args.max_stream_data
    if args.quic_log:
        configuration.quic_logger = QuicFileLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            pass

    if uvloop is not None:
        uvloop.install()
    asyncio.run(
        main(
            configuration=configuration,
            urls=args.url,
            data=args.data,
            include=args.include,
            output_dir=args.output_dir,
            local_port=args.local_port,
            zero_rtt=args.zero_rtt,
        )
    )
