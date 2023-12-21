import asyncio
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, StreamDataReceived
from aioquic.tls import SessionTicket
import http3
import urllib

class HTTP3Client(QuicConnectionProtocol):
    def __init__(self, *args, stream_hijacker=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._connected = asyncio.Event()
        self._protocol_negotiated = asyncio.Event()
        self._session_ticket = None
        self.stream_hijacker = stream_hijacker

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self._protocol_negotiated.set()
        elif isinstance(event, SessionTicket):
            self._session_ticket = event
        elif isinstance(event, StreamDataReceived):
            if self.stream_hijacker and self.stream_hijacker(event):
                # Hijacking the stream, stop further processing
                return

    async def wait_connected(self):
        await self._connected.wait()

    async def wait_protocol_negotiated(self):
        await self._protocol_negotiated.wait()

    async def get_session_ticket(self):
        return self._session_ticket

class RoundTripper:
    def __init__(self, quic_config=None, stream_hijacker=None):
        self.quic_config = quic_config or QuicConfiguration(is_client=True)
        self.stream_hijacker = stream_hijacker
        
    async def round_trip(self, method, url, body=None, headers={}):
        parsed_url = urllib.parse.urlparse(url)
        async with connect(parsed_url.hostname, parsed_url.port or 443, configuration=self.quic_config, create_protocol=HTTP3Client) as protocol:
            await protocol.wait_for_negotiation()
            http3_conn = protocol.http3_connection

            # Prepare and send the request
            stream_id = http3_conn.send_request(method, headers, end_stream=(body is None))
            if body:
                http3_conn.send_data(stream_id, body, end_stream=True)

            # Wait for response
            while True:
                event = await protocol.next_event()
                if isinstance(event, http3.ResponseReceived) and event.stream_id == stream_id:
                    response = event
                    break

            # Read response body
            body = b''
            while True:
                event = await protocol.next_event()
                if isinstance(event, http3.DataReceived) and event.stream_id == stream_id:
                    body += event.data
                    if event.stream_ended:
                        break

            return response, body
        
async def http3_request(url, method="GET", data=None, headers={}):
    configuration = QuicConfiguration(is_client=True)
    configuration.load_verify_locations()

    # Connect to the server
    async with connect(url.hostname, url.port, configuration=configuration, create_protocol=HTTP3Client) as protocol:
        client = protocol
        await client.wait_connected()
        await client.wait_protocol_negotiated()

        # Create an HTTP/3 connection
        http3_conn = http3.H3Connection(protocol)

        # Send an HTTP request
        stream_id = http3_conn.send_request(method, headers, end_stream=(data is None))
        if data:
            http3_conn.send_data(stream_id, data, end_stream=True)

        # Receive the HTTP response
        event = await protocol.next_event()
        while not isinstance(event, http3.ResponseReceived):
            event = await protocol.next_event()
        response = event

        # Read response body
        body = b''
        event = await protocol.next_event()
        while not isinstance(event, http3.DataReceived) or not event.stream_ended:
            body += event.data
            event = await protocol.next_event()

        return response, body

# # Example usage
# async def main():
#     url = 'https://example.com'
#     response, body = await http3_request(url)
#     print(f"Response status: {response.status_code}")
#     print(f"Response body: {body.decode()}")

# asyncio.run(main())
