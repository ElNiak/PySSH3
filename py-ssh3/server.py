import asyncio
from aiohttp import web
from aioquic.asyncio import QuicConnectionProtocol
import logging


class Server:
    def __init__(self, max_packet_size, default_datagram_queue_size, h3_server, conversation_handler):
        self.max_packet_size = max_packet_size
        self.h3_server = h3_server
        self.conversations = {}  # Map of StreamCreator to ConversationManager
        self.conversation_handler = conversation_handler
        self.lock = asyncio.Lock()

    async def get_conversations_manager(self, stream_creator):
        async with self.lock:
            return self.conversations.get(stream_creator, None)

    async def get_or_create_conversations_manager(self, stream_creator):
        async with self.lock:
            if stream_creator not in self.conversations:
                self.conversations[stream_creator] = ConversationManager(stream_creator)
            return self.conversations[stream_creator]

    async def remove_connection(self, stream_creator):
        async with self.lock:
            self.conversations.pop(stream_creator, None)

    def get_http_handler_func(self, context):
        async def handler(request):
            logging.info(f"Got request: method: {request.method}, URL: {request.url}")
            # Handle the request logic here
            # ...

        return handler

async def run_server():
    server = Server(...)
    app = web.Application()
    app.router.add_route('*', '/', server.get_http_handler_func(...))
    runner = web.AppRunner(app)
    await runner.setup()
    