import asyncio

# Assuming util and http3 modules are available in your Python environment
# or you have equivalent functionality implemented in Python
import util
import http3

# type ControlStreamID = uint64


class ConversationsManager:
    def __init__(self, connection):
        self.connection = connection
        self.conversations = {}
        self.lock = asyncio.Lock()

    async def add_conversation(self, conversation):
        async with self.lock:
            self.conversations[conversation.control_stream.stream_id] = conversation

    async def get_conversation(self, id):
        async with self.lock:
            return self.conversations.get(id, None)

    async def remove_conversation(self, conversation):
        async with self.lock:
            self.conversations.pop(conversation.control_stream.stream_id, None)

class ChannelsManager:
    def __init__(self):
        self.channels = {}
        self.dangling_dgram_queues = {}
        self.lock = asyncio.Lock()

    async def add_channel(self, channel):
        async with self.lock:
            dgrams_queue = self.dangling_dgram_queues.pop(channel.channel_id, None)
            if dgrams_queue:
                channel.set_dgram_queue(dgrams_queue)
            self.channels[channel.channel_id] = channel

    async def add_dangling_datagrams_queue(self, id, queue):
        async with self.lock:
            channel = self.channels.get(id)
            if channel:
                while True:
                    dgram = queue.next()
                    if dgram is None:
                        break
                    channel.add_datagram(dgram)
            else:
                self.dangling_dgram_queues[id] = queue

    async def get_channel(self, id):
        async with self.lock:
            return self.channels.get(id, None)

    async def remove_channel(self, channel):
        async with self.lock:
            self.channels.pop(channel.channel_id, None)
