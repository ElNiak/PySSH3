import asyncio
import logging
import random
from typing import Callable, Tuple
from ssh3.conversation import Conversation, ConversationsManager
from http3.http3_server import *
from ssh3.resources_manager import *
import util.util as util
import util.quic_util as quic_util
from ssh3.version import parse_version  
from ssh3.channel import *
from starlette.responses import PlainTextResponse, Response
from aioquic.quic.connection import NetworkAddress, QuicConnection
log = logging.getLogger(__name__)

class SSH3Server:
    def __init__(self, max_packet_size, 
                 h3_server: HttpServerProtocol,
                 default_datagram_queue_size, 
                 conversation_handler, *args, **kwargs):
        # super().__init__(*args, **kwargs)
        self.h3_server = h3_server
        self.max_packet_size = max_packet_size
        self.conversations = {}  # Map of StreamCreator to ConversationManager
        self.conversation_handler = conversation_handler
        self.lock = asyncio.Lock()
        log.debug("SSH3Server initialized")
        #self.h3_server._stream_handler = self.stream_hijacker
        
    def stream_hijacker(frame_type, stream_id, data, end_stream):
        # Your stream hijacking logic
        """
        Process data received on a hijacked stream.
        
        :param frame_type: The type of frame received (inferred from the data)
        :param stream_id: The ID of the stream
        :param data: The data received on the stream
        :param end_stream: Flag indicating if the stream has ended
        """
        log.debug(f"Stream hijacker called with frame_type: {frame_type}, stream_id: {stream_id}, data: {data}, end_stream: {end_stream}")
        if frame_type != SSH_FRAME_TYPE:
            # If the frame type is not what we're interested in, ignore it
            return False, None

        try:
            conversation_control_stream_id, channel_type, max_packet_size = parse_header(stream_id, data)
            conversations_manager = self.get_conversations_manager()
            conversation = conversations_manager.get_conversation(conversation_control_stream_id)  # Implement this function
            if conversation is None:
                err = Exception(f"Could not find SSH3 conversation with control stream id {conversation_control_stream_id} for new channel {stream_id}")
                log.error(str(err))
                return False, err

            channel_info = ChannelInfo(
                conversation_id=conversation.conversation_id,
                conversation_stream_id=conversation_control_stream_id,
                channel_id=stream_id,
                channel_type=channel_type,
                max_packet_size=max_packet_size
            )

            new_channel = ChannelImpl(
                channel_info.conversation_stream_id,
                channel_info.conversation_id,
                channel_info.channel_id,
                channel_info.channel_type,
                channel_info.max_packet_size,
                stream_reader=None,  # Replace with the actual stream reader
                stream_writer=None,  # Replace with the actual stream writer
                channels_manager=conversation.channels_manager,
                default_datagrams_queue_size=conversation.default_datagrams_queue_size
            )

            if channel_type == "direct-udp":
                udp_addr = parse_udp_forwarding_header(channel_info.channel_id, stream)
                new_channel.set_datagram_sender(conversation.get_datagram_sender_for_channel(channel_info.channel_id))
                new_channel = UDPForwardingChannelImpl(new_channel, udp_addr)
            elif channel_type == "direct-tcp":
                tcp_addr = parse_tcp_forwarding_header(channel_info.channel_id, stream)
                new_channel = TCPForwardingChannelImpl(new_channel, tcp_addr)

            conversation.channels_accept_queue.add(new_channel)
            return True, None
        except Exception as e:
            log.error(f"Error in stream hijacker: {e}")
            return False, e

        # self._stream_handler = stream_hijacker
        
     
    async def get_conversations_manager(self, stream_creator):
        async with self.lock:
            return self.conversations.get(stream_creator, None)

    async def get_or_create_conversations_manager(self, stream_creator):
        async with self.lock:
            if stream_creator not in self.conversations:
                self.conversations[stream_creator] = ConversationsManager(stream_creator)
            return self.conversations[stream_creator]

    async def remove_connection(self, stream_creator):
        async with self.lock:
            self.conversations.pop(stream_creator, None)

    async def handle_datagrams(self, qconn: QuicConnectionProtocol, new_conv):
        while True:
            try:
                # Receive a datagram from the QUIC connection
                dgram = await qconn.receive_datagram()

                # Process the datagram
                # Assuming quic_util.read_var_int and util.bytes_read_closer are defined to parse the conversation ID
                buf = util.BytesReadCloser(dgram)
                conv_id, err = quic_util.read_var_int(buf)
                if err:
                    log.error(f"Could not read conv id from datagram: {err}")
                    return

                if conv_id == new_conv.control_stream.stream_id:
                    # Assuming newConv has an AddDatagram method
                    try:
                        await new_conv.add_datagram(dgram[len(dgram)-buf.remaining():])
                    except util.ChannelNotFound as e:
                        log.warning(f"Could not find channel {e.channel_id}, queuing datagram in the meantime")
                    except Exception as e:
                        log.error(f"Could not add datagram to conv id {new_conv.control_stream.stream_id}: {e}")
                        return
                else:
                    log.error(f"Discarding datagram with invalid conv id {conv_id}")

            except asyncio.CancelledError:
                # Handling cancellation of the datagram listener
                break
            except Exception as e:
                if not isinstance(e, (asyncio.CancelledError, ConnectionError)):
                    log.error(f"Could not receive message from connection: {e}")
                return
    
    async def manage_conversation(self,server, authenticated_username, new_conv, conversations_manager, stream_creator):
        try:
            # Call the conversation handler
            await server.conversation_handler(authenticated_username, new_conv)

        except asyncio.CancelledError:
            # Handle cancellation of the conversation handler
            logging.info(f"Conversation canceled for conversation id {new_conv.conversation_id}, user {authenticated_username}")
        except Exception as e:
            # Log other errors
            logging.error(f"Error while handling new conversation: {new_conv.conversation_id} for user {authenticated_username}: {e}")

        finally:
            # Perform cleanup on conversation completion or error
            if new_conv:
                await new_conv.close()
            if conversations_manager:
                await conversations_manager.remove_conversation(new_conv)
            if stream_creator:
                await server.remove_connection(stream_creator)
    
    def get_http_handler_func(self):
        """
        Returns a handler function for authenticated HTTP requests.
        """
        async def handler(authenticated_username, new_conv, request):
            log.info(f"Got auth request: {request}")
            log.debug(f"request.url: {request.url}")
            if request.method == "CONNECT" and request.headers.get("protocol", None) == "ssh3": # request.url.scheme == "ssh3": TODO
                # Assuming that request_handler can act as a hijacker
                
                protocols_keys = list(glob.QUIC_SERVER._protocols.keys())
                prot = glob.QUIC_SERVER._protocols[protocols_keys[-1]]
    
                hijacker = prot.hijacker #self.h3_server.hijacker
                stream_creator = hijacker.stream_creator()
                # stream_creator =QuicConnection(
                #     configuration=glob.CONFIGURATION,
                #     session_ticket_handler=glob.SESSION_TICKET_HANDLER
                # )
                
                stream_creator = random.randint(0,10) # TODO

                conversations_manager = await self.get_or_create_conversations_manager(stream_creator)
                await conversations_manager.add_conversation(new_conv)

                # Handling datagrams and conversation
                asyncio.create_task(self.handle_datagrams(new_conv, conversations_manager))
                asyncio.create_task(self.manage_conversation(self, authenticated_username, new_conv, conversations_manager, stream_creator))
                
                return Response(status_code=200)
            else:
                return Response(status_code=404)

        return handler
    