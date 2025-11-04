use crate::core::comms::tcp_types::{
    MESSAGE_HEADER_LEN,
    CHUNK_MESSAGE, OPEN_SECURE_CHANNEL_MESSAGE, CLOSE_SECURE_CHANNEL_MESSAGE,
    HELLO_MESSAGE, ACKNOWLEDGE_MESSAGE, ERROR_MESSAGE, REVERSE_HELLO_MESSAGE,
    CHUNK_FINAL, CHUNK_INTERMEDIATE, CHUNK_FINAL_ERROR};
use crate::prelude::{MESSAGE_CHUNK_HEADER_SIZE, MessageChunkHeader, MessageChunkType, MessageIsFinalType, SequenceHeader};
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::{
    AcknowledgeMessage, ByteString, ChannelSecurityToken, CloseSecureChannelRequest, CloseSecureChannelResponse, ErrorMessage, HelloMessage, MessageHeader, MessageSecurityMode, MessageType, OpenSecureChannelRequest, OpenSecureChannelResponse, RequestHeader, ResponseHeader, ReverseHelloMessage, SecurityTokenRequestType, UAString};

use extractable_macro::Extractable;
use puffin::codec::{Codec, CodecP, Reader};
use puffin::error::Error;
use puffin::protocol::{
    OpaqueProtocolMessage, OpaqueProtocolMessageFlight, ProtocolMessage,
    ProtocolMessageDeframer, ProtocolMessageFlight};
use puffin::codec;

use std::collections::VecDeque;
use std::io;
use std::io::Read;
use std::str;

pub const MAX_WIRE_SIZE: usize = 40960;

// Neither MessageChunkType, nor MessageIsFinalType is directly encoded,
// so we define here a simplified ChunkType that is extractable:
#[derive(Clone, Copy, Debug, Deserialize, Eq, Extractable, Hash, PartialEq, Serialize)]
#[extractable(OpcuaProtocolTypes)]
pub enum ChunkType {
    Open,
    Intermediate,
    Final,
    FinalError,
    Close
}

impl ChunkType{
    pub fn to_message_chunk_type(self) -> MessageChunkType {
        match self {
            ChunkType::Open  => MessageChunkType::OpenSecureChannel,
            ChunkType::Close => MessageChunkType::CloseSecureChannel,
            _                => MessageChunkType::Message
        }
    }
    pub fn to_is_final(self) -> MessageIsFinalType {
        match self {
            ChunkType::Intermediate => MessageIsFinalType::Intermediate,
            ChunkType::FinalError   => MessageIsFinalType::FinalError,
            _                       => MessageIsFinalType::Final
        }
    }
}

impl CodecP for ChunkType{
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            ChunkType::Open  => bytes.extend_from_slice(OPEN_SECURE_CHANNEL_MESSAGE),
            ChunkType::Close => bytes.extend_from_slice(CLOSE_SECURE_CHANNEL_MESSAGE),
            _                => bytes.extend_from_slice(CHUNK_MESSAGE)
        }
        match self {
            ChunkType::Intermediate => bytes.push(CHUNK_INTERMEDIATE),
            ChunkType::FinalError   => bytes.push(CHUNK_FINAL_ERROR),
            _                       => bytes.push(CHUNK_FINAL)
        }
    }

    fn read(&mut self, rd: &mut Reader) -> Result<(), Error> {
        let mut head = [0u8; 4];
        rd.read_exact(&mut head)?;
        match &head[0..3] {
            OPEN_SECURE_CHANNEL_MESSAGE => *self = ChunkType::Open,
            CLOSE_SECURE_CHANNEL_MESSAGE => *self = ChunkType::Close,
            CHUNK_MESSAGE =>
                match head[3] {
                    CHUNK_INTERMEDIATE => *self = ChunkType::Intermediate,
                    CHUNK_FINAL        => *self = ChunkType::Final,
                    CHUNK_FINAL_ERROR  => *self = ChunkType::FinalError,
                    _ => return Err(Error::Codec("Unexpected message head!".to_string()))
                },
                _ => return Err(Error::Codec("Unexpected message head!".to_string()))
            }
        Ok(())
    }
}


/// The enum type [`crate::core::comms::tcp_codec::Message`] defines
/// all UA Connection Protocol messages and chunks of UA Secure Channel messages
/// that are Signed and/or Encrypted.
/// However chunks make no distinction between:
///  - OpensecureChannel messages that are encrypted
///  - normal messages that are only protected by a MAC
/// Therefore to avoid modifing the original code, we redefine a similar Message
/// structure here that is more suited to the fuzzer.
/// This Message structure is used as [`OpaqueProtocolMessage`].
/// These messages are opaque in the sense that chunks may be encrypted.
/// Yet, knowledge can be learned from them if they are not encrypted.
/// The [`OpaqueProtocolMessageFlight`] is used for exchanges with the PUT.

#[derive(Debug, Clone, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub enum Message {
    Hello(HelloMessage),
    Acknowledge(AcknowledgeMessage),
    Error(ErrorMessage),
    Reverse(ReverseHelloMessage),
    Open(MessageChunkHeader, #[extractable_ignore] Vec<u8>),
    Chunk(MessageChunkHeader, MessageBody),
}

impl Codec for Message {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            Message::Hello(ref h) => h.encode(bytes),
            Message::Acknowledge(ref a) => a.encode(bytes),
            Message::Error(ref e) => e.encode(bytes),
            Message::Reverse(ref r) => r.encode(bytes),
            Message::Open(ref h, ref c) => {
                h.encode(bytes);
                bytes.extend_from_slice(&c);
            }
            Message::Chunk(ref header, ref body ) => {
                header.encode(bytes);
                body.encode(bytes);
            }
        }
    }

    fn read(rd: &mut Reader) -> Option<Self> {
        if let Some(head) = rd.peek(3) {
        match head {
            HELLO_MESSAGE => {
                let mut h = HelloMessage::new(&"",0,0,0,0);
                if let Ok(()) = HelloMessage::read(&mut h, rd) {Some(Message::Hello(h))}
                else {None}
            }
            ACKNOWLEDGE_MESSAGE => {
                let mut a = AcknowledgeMessage {
                    message_header: MessageHeader::new(MessageType::Acknowledge),
                    protocol_version: 0,
                    receive_buffer_size: 0,
                    send_buffer_size: 0,
                    max_message_size: 0,
                    max_chunk_count: 0
                };
                if let Ok(()) = AcknowledgeMessage::read(&mut a, rd) {Some(Message::Acknowledge(a))}
                else {None}
            }
            REVERSE_HELLO_MESSAGE => {
                let mut r = ReverseHelloMessage{
                    message_header: MessageHeader::new(MessageType::Reverse),
                    server_uri: UAString::null(),
                    endpoint_url: UAString::null()
                };
                if let Ok(()) = ReverseHelloMessage::read(&mut r, rd) {Some(Message::Reverse(r))}
                else {None}
            }
            ERROR_MESSAGE => {
                let mut e = ErrorMessage{
                    message_header: MessageHeader::new(MessageType::Error),
                    error: 0,
                    reason: UAString::null()
                };
                if let Ok(()) = ErrorMessage::read(&mut e, rd) {Some(Message::Error(e))}
                else {None}
            }
            OPEN_SECURE_CHANNEL_MESSAGE => {
                let mut header = MessageChunkHeader{
                    message_type: MessageChunkType::OpenSecureChannel,
                    is_final: MessageIsFinalType::Final,
                    message_size: 0,
                    secure_channel_id: 0
                };
                if let Ok(()) = MessageChunkHeader::read(&mut header, rd) {
                    let size = (header.message_size as usize) - MESSAGE_CHUNK_HEADER_SIZE;
                    if size < 1 { return None }
                    let mut body = vec![0u8; size];
                    if let Ok(()) = rd.read_exact(&mut body) {
                        Some(Message::Open(header, body))
                    } else {None}
                } else {None}
            }
            CLOSE_SECURE_CHANNEL_MESSAGE | CHUNK_MESSAGE => {
                let mut header = MessageChunkHeader{
                    message_type: MessageChunkType::OpenSecureChannel,
                    is_final: MessageIsFinalType::Final,
                    message_size: 0,
                    secure_channel_id: 0
                };
                if let Ok(()) = MessageChunkHeader::read(&mut header, rd) {
                    let size = (header.message_size as usize) - MESSAGE_CHUNK_HEADER_SIZE;
                    if size < 1 { return None }
                    let mut body = MessageBody::default();
                    if let Ok(()) = CodecP::read(&mut body, rd) {
                        Some(Message::Chunk(header, body))
                    } else {None}
                } else {None}
            }
            _ => None
        }
        } else {None}
    }
}

impl codec::VecCodecWoSize for Message {}

impl OpaqueProtocolMessage<OpcuaProtocolTypes> for Message {
    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

// /!\ a ServiceMessage may be encoded as a MessageFlight and not
//     only as a single message.
impl ProtocolMessage<OpcuaProtocolTypes, Message> for Message {
    fn create_opaque(&self) -> Message {
        self.clone()
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}


/**
The enum type [`crate::core::supported_message::SupportedMessage`] defines all [`ProtocolMessage`],
i.e. all possible OPC UA service requests before security is applied to them,
and all possible responses after security has been removed from them.
/!\ We use here a simplified enum type, for a first try, called a [`ServiceMessage`]
*/
#[derive(Debug, PartialEq, Clone, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub enum ServiceMessage {
    // /!\ The trait is not implemented for Box<...>!
    // /!\ We may have to add the SecureChannel data.
    OpenSecureChannelRequest(OpenSecureChannelRequest),
    OpenSecureChannelResponse(OpenSecureChannelResponse),
    CloseSecureChannelRequest(CloseSecureChannelRequest),
    CloseSecureChannelResponse(CloseSecureChannelResponse),
    None
}

impl Codec for ServiceMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            ServiceMessage::OpenSecureChannelRequest(ref r) =>
               r.encode(bytes),
            ServiceMessage::OpenSecureChannelResponse(ref r) =>
               r.encode(bytes),
            ServiceMessage::CloseSecureChannelRequest(ref r) =>
               r.encode(bytes),
            ServiceMessage::CloseSecureChannelResponse(ref r) =>
               r.encode(bytes),
            ServiceMessage::None => ()
        }
    }

    fn read(rd: &mut Reader) -> Option<Self> {
        let mut open_request = OpenSecureChannelRequest {
            request_header: RequestHeader::default(),
            client_protocol_version: 0,
            request_type: SecurityTokenRequestType::Issue,
            security_mode: MessageSecurityMode::Sign,
            client_nonce: ByteString::null(),
            requested_lifetime: 0,
        };
        if let Ok(()) = CodecP::read(&mut open_request, rd) {
            return Some(ServiceMessage::OpenSecureChannelRequest(open_request))
        };
        let mut open_response = OpenSecureChannelResponse {
            response_header: ResponseHeader::null(),
            server_protocol_version: 0,
            security_token: ChannelSecurityToken::default(),
            server_nonce: ByteString::null()
        };
        if let Ok(()) = CodecP::read(&mut open_response, rd) {
            return Some(ServiceMessage::OpenSecureChannelResponse(open_response))
        }
        let mut close_request = CloseSecureChannelRequest {
            request_header: RequestHeader::default()
        };
        if let Ok(()) = CodecP::read(&mut close_request, rd) {
            return Some(ServiceMessage::CloseSecureChannelRequest(close_request))
        };
        let mut close_response = CloseSecureChannelResponse {
            response_header: ResponseHeader::null()
        };
        if let Ok(()) = CodecP::read(&mut close_response, rd) {
            return Some(ServiceMessage::CloseSecureChannelResponse(close_response))
        }
        None
    }
}

#[derive(Debug, Clone, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub struct MessageBody {
    pub channel_token_id: u32,
    pub sequence_header: SequenceHeader,
    pub request: ServiceMessage,
    pub mac: Vec<u8>
}

impl Default for MessageBody {
    fn default() -> MessageBody {
        MessageBody{
            channel_token_id: 0,
            sequence_header: SequenceHeader {
                sequence_number: 0,
                request_id: 0
            },
            request: ServiceMessage::None,
            mac: vec![]
        }
    }
}

impl CodecP for MessageBody {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CodecP::encode(&self.channel_token_id, bytes);
        CodecP::encode(&self.sequence_header, bytes);
        bytes.extend_from_slice(&self.mac);
    }

    fn read(&mut self, rd: &mut Reader) -> Result<(), Error> {
        self.channel_token_id.read(rd)?;
        self.sequence_header.read(rd)?;
        self.request.read(rd)?;
        self.mac.read(rd)?;
        Ok(())
    }
}


/// The [`MessageDeframer`] is used to extract from a buffer of bytes ([u8]) a [`MessageFlight`].
// Maybe, some of the code of the MessageDeframer should be moved into Puffin,
// and the trait should only implement "try_deframe_one"?
pub struct MessageDeframer {
    /// Complete chunks ready to be deciphered.
    pub frames: VecDeque<Message>,
    /// A fixed-size buffer containing a bunch of OPC UA messages, or only a part of one.
    buffer: Box<[u8; MAX_WIRE_SIZE]>,
    /// What part of buffer is used.
    used: usize,
}

impl Default for MessageDeframer {
    fn default() -> Self {
        Self::new()
    }
}

enum BufferContent {
    /// this enum gives the status of the prefix found in MessageDeframer.buffer:
    /// it may contain either an invalid message, a partial message or a valid chunk.
    Invalid,
    Partial,
    Valid
}

impl MessageDeframer {
    pub fn new() -> Self {
        Self {
            frames: VecDeque::new(),
            buffer: Box::new([0u8; MAX_WIRE_SIZE]),
            used: 0,
        }
    }

    /// Read some bytes from `rd`, and add them to our internal buffer.
    /// Then if our internal buffer contains full messages, decode them all.
    pub fn read(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        // Try to do the largest reads possible.  Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        debug_assert!(self.used <= MAX_WIRE_SIZE);
        let new_bytes = rd.read(&mut self.buffer[self.used..])?;
        self.used += new_bytes;

        if new_bytes > 0 { loop {
            match self.try_deframe_one() {
                BufferContent::Invalid => {
                    self.used = 0;  // TODO: try to resynchronize.
                    log::error!("Invalid UA TCP message!");
                    break;
                }
                BufferContent::Valid => continue,
                BufferContent::Partial => break,
            }
        }}
        Ok(new_bytes)
    }

    /// Returns true if we have messages for the caller to process,
    /// either whole chunks in our output queue or a partial chunk in our buffer.
    pub fn has_pending(&self) -> bool {
        !self.frames.is_empty() || self.used > 0
    }

    /// Try to decode an UA TCP or UA SC message off the front of the buffer,
    /// and store it in "frames". We just read the MessageHeader.
    fn try_deframe_one(&mut self) -> BufferContent {
        //log::warn!("Try deframe one UA TCP message (buffer size: {})", self.used);
        if self.used < MESSAGE_HEADER_LEN { return BufferContent::Partial }
        let mut rd = codec::Reader::init(&self.buffer[0..MESSAGE_HEADER_LEN]);
        let mut message_header = MessageHeader::new(MessageType::Hello);
        let result = MessageHeader::read(&mut message_header, &mut rd);
        if let Err(_) = result {
            return BufferContent::Invalid
        }
        let message_size = message_header.message_size as usize;
        if message_size > self.used {
            return BufferContent::Partial
        }
        let head: [u8; 4] = self.buffer[0..4].try_into().unwrap(); //checked by MessageHeader::read
        let message_head = str::from_utf8(&head).unwrap(); //checked by MessageHeader::read
        let mut rd = codec::Reader::init(&self.buffer[0..message_size]);
        if let Some(msg) = Codec::read(&mut rd) {
            log::warn!("New UA TCP message received! ({}, {} bytes)", message_head, message_size);
            self.frames.push_back(msg);
            self.consume(message_size);
            if (&head[0..3] == CHUNK_MESSAGE) && (head[3] == CHUNK_INTERMEDIATE) {
                return BufferContent::Partial
            } else {
                return BufferContent::Valid
            }
        } else {
            log::warn!("Error reading an UA TCP message! ({}, {} bytes)", message_head, message_size);
            return BufferContent::Invalid
        }
    }

    fn consume(&mut self, size: usize) {
        if size < self.used {
            self.buffer.copy_within(size..self.used, 0);
            self.used -= size;
        } else if size == self.used {
            self.used = 0;
        }
    }

}

impl ProtocolMessageDeframer<OpcuaProtocolTypes> for MessageDeframer {
    type OpaqueProtocolMessage = Message;

    fn pop_frame(&mut self) -> Option<Message> {
        self.frames.pop_front()
    }

    fn read(&mut self, rd: &mut dyn Read) -> std::io::Result<usize> {
        self.read(rd)
    }
}

impl ProtocolMessageFlight<OpcuaProtocolTypes, Message, Message, MessageFlight>
    for MessageFlight
{
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: Message) {
        self.messages.push(msg);
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

/// All chunks of a complete UA TCP message are grouped into an [`OpaqueProtocolMessageFlight`]
/// that can be exchanged with the target (PUT)
#[derive(Debug, Clone, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub struct MessageFlight {
    messages: Vec<Message>,
}

impl MessageFlight {
    // Creates a flight of messages from the encoded chunks of a message issued by a secure channel.
    // fn from_sc_message(&mut self, chunks: &Vec<MessageChunk>) {
    //     self.messages.clear();
    //     for msg_chunk in chunks {
    //         self.messages.push(Message::Chunk(msg_chunk.clone()))
    //     }
    // }
}

impl OpaqueProtocolMessageFlight<OpcuaProtocolTypes, Message> for MessageFlight {
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: Message) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self);
    }
}

impl From<Message> for MessageFlight {
    fn from(value: Message) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

impl Codec for MessageFlight {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for msg in &self.messages {
            Codec::encode(msg, bytes)
        }
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let mut deframer = MessageDeframer::new();
        let mut flight = <MessageFlight as OpaqueProtocolMessageFlight<OpcuaProtocolTypes, Message>>::new();

        let _ = deframer.read(&mut reader.rest());
        while let Some(msg) = deframer.pop_frame() {
            OpaqueProtocolMessageFlight::push(&mut flight, msg);
            // continue to read the buffer
            let _ = deframer.read(&mut reader.rest());
        }
        Some(flight)
    }
}

