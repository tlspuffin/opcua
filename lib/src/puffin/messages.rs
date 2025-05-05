use crate::core::comms::tcp_codec::{Message};
use crate::core::comms::tcp_types::{
    CHUNK_MESSAGE, OPEN_SECURE_CHANNEL_MESSAGE, CLOSE_SECURE_CHANNEL_MESSAGE,
    HELLO_MESSAGE, ACKNOWLEDGE_MESSAGE, ERROR_MESSAGE, REVERSE_HELLO_MESSAGE,
    CHUNK_FINAL, CHUNK_INTERMEDIATE, CHUNK_FINAL_ERROR};
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::{
    AcknowledgeMessage, ErrorMessage, HelloMessage, MessageChunk, MessageHeader, MessageType, OpenSecureChannelRequest, OpenSecureChannelResponse, ReverseHelloMessage, UAString};
use crate::types::encoding::read_u32;

use extractable_macro::Extractable;
use puffin::codec::{Codec, CodecP, Reader};
use puffin::error::Error;
use puffin::protocol::{
    Extractable, OpaqueProtocolMessage, OpaqueProtocolMessageFlight, ProtocolMessage,
    ProtocolMessageDeframer, ProtocolMessageFlight, ProtocolTypes,
};
use puffin::trace::{Knowledge, Source};
use puffin::{codec, dummy_codec, dummy_extract_knowledge, dummy_extract_knowledge_codec};

use std::collections::VecDeque;
use std::convert::TryFrom;
//use std::fmt;
use std::io;
use std::io::Read;

/// The enum type [`crate::core::comms::tcp_codec::Message`] defines
/// all [`OpaqueProtocolMessage`], i.e. UA Connection Protocol messages,
/// and chunks of UA Secure Channel messages that are Signed and/or Encrypted.
/// These messages are opaque in the sense that chunks may be encrypted.
/// Yet, knowledge can be learned from them if they are not encrypted.
/// The [`OpaqueProtocolMessageFlight`] is used for exchanges with the PUT.

impl Message {

    pub const MAX_WIRE_SIZE: usize = 40960; // TODO: adjust this value to the real buffer size

}

impl Codec for Message {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            Message::Hello(ref h) => h.encode(bytes),
            Message::Acknowledge(ref a) => a.encode(bytes),
            Message::Error(ref e) => e.encode(bytes),
            Message::Reverse(ref r) => r.encode(bytes),
            Message::Chunk(ref c) => bytes.extend_from_slice(&c.data) //c.encode(bytes) will panic!
        }
    }

    fn read(rd: &mut Reader) -> Option<Self> {
        match rd.peek(3).unwrap() {
            HELLO_MESSAGE => {
                let mut h = HelloMessage::new(&"",0,0,0,0);
                HelloMessage::read(&mut h, rd).unwrap();
                Some(Message::Hello(h))
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
                AcknowledgeMessage::read(&mut a, rd).unwrap();
                Some(Message::Acknowledge(a))
            }
            REVERSE_HELLO_MESSAGE => {
                let mut r = ReverseHelloMessage{
                    message_header: MessageHeader::new(MessageType::Reverse),
                    server_uri: UAString::null(),
                    endpoint_url: UAString::null()
                };
                ReverseHelloMessage::read(&mut r, rd).unwrap();
                Some(Message::Reverse(r))
            }
            ERROR_MESSAGE => {
                let mut e = ErrorMessage{
                    message_header: MessageHeader::new(MessageType::Error),
                    error: 0,
                    reason: UAString::null()
                };
                ErrorMessage::read(&mut e, rd).unwrap();
                Some(Message::Error(e))
            }
            OPEN_SECURE_CHANNEL_MESSAGE | CLOSE_SECURE_CHANNEL_MESSAGE | CHUNK_MESSAGE => {
                let mut c = MessageChunk{
                    data: vec![]
                };
                MessageChunk::read(&mut c, rd).unwrap();
                Some(Message::Chunk(c))
            }
            _ => None
        }
    }
}

impl codec::VecCodecWoSize for Message {}

impl OpaqueProtocolMessage<OpcuaProtocolTypes> for Message {
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
}

impl Codec for ServiceMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            ServiceMessage::OpenSecureChannelRequest(ref r) =>
               r.encode(bytes),
            ServiceMessage::OpenSecureChannelResponse(ref r) =>
               r.encode(bytes),
        }
    }

    fn read(_rd: &mut Reader) -> Option<Self> {
        panic!("Not implemented for test stub");
    }
}

// /!\ a ServiceMessage may be encoded as a MessageFlight and not
//     only as a single message.
impl ProtocolMessage<OpcuaProtocolTypes, Message> for ServiceMessage {
    fn create_opaque(&self) -> Message {
        panic!("Not implemented for test stub");
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

/// The [`MessageDeframer`] is used to extract from a buffer of bytes ([u8]) a [`MessageFlight`].
// Maybe, some of the code of the MessageDeframer should be moved into Puffin,
// and the trait should only implement "try_deframe_one"?
pub struct MessageDeframer {
    /// Complete chunks ready to be deciphered.
    pub frames: VecDeque<Message>,
    /// A fixed-size buffer containing a bunch of OPC UA messages.
    buffer: Box<[u8; Message::MAX_WIRE_SIZE]>,
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
            buffer: Box::new([0u8; Message::MAX_WIRE_SIZE]),
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
        debug_assert!(self.used <= Message::MAX_WIRE_SIZE);
        let new_bytes = rd.read(&mut self.buffer[self.used..])?;
        self.used += new_bytes;

        loop {
            match self.try_deframe_one() {
                BufferContent::Invalid => {
                    self.used = 0;  // TODO: log an error and try to resynchronize.
                    break;
                }
                BufferContent::Valid => continue,
                BufferContent::Partial => break,
            }
        }
        Ok(new_bytes)
    }

    /// Returns true if we have messages for the caller to process,
    /// either whole chunks in our output queue or a partial chunk in our buffer.
    pub fn has_pending(&self) -> bool {
        !self.frames.is_empty() || self.used > 0
    }

    /// Try to decode an UA TCP or UA SC message off the front of the buffer.
    fn try_deframe_one(&mut self) -> BufferContent {
        match &self.buffer[0..3] {
            CHUNK_MESSAGE => {
                match self.buffer[3] {
                    CHUNK_FINAL | CHUNK_INTERMEDIATE | CHUNK_FINAL_ERROR => {},
                    _ => return BufferContent::Invalid
                }
            }
            OPEN_SECURE_CHANNEL_MESSAGE | CLOSE_SECURE_CHANNEL_MESSAGE |
            HELLO_MESSAGE | ACKNOWLEDGE_MESSAGE | ERROR_MESSAGE | REVERSE_HELLO_MESSAGE => {
                match self.buffer[3] {
                    CHUNK_FINAL => {},
                    _ => return BufferContent::Invalid
                }
            }
            _ => return BufferContent::Invalid
        }
        let mut rd = codec::Reader::init(&self.buffer[3..7]);
        let message_size = read_u32(&mut rd).unwrap() as usize;
        if message_size > self.used {
            return BufferContent::Partial
        }
        let mut rd = codec::Reader::init(&self.buffer[0..message_size]);
        let msg: Message = Codec::read(&mut rd).unwrap();
        self.frames.push_back(msg);
        self.consume(message_size);
        return BufferContent::Valid
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

// Should not be useful...
#[derive(Debug, Clone)]
pub struct ServiceMessageFlight {
   pub messages: Vec<ServiceMessage>
}

impl ProtocolMessageFlight<OpcuaProtocolTypes, ServiceMessage, Message, MessageFlight>
    for ServiceMessageFlight
{
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: ServiceMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, _info: &str) {
        panic!("Not implemented for test stub");
    }
}

impl TryFrom<MessageFlight> for ServiceMessageFlight {
    type Error = ();

    fn try_from(_value: MessageFlight) -> Result<Self, Self::Error> {
        Ok(Self{ messages: vec![]})
    }
}

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, ServiceMessageFlight);

impl From<ServiceMessage> for ServiceMessageFlight {
    fn from(value: ServiceMessage) -> Self {
        Self{ messages: vec![value] }
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
        let mut flight = Self::new();

        let _ = deframer.read(&mut reader.rest());
        while let Some(msg) = deframer.pop_frame() {
            flight.push(msg);
            // continue to read the buffer
            let _ = deframer.read(&mut reader.rest());
        }

        Some(flight)
    }
}

impl From<ServiceMessageFlight> for MessageFlight {
    fn from(_value: ServiceMessageFlight) -> Self {
        panic!("Not implemented for test stub");
    }
}
