use extractable_macro::Extractable;
use puffin::algebra::dynamic_function::FunctionAttributes;
use puffin::algebra::error::FnError;
use puffin::error::Error;
use puffin::{codec, define_signature, dummy_codec};
use crate::prelude::{ByteString, MessageType};
use crate::puffin::fn_constants::*;
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::encoding::BinaryEncoder;
use crate::types::{
    AcknowledgeMessage, DiagnosticBits, ErrorMessage, ExtensionObject, HelloMessage, Identifier, MessageHeader, MessageSecurityMode, NodeId, 
    OpenSecureChannelRequest, RequestHeader, SecurityTokenRequestType, UAString, UtcTime
};

/// UA TCP client Hello message
pub fn fn_hello (
    endpoint_url: &UAString,
    send_buffer_size: &u32,
    receive_buffer_size: &u32,
) -> Result<HelloMessage, FnError> {
    let mut msg = HelloMessage {
        message_header: MessageHeader::new(MessageType::Hello),
        protocol_version: 0,
        send_buffer_size: *send_buffer_size,
        receive_buffer_size: *receive_buffer_size,
        max_message_size: 0,  // 0: Client has no limit
        max_chunk_count: 0,   // 0: Client has no limit
        endpoint_url: endpoint_url.clone()
    };
    msg.message_header.message_size = msg.byte_len() as u32;
    Ok(msg)
}

/// UA TCP server response to Hello message
pub fn fn_acknowledge (
    receive_buffer_size: &u32,
    send_buffer_size: &u32,
) -> Result<AcknowledgeMessage, FnError> {
    let mut msg = AcknowledgeMessage {
        message_header: MessageHeader::new(MessageType::Acknowledge),
        protocol_version: 0,
        receive_buffer_size: *receive_buffer_size,
        send_buffer_size: *send_buffer_size,
        max_message_size: 0,  // 0: Server has no limit
        max_chunk_count: 0,   // 0: Server has no limit
    };
    msg.message_header.message_size = msg.byte_len() as u32;
    Ok(msg)
}

pub fn fn_error (
   reason: &UAString,
   error_code: &u32
) -> Result<ErrorMessage, FnError> {
    let mut msg = ErrorMessage {
        message_header: MessageHeader::new(MessageType::Error),
        error: *error_code,
        reason: reason.clone(),
    };
    msg.message_header.message_size = msg.byte_len() as u32;
    Ok(msg)
}

/*
From types::service_types::open_secure_channel_request:
- [X] TODO1: make this CodecP implementation a derive macro CodecP to automate the process of writing this for all struct and enum of our choice
        ---> Done in types::service_types::open_secure_channel_request!
        ---> Make it a proper derive macro (procedural macro) would be highly complex because it
        has to be defined in an external crate, that would need to use this crate and puffin.
        But this crate would also need to use the procedural macro crate --> cyclic dependencies
        --> Keep as it is and use codec::impl_codec_p! instead!
 - [x] TODO2: Also use Extractable macro instead of manually implementing it in opcuapuffin
        --> Done, see above file.
 - [ ] TODO3: Add a new macro Constructor to automate the definition of construction function symbol, e.g., fn_OpenSecureChannelRequest
*/

// Since we have not done TODO3, yet, here is a manual constructor function:
pub fn fn_open_channel_request(
    security_mode: &MessageSecurityMode,
    client_nonce: &ByteString
) -> Result<OpenSecureChannelRequest, FnError> {
    Ok(OpenSecureChannelRequest {
        request_header: Default::default(),
        client_protocol_version: 0,
        request_type: SecurityTokenRequestType::Issue,
        security_mode: security_mode.clone(),
        client_nonce: client_nonce.clone(),
        requested_lifetime: 0,
    })
}

// /!\ The SA Token is an UInt32 identifier for a NodeId!
pub fn fn_sa_token(v: &u32) -> Result<NodeId, FnError> {
    Ok(NodeId {
        namespace: 0,
        identifier: Identifier::from(*v)
    })
}

pub fn fn_request_header(
    sa_token: &NodeId,
    request_id: &u32,
) -> Result<RequestHeader, FnError> {
    Ok(RequestHeader{
        authentication_token: sa_token.clone(),
        timestamp: UtcTime::now(),
        request_handle: *request_id,
        return_diagnostics: DiagnosticBits::empty(),
        audit_entry_id: UAString::null(),
        timeout_hint: 0, // No timeout
        additional_header: ExtensionObject::default()
    })
}


/* -----------------------------------------------------------------------------
              TO REMOVE LATER
----------------------------------------------------------------------------- */

#[derive(Clone, Debug, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub struct MessageChunk {
    // msg_header: MessageHeader,
    //sec_header: SecurityHeader,
    payload: Vec<u8>,
}

dummy_codec!(OpcuaProtocolTypes, MessageChunk);

pub fn fn_message_chunk() -> Result<MessageChunk, FnError> {
    Ok(MessageChunk {
        // msg_header: MessageHeader {
        //     msg_type: *(b"OPN"),
        //     // is_final: b'F',
        //     // msg_size: 0x15,
        //     sc_id: fn_new_channel_id().unwrap(),
        // },
        payload: vec![0x01, 0x02, 0x03, 0x04],
    })
}

/* -----------------------------------------------------------------------------
             END TO REMOVE LATER
----------------------------------------------------------------------------- */

define_signature! {
    OPCUA_SIGNATURE<OpcuaProtocolTypes>,
    // constants
    fn_true
    fn_false
    fn_none
    fn_sign
    fn_encrypt
    fn_seq_0
    fn_sa_token
    // messages
    fn_hello
    fn_acknowledge
    fn_error
    fn_open_channel_request
    fn_request_header
    fn_message_chunk
}
