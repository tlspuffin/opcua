use fn_impl::*;
use puffin::algebra::dynamic_function::FunctionAttributes;
use puffin::algebra::error::FnError;
use puffin::define_signature;
use crate::prelude::{ByteString, MessageType};
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::encoding::BinaryEncoder;
use crate::types::{
    AcknowledgeMessage, DiagnosticBits, ErrorMessage, ExtensionObject, HelloMessage, MessageHeader, MessageSecurityMode, NodeId, 
    OpenSecureChannelRequest, ReverseHelloMessage, RequestHeader, SecurityTokenRequestType, UAString, UtcTime
};

/// These modules contain all the concrete implementations of function symbols.
#[path = "."]
pub mod fn_impl {
    pub mod fn_constants;
    pub use fn_constants::*;

    pub mod fn_uasc;
    pub use fn_uasc::*;
}


/// UA TCP sub-protocol:

/// Reverse Hello
pub fn fn_server_hello (
    server_uri:  &Vec<u8>,
    endpoint_url: &Vec<u8>,
) -> Result<ReverseHelloMessage, FnError> {
    let mut msg = ReverseHelloMessage {
        message_header: MessageHeader::new(MessageType::Reverse),
        server_uri: UAString::from(String::from_utf8_lossy(server_uri).as_ref()),
        endpoint_url: UAString::from(String::from_utf8_lossy(&endpoint_url).as_ref())
    };
    msg.message_header.message_size = msg.byte_len() as u32;
    Ok(msg)
}

/// Hello
pub fn fn_client_hello (
    endpoint_url: &Vec<u8>,
    send_buffer_size: &u32,
    receive_buffer_size: &u32
) -> Result<HelloMessage, FnError> {
    let mut msg = HelloMessage {
        message_header: MessageHeader::new(MessageType::Hello),
        protocol_version: 0,
        send_buffer_size: *send_buffer_size,
        receive_buffer_size: *receive_buffer_size,
        max_message_size: 0,  // 0: Client has no limit
        max_chunk_count: 0,   // 0: Client has no limit
        endpoint_url: UAString::from(String::from_utf8_lossy(endpoint_url).as_ref())
    };
    msg.message_header.message_size = msg.byte_len() as u32;
    Ok(msg)
}

/// Acknowledge
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

/// Error
pub fn fn_error (
    error_code: &u32,
    reason: &String
) -> Result<ErrorMessage, FnError> {
    let mut msg = ErrorMessage {
        message_header: MessageHeader::new(MessageType::Error),
        error: *error_code,
        reason: UAString::from(reason),
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
pub fn fn_client_open(
    client_nonce: &ByteString
) -> Result<OpenSecureChannelRequest, FnError> {
    Ok(OpenSecureChannelRequest {
        request_header: Default::default(),
        client_protocol_version: 0,
        request_type: SecurityTokenRequestType::Issue,
        security_mode: MessageSecurityMode::Sign,
        client_nonce: client_nonce.clone(),
        requested_lifetime: 0,
    })
}

// pub fn fn_new_secure_channel(
//     role: &Role,
//     security_mode: &MessageSecurityMode,

// ) -> Result<SecureChannel, FnError> {
//     Ok(SecureChannel {
//         role,
//         security_policy: SecurityPolicy::Basic256Sha256,
//         security_mode,
//         secure_channel_id: 0,
//         token_created_at: DateTime::default(),
//         token_lifetime: 0,
//         token_id: 0,
//         /// Our certificate
//         cert: Option<X509>,
//         /// Our private key
//         private_key: Option<PrivateKey>,
//         /// Their certificate
//         remote_cert: Option<X509>,
//         /// Their nonce provided by open secure channel
//         remote_nonce: Vec<u8>,
//         /// Our nonce generated while handling open secure channel
//         local_nonce: Vec<u8>,
//         /// Client (i.e. other end's set of keys) Symmetric Signing Key, Encrypt Key, IV
//         remote_keys: None, //Option<(Vec<u8>, AesKey, Vec<u8>)>,
//         /// Server (i.e. our end's set of keys) Symmetric Signing Key, Decrypt Key, IV
//         local_keys: None, //Option<(Vec<u8>, AesKey, Vec<u8>)>,
//         /// Decoding options
//         decoding_options: DecodingOptions,


//     })
// }



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


define_signature! {
    OPCUA_SIGNATURE<OpcuaProtocolTypes>,
    // constants
    fn_true
    fn_false

    fn_seq_0

    fn_alice_cert
    fn_bob_cert
    fn_mallory_cert
    fn_oscar_cert

    // UA TCP messages:
    fn_server_hello
    fn_client_hello
    fn_acknowledge
    fn_error

    fn_default_size
    fn_size_8192
    fn_bob_uri
    fn_bob_endpoint


    // UA SC messages:
    fn_chunk_header
    fn_chunk

    fn_client_open

    fn_issue
    fn_renew

    fn_request_header

    fn_sa_token_zero

}
