use fn_impl::*;
use puffin::algebra::dynamic_function::FunctionAttributes;
use puffin::algebra::error::FnError;
use puffin::define_signature;
use crate::prelude::MessageType;
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::encoding::BinaryEncoder;
use crate::types::{
    AcknowledgeMessage, ErrorMessage, HelloMessage, MessageHeader, ReverseHelloMessage, UAString};

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


define_signature! {
    OPCUA_SIGNATURE<OpcuaProtocolTypes>,
    // constants
    fn_true
    fn_false

    fn_seq_0
    fn_seq_1
    fn_seq_2
    fn_seq_3
    fn_seq_4
    fn_seq_5
    fn_seq_6
    fn_seq_7
    fn_seq_8
    fn_seq_9
    fn_seq_10

    fn_open
    fn_close
    fn_intermediate
    fn_final
    fn_abort

    fn_alice_cert
    fn_bob_cert
    fn_mallory_cert
    fn_oscar_cert
    fn_null_cert

    fn_alice_sk
    fn_bob_sk
    fn_mallory_sk
    fn_oscar_sk

    fn_security_policy_none
    fn_aes128sha256_rsa_oaep
    fn_basic256sha256
    fn_aes256sha256_rsa_pss
    fn_basic128_rsa_15
    fn_basic256

    fn_issue
    fn_renew
    fn_sa_token_zero

    fn_channel_nonce_1

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
    fn_header
    fn_sequence_header
    fn_request
    fn_body
    fn_open_header
    fn_data_to_sign
    fn_data_to_encrypt
    fn_sign
    fn_asym_encrypt
    fn_asym_decrypt
    fn_get_channel_token
    fn_get_server_nonce
    fn_client_mac_key
    fn_mac_header
    fn_data_to_mac
    fn_mac
    fn_message

    fn_request_header
    fn_client_open
    fn_client_close

}
