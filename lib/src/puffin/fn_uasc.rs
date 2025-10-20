// UA SC sub-protocol:

use std::io::{Read, Write};

use puffin::algebra::error::FnError;

use crate::crypto::SecurityPolicy;
use crate::prelude::{AsymmetricSecurityHeader, DecodingOptions, EncodingResult, MessageChunk,
   MessageChunkHeader, MessageChunkType, MessageIsFinalType, SecurityHeader, SequenceHeader};
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::encoding::BinaryEncoder;
use crate::types::{ByteString, StatusCode, UAString,
    process_decode_io_result, process_encode_io_result, write_u8};

pub fn fn_chunk_header (
    message_type: &MessageChunkType,
    is_final: &MessageIsFinalType,
    secure_channel_id: &u32
) -> Result<MessageChunkHeader, FnError> {
    Ok(MessageChunkHeader{
        message_type: message_type.clone(),
        is_final: is_final.clone(),
        message_size: 0,
        secure_channel_id: *secure_channel_id
    })
}

pub fn fn_asymmetric_security_header(
    security_policy_uri: &Vec<u8>,
    sender_certificate: &Vec<u8>,
    receiver_certificate_thumbprint: &Vec<u8>
) -> Result<AsymmetricSecurityHeader, FnError> {
    Ok(AsymmetricSecurityHeader {
        security_policy_uri: UAString::from(String::from_utf8_lossy(security_policy_uri).as_ref()),
        sender_certificate: ByteString{value: Some(sender_certificate.clone()) },
        receiver_certificate_thumbprint: ByteString{value: Some(receiver_certificate_thumbprint.clone())}
    })
}

pub fn fn_sequence_header(
    sequence_number: &u32,
    request_id: &u32,
) -> Result<SequenceHeader, FnError> {
    Ok(SequenceHeader {
        sequence_number: *sequence_number,
        request_id: *request_id
    })
}

pub fn fn_data_to_sign(
    security: &Vec<u8>,
    sequence: &SequenceHeader,
    request: &Vec<u8>
 ) -> Result<Vec<u8>, FnError> {
    let mut buffer= Vec::<u8>::new();
    buffer.extend_from_slice(security);
    let _ = sequence.encode(&mut buffer);
    buffer.extend_from_slice(request);
    Ok(buffer)
 }

pub fn fn_sign (
    chunk_header: &MessageChunkHeader,
    data: &Vec<u8>,
    policy: &SecurityPolicy,
    private_key: &Vec<u8>
) -> Result<Vec<u8>, FnError> {
    Ok(vec![1,2,3])
}

pub fn fn_chunk (
    header: &MessageChunkHeader,
    security: &Vec<u8>,
    body: &Vec<u8>,
) -> Result<MessageChunk, FnError> {
    let mut buffer= Vec::<u8>::new();
    let result = header.encode(&mut buffer);
    if let Err(_) = result {
        return Err(FnError::Codec("Error while encoding chunk header".to_string()))
    }
    buffer.extend_from_slice(security);
    buffer.extend_from_slice(body);
    Ok(MessageChunk {data: buffer})
}