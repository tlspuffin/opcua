// UA SC sub-protocol:

use puffin::algebra::error::FnError;
use puffin::codec::{CodecP, Reader};
use puffin::error::Error;

use crate::crypto::SecurityPolicy;
use crate::prelude::{AsymmetricSecurityHeader, MessageChunk,
   MessageChunkHeader, MessageChunkType, MessageIsFinalType, SequenceHeader};
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::encoding::BinaryEncoder;
use crate::types::{ByteString, UAString};

use extractable_macro::Extractable;

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

// Making crate::crypto::SecurityPolicy extractable and encodable through CodecP
// creates a lot of troubles for compiling the existing code of opcua-mapper.
// (conflicts between puffin::codec:CodecP and BinaryEncoder and huge borrow
// checker errors).
// Hence I prefer to duplicate this enum here:

#[derive(Clone, Copy, Debug, Deserialize, Eq, Extractable, Hash, PartialEq, Serialize)]
#[extractable(OpcuaProtocolTypes)]
pub enum CipherSuite {
    Unknown,
    None,
    Aes128Sha256RsaOaep,
    Basic256Sha256,
    Aes256Sha256RsaPss,
    Basic128Rsa15,
    Basic256,
}

impl CipherSuite {
    fn security_policy(v: CipherSuite) -> SecurityPolicy {
        match v {
            CipherSuite::Unknown => SecurityPolicy::Unknown,
            CipherSuite::None => SecurityPolicy::None,
            CipherSuite::Aes128Sha256RsaOaep => SecurityPolicy::Aes128Sha256RsaOaep,
            CipherSuite::Basic256Sha256 => SecurityPolicy::Basic256Sha256,
            CipherSuite::Aes256Sha256RsaPss => SecurityPolicy::Aes256Sha256RsaPss,
            CipherSuite::Basic128Rsa15 => SecurityPolicy::Basic128Rsa15,
            CipherSuite::Basic256 => SecurityPolicy::Basic256
        }
    }
}

impl From<SecurityPolicy> for CipherSuite {
    fn from(v: SecurityPolicy) -> CipherSuite {
        match v {
            SecurityPolicy::Unknown => CipherSuite::Unknown,
            SecurityPolicy::None => CipherSuite::None,
            SecurityPolicy::Aes128Sha256RsaOaep => CipherSuite::Aes128Sha256RsaOaep,
            SecurityPolicy::Basic256Sha256 => CipherSuite::Basic256Sha256,
            SecurityPolicy::Aes256Sha256RsaPss => CipherSuite::Aes256Sha256RsaPss,
            SecurityPolicy::Basic128Rsa15 => CipherSuite::Basic128Rsa15,
            SecurityPolicy::Basic256 => CipherSuite::Basic256
        }
    }
}


impl CodecP for CipherSuite {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let uri = UAString::from(CipherSuite::security_policy(*self).to_uri());
        CodecP::encode(&uri, bytes);
    }

    fn read(&mut self, rd: &mut Reader) -> Result<(), Error> {
        let mut uri: UAString = UAString::null();
        uri.read(rd)?;
        *self = CipherSuite::from(SecurityPolicy::from_uri(uri.as_ref()));
        Ok(())
    }
}


pub fn fn_asymmetric_security_header(
    cipher_suite: &CipherSuite,
    sender_certificate: &Vec<u8>,
    receiver_certificate_thumbprint: &Vec<u8>
) -> Result<Vec<u8>, FnError> {
    let header = AsymmetricSecurityHeader {
        security_policy_uri: UAString::from(CipherSuite::security_policy(*cipher_suite).to_uri()),
        sender_certificate: ByteString{value: Some(sender_certificate.clone()) },
        receiver_certificate_thumbprint: ByteString{value: Some(receiver_certificate_thumbprint.clone())}
    };
    let mut bytes = Vec::<u8>::new();
    let _ = CodecP::encode(&header, &mut bytes);
    Ok(bytes)
}

pub fn fn_symmetric_security_header(
    token_id: &u32
) -> Result<Vec<u8>, FnError> {
    let mut bytes = Vec::<u8>::new();
    CodecP::encode(token_id, &mut bytes);
    Ok(bytes)
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
    let _ = CodecP::encode(sequence, &mut buffer);
    buffer.extend_from_slice(request);
    Ok(buffer)
 }

pub fn fn_sign (
    policy: &CipherSuite,
    chunk_header: &MessageChunkHeader,
    data: &Vec<u8>,
    private_key: &Vec<u8>
) -> Result<Vec<u8>, FnError> {
    let mut header = chunk_header.clone();
    header.message_size = (data.len() + header.byte_len()) as u32;
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(&header, &mut buffer);
    buffer.extend_from_slice(data);

    let mut signature = Vec::<u8>::new();
    
    Ok(signature)
}

pub fn fn_chunk (
    header: &MessageChunkHeader,
    security: &Vec<u8>,
    body: &Vec<u8>,
) -> Result<MessageChunk, FnError> {
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(header, &mut buffer);
    buffer.extend_from_slice(security);
    buffer.extend_from_slice(body);
    Ok(MessageChunk {data: buffer})
}