// symbolic functions for the UA Secure Channel sub-protocol

use std::io::Read;

use openssl::pkey::{Private};

use puffin::algebra::error::FnError;
use puffin::codec::{CodecP, Reader};
use puffin::error::Error;

use crate::core::comms::tcp_types::{
    CHUNK_MESSAGE, OPEN_SECURE_CHANNEL_MESSAGE, CLOSE_SECURE_CHANNEL_MESSAGE,
    CHUNK_FINAL, CHUNK_INTERMEDIATE, CHUNK_FINAL_ERROR};
use crate::crypto::{KeySize, PKey, PrivateKey, RsaPadding, SecurityPolicy, X509};
use crate::prelude::{AsymmetricSecurityHeader, MessageChunk, MessageChunkHeader,
    MESSAGE_CHUNK_HEADER_SIZE, MessageChunkType, MessageIsFinalType, SequenceHeader};
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::encoding::BinaryEncoder;
use crate::types::{ByteString, DiagnosticBits, ExtensionObject, MessageSecurityMode,
    NodeId, RequestHeader, SecurityTokenRequestType, UAString, UtcTime};
use crate::types::service_types::{CloseSecureChannelRequest, OpenSecureChannelRequest};


use extractable_macro::Extractable;

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
    fn to_message_chunk_type(self) -> MessageChunkType {
        match self {
            ChunkType::Open  => MessageChunkType::OpenSecureChannel,
            ChunkType::Close => MessageChunkType::CloseSecureChannel,
            _                => MessageChunkType::Message
        }
    }
    fn to_is_final(self) -> MessageIsFinalType {
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


pub fn fn_header (
    message_type: &ChunkType,
    secure_channel_id: &u32
) -> Result<MessageChunkHeader, FnError> {
    Ok(MessageChunkHeader{
        message_type: message_type.to_message_chunk_type(),
        is_final: message_type.to_is_final(),
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
    fn security_policy(self) -> SecurityPolicy {
        match self {
            CipherSuite::Unknown => SecurityPolicy::Unknown,
            CipherSuite::None => SecurityPolicy::None,
            CipherSuite::Aes128Sha256RsaOaep => SecurityPolicy::Aes128Sha256RsaOaep,
            CipherSuite::Basic256Sha256 => SecurityPolicy::Basic256Sha256,
            CipherSuite::Aes256Sha256RsaPss => SecurityPolicy::Aes256Sha256RsaPss,
            CipherSuite::Basic128Rsa15 => SecurityPolicy::Basic128Rsa15,
            CipherSuite::Basic256 => SecurityPolicy::Basic256
        }
    }

    fn needs_asym_encryption(self) -> bool {
        match self {
            CipherSuite::Unknown |
            CipherSuite::None => false,
            CipherSuite::Aes128Sha256RsaOaep => true,
            CipherSuite::Basic256Sha256 => true,
            CipherSuite::Aes256Sha256RsaPss => true,
            CipherSuite::Basic128Rsa15 => true,
            CipherSuite::Basic256 => true
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


pub fn fn_sequence_header(
    sequence_number: &u32,
    request_id: &u32,
) -> Result<SequenceHeader, FnError> {
    Ok(SequenceHeader {
        sequence_number: *sequence_number,
        request_id: *request_id
    })
}

pub fn fn_request(
    sequence: &SequenceHeader,
    request: &Vec<u8>
 ) -> Result<Vec<u8>, FnError> {
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(sequence, &mut buffer);
    buffer.extend_from_slice(request);
    Ok(buffer)
 }

pub fn fn_body(
    channel_token_id: &u32,
    request: &Vec<u8>,
    mac: &Vec<u8>
 ) -> Result<Vec<u8>, FnError> {
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(channel_token_id, &mut buffer);
    buffer.extend_from_slice(request);
    buffer.extend_from_slice(mac);
    Ok(buffer)
 }

// helper function copied from crate::comms::secure_channel
//cf. fn plain_text_block_size(&self, padding: RsaPadding) -> usize
fn calculate_plain_text_block_size (
    security_policy: SecurityPolicy,
    encryption_key_size: usize
) -> Result<usize, FnError> {
    let padding: RsaPadding = security_policy.asymmetric_encryption_padding();
    let padding_size: usize = match padding {
        RsaPadding::Pkcs1 => 11,
        RsaPadding::OaepSha1 => 42,
        RsaPadding::OaepSha256 => 66,
        _ => return Err(FnError::Crypto("Unsupported padding".to_string())),
    };
    Ok(encryption_key_size - padding_size)
}

// This is a complete revrite of SecureChannel::asymmetric_sign_and_encrypt()
// in crate::core::comms::secure_channel::SecureChannel.
pub fn fn_sign (
    chunk_header: &MessageChunkHeader,
    cipher_suite: &CipherSuite,
    sender_certificate: &Vec<u8>,
    receiver_certificate: &Vec<u8>,
    data: &Vec<u8>,
    private_key: &Vec<u8>
) -> Result<Vec<u8>, FnError> {

    let security_policy = cipher_suite.security_policy();
    let needs_asym_encryption = cipher_suite.needs_asym_encryption();
    let signature_size: usize = {
        let x509 = X509::from_der(sender_certificate)
           .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
        x509.public_key().unwrap().size()
    };
    let receiver_x509 = X509::from_der(&receiver_certificate)
       .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;

    let (cipher_text_size, padding_size, min_footer_size) =
        if needs_asym_encryption {
            let encryption_key_size: usize = receiver_x509.public_key().unwrap().size();

            let plain_text_block_size = calculate_plain_text_block_size(security_policy, encryption_key_size)?;
            let cipher_text_bloc_size = encryption_key_size;
            let min_footer_size: usize = if encryption_key_size > 2048 {2} else {1};
            let plain_text_size = data.len() + min_footer_size;
            let padding_size = plain_text_size % plain_text_block_size;
            let block_count = if padding_size == 0 {
                plain_text_size / plain_text_block_size
            } else {
                (plain_text_size / plain_text_block_size) + 1
            };
            let cipher_text_size = (block_count * cipher_text_bloc_size) + signature_size;
            (cipher_text_size, padding_size, min_footer_size)
        } else {
            let plain_text_size = data.len();
            (plain_text_size, 0, 0)
        };

    // collect data to sign in a buffer:
    let security_header = AsymmetricSecurityHeader {
        security_policy_uri: UAString::from(security_policy.to_uri()),
        sender_certificate: ByteString{value: Some(sender_certificate.clone()) },
        receiver_certificate_thumbprint: receiver_x509.thumbprint().as_byte_string()
    };
    let mut header = chunk_header.clone();
    header.message_size = (header.byte_len() + security_header.byte_len() + cipher_text_size) as u32;
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(&header, &mut buffer);
    CodecP::encode(&security_header, &mut buffer);
    buffer.extend_from_slice(data);
    // Add padding in the Message Footer
    if needs_asym_encryption {
        let padding_byte= (padding_size & 0xff) as u8;
        for _ in 0..padding_size+1 {
            buffer.push(padding_byte);
        }
        if min_footer_size == 2 {
            buffer.push((padding_size >> 8) as u8);
        }
    }

    // compute signature:
    let signing_key: PKey<Private> = openssl::pkey::PKey::private_key_from_pkcs8(private_key)
       .map(|value|{PrivateKey {value}})
       .map_err( |_| {FnError::Crypto("Error reading private key in PKCS #8 format with DER encoding".to_string())})?;

    let mut signature = vec![0u8; signature_size];
    security_policy.asymmetric_sign(&signing_key, &buffer, &mut signature)
       .map_err( |_| {FnError::Crypto("Error during signing".to_string())})?;
    Ok(signature)
}


pub fn fn_asym_encrypt (
    cipher_suite: &CipherSuite,
    sender_certificate: &Vec<u8>,
    receiver_certificate: &Vec<u8>,
    request: &Vec<u8>,
    signature: &Vec<u8>
) -> Result<Vec<u8>, FnError> {

    let security_policy = cipher_suite.security_policy();
    let needs_asym_encryption = cipher_suite.needs_asym_encryption();

    let receiver_x509 = X509::from_der(&receiver_certificate)
       .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
    let encryption_key= receiver_x509.public_key().unwrap();
    let encryption_key_size: usize = encryption_key.size();
    let (cipher_text_size, padding_size, min_footer_size) =
       if needs_asym_encryption {
           let plain_text_block_size = calculate_plain_text_block_size(security_policy, encryption_key_size)?;
           let cipher_text_bloc_size = encryption_key_size;
           let min_footer_size: usize = if encryption_key_size > 2048 {2} else {1};
           let plain_text_size = request.len() + min_footer_size;
           let padding_size = plain_text_size % plain_text_block_size;
           let block_count = if padding_size == 0 {
               plain_text_size / plain_text_block_size
           } else {
               (plain_text_size / plain_text_block_size) + 1
           };
           let cipher_text_size = (block_count * cipher_text_bloc_size) + signature.len();

           (cipher_text_size, padding_size, min_footer_size)
       } else {
           let plain_text_size = request.len() + signature.len();
           (plain_text_size, 0, 0)
       };

    // collect encrypted data in a buffer, starting with the security header in plain text
    let security_header = AsymmetricSecurityHeader {
        security_policy_uri: UAString::from(security_policy.to_uri()),
        sender_certificate: ByteString{value: Some(sender_certificate.clone()) },
        receiver_certificate_thumbprint: receiver_x509.thumbprint().as_byte_string()
    };
    let mut buffer= vec![0u8; cipher_text_size];
    CodecP::encode(&security_header, &mut buffer);

    let mut data = Vec::from(request.clone());
    // Add padding in the Message Footer:
    if needs_asym_encryption {
        let padding_byte= (padding_size & 0xff) as u8;
        for _ in 0..padding_size+1 {
            data.push(padding_byte);
        }
        if min_footer_size > 1 {
            data.push((padding_size >> 8) as u8);
        }
        data.extend_from_slice(&signature);

        // Encrypt data into buffer
        let encrypted_size = security_policy.asymmetric_encrypt(
            &encryption_key, &data, &mut buffer)
            .map_err( |_| {FnError::Crypto("Error during signing".to_string())})?;
        // Validate encrypted size is right
        if encrypted_size != cipher_text_size {
            panic!(
                "Encrypted block size {} is not the same as calculated cipher text size {}",
                encrypted_size, cipher_text_size
            );
        }
    } else {
        buffer.extend_from_slice(&request);
        buffer.extend_from_slice(&signature);
     }
    Ok(buffer)
}

pub fn fn_asym_decrypt(
    data: &Vec<u8>,
    private_key: &Vec<u8>
) -> Result<Vec<u8>, FnError> {

    // Read asymmetric security header:
    let mut rd = Reader::init(data);
    let mut security_header = AsymmetricSecurityHeader::none();
    CodecP::read(&mut security_header, &mut rd)
    .map_err( |_| {FnError::Crypto("Error reading asymmetric security header before decryption".to_string())})?;
    let security_policy = SecurityPolicy::from_uri(security_header.security_policy_uri.as_ref());

    // decrypt payload:
    let encrypted_range = security_header.byte_len() .. data.len();
    let encrypted_size= encrypted_range.len();
    let mut decrypted_tmp = vec![0u8; encrypted_size];
    let decryption_key: PKey<Private> = openssl::pkey::PKey::private_key_from_pkcs8(private_key)
    .map(|value|{PrivateKey {value}})
    .map_err( |_| {FnError::Crypto("Error reading private key in PKCS #8 format with DER encoding".to_string())})?;
    let _decrypted_size = security_policy.asymmetric_decrypt(&decryption_key,
        &data[encrypted_range],
         &mut decrypted_tmp)
    .map_err( |_| {FnError::Crypto("Error during asymmetric decryption".to_string())})?;
    Ok(decrypted_tmp)
}

pub fn fn_get_channel_token(
    _open_response: &Vec<u8>
) -> Result<u32, FnError> {
    Err(FnError::Unknown("Unimplemented".to_string()))
}

pub fn fn_get_server_nonce(
    _open_response: &Vec<u8>
) -> Result<Vec<u8>, FnError> {
    Err(FnError::Unknown("Unimplemented".to_string()))
}

pub fn fn_client_mac_key(
    cipher_suite: &CipherSuite,
    client_nonce: &Vec<u8>,
    server_nonce: &Vec<u8>
) -> Result<Vec<u8>, FnError> {

    let security_policy = cipher_suite.security_policy();
    // cf. SecureChannel: Our end's set of keys: Symmetric Signing Key, Decrypt Key, IV
    let client_keys = security_policy.make_secure_channel_keys(
        &server_nonce, &client_nonce);
    Ok(client_keys.0)
}

pub fn fn_make_symmetric_header (
    message_type: &ChunkType,
    secure_channel_id: &u32,
    cipher_suite: &CipherSuite,
    security_header: &Vec<u8>,
    request: &Vec<u8>,
) -> Result<Vec<u8>, FnError> {
    let security_policy = cipher_suite.security_policy();
    let mac_length: usize = security_policy.symmetric_signature_size();
    let message_size = (MESSAGE_CHUNK_HEADER_SIZE +
        security_header.len() + request.len() + mac_length) as u32;
    let header = MessageChunkHeader{
        message_type: message_type.to_message_chunk_type(),
        is_final: message_type.to_is_final(),
        message_size,
        secure_channel_id: *secure_channel_id
    };
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(&header, &mut buffer);
    Ok(buffer)
}

pub fn fn_data_to_mac(
    cipher_suite: &CipherSuite,
    chunk_header: &MessageChunkHeader,
    channel_token_id: &u32,
    request: &Vec<u8>,
) -> Result<Vec<u8>, FnError> {
    let security_policy = cipher_suite.security_policy();
    let mac_length: usize = security_policy.symmetric_signature_size();

    // collect data to sign in a buffer:
    let mut header = chunk_header.clone();
    header.message_size = (header.byte_len() + 4 + request.len() + mac_length) as u32;
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(&header, &mut buffer);
    CodecP::encode(channel_token_id, &mut buffer);
    buffer.extend_from_slice(request);

    Ok(buffer)
}

pub fn fn_mac (
    cipher_suite: &CipherSuite,
    data: &Vec<u8>,
    mac_key: &Vec<u8>
) -> Result<Vec<u8>, FnError> {

    let security_policy = cipher_suite.security_policy();
    let mac_length: usize = security_policy.symmetric_signature_size();

    // compute Message Authentication Code:
    let mut mac = vec![0u8; mac_length];
    security_policy.symmetric_sign(mac_key, &data, &mut mac)
       .map_err( |_| {FnError::Crypto("Error during MAC computation".to_string())})?;
    Ok(mac)
}

pub fn fn_message (
    header: &MessageChunkHeader,
    body: &Vec<u8>,
) -> Result<MessageChunk, FnError> {
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(header, &mut buffer);
    buffer.extend_from_slice(body);
    Ok(MessageChunk {data: buffer})
}

pub fn fn_request_header (
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

pub fn fn_client_open (
    request_header: &RequestHeader,
    kind: &SecurityTokenRequestType,
    client_nonce: &Vec<u8>
) -> Result<Vec<u8>, FnError> {
    let request = OpenSecureChannelRequest {
        request_header: request_header.clone(),
        client_protocol_version: 0,
        request_type: *kind,
        security_mode: MessageSecurityMode::Sign,
        client_nonce: ByteString { value: Some(client_nonce.clone())},
        requested_lifetime: 0,
    };
    let mut buffer = vec![0u8; 20];
    CodecP::encode(&request, &mut buffer);
    Ok(buffer)

}

pub fn fn_client_close (
    request_header: &RequestHeader,
) -> Result<Vec<u8>, FnError> {
    let request = CloseSecureChannelRequest {
        request_header: request_header.clone(),
    };
    let mut buffer = vec![0u8; 20];
    CodecP::encode(&request, &mut buffer);
    Ok(buffer)

}