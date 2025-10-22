// symbolic functions for the UA Secure Channel sub-protocol

use openssl::pkey::{Private};

use puffin::algebra::error::FnError;
use puffin::codec::{CodecP, Reader};
use puffin::error::Error;

use crate::crypto::{KeySize, PKey, PrivateKey, RsaPadding, SecurityPolicy, X509, security_policy};
use crate::prelude::{AsymmetricSecurityHeader, MessageChunk, MessageChunkHeader, MessageChunkType, MessageIsFinalType, SequenceHeader};
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
) -> Result<AsymmetricSecurityHeader, FnError> {
    Ok(AsymmetricSecurityHeader {
        security_policy_uri: UAString::from(CipherSuite::security_policy(*cipher_suite).to_uri()),
        sender_certificate: ByteString{value: Some(sender_certificate.clone()) },
        receiver_certificate_thumbprint: ByteString{value: Some(receiver_certificate_thumbprint.clone())}
    })
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

pub fn fn_data_to_encrypt (
    sequence: &SequenceHeader,
    request: &Vec<u8>,
    signature: &Vec<u8>
) -> Result<Vec<u8>, FnError> {
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(sequence, &mut buffer);
    buffer.extend_from_slice(request);
    buffer.extend_from_slice(signature);
    Ok(buffer)
}

// helper function copied from crate::comms::secure_channel
// cf. fn calculate_cipher_text_size(&self, data_size: usize, padding: RsaPadding) -> usize
fn calculate_cipher_text_size (
    security_policy: SecurityPolicy,
    data_size: usize,
    encryption_key_size: usize
) -> Result<usize, FnError> {
    let padding: RsaPadding = security_policy.asymmetric_encryption_padding();
    //cf. fn plain_text_block_size(&self, padding: RsaPadding) -> usize
    let plain_text_block_size = match padding {
        RsaPadding::Pkcs1 => encryption_key_size - 11,
        RsaPadding::OaepSha1 => encryption_key_size - 42,
        RsaPadding::OaepSha256 => encryption_key_size - 66,
        _ => return Err(FnError::Crypto("Unsupported padding".to_string())),
    };
    let block_count = if data_size % plain_text_block_size == 0 {
        data_size / plain_text_block_size
    } else {
        (data_size / plain_text_block_size) + 1
    };
    let cipher_text_bloc_size = encryption_key_size;
    Ok(block_count * cipher_text_bloc_size)
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

    let security_policy = CipherSuite::security_policy(*cipher_suite);
    let signature_length: usize = {
        let x509 = X509::from_der(sender_certificate)
           .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
        x509.public_key().unwrap().size()
    };
    let receiver_x509 = X509::from_der(&receiver_certificate)
       .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
    let encryption_key_size: usize = receiver_x509.public_key().unwrap().size();

    let cipher_text_size = calculate_cipher_text_size(
        security_policy, data.len() + signature_length, encryption_key_size)?;

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

    // compute signature:
    let signing_key: PKey<Private> = openssl::pkey::PKey::private_key_from_pkcs8(private_key)
       .map(|value|{PrivateKey {value}})
       .map_err( |_| {FnError::Crypto("Error reading private key in PKCS #8 format with DER encoding".to_string())})?;

    let mut signature = vec![0u8; signature_length];
    security_policy.asymmetric_sign(&signing_key, &buffer, &mut signature)
       .map_err( |_| {FnError::Crypto("Error during signing".to_string())})?;
    Ok(signature)
}


pub fn fn_asym_encrypt (
    cipher_suite: &CipherSuite,
    sender_certificate: &Vec<u8>,
    receiver_certificate: &Vec<u8>,
    data: &Vec<u8>
) -> Result<Vec<u8>, FnError> {

    let security_policy = CipherSuite::security_policy(*cipher_suite);

    let receiver_x509 = X509::from_der(&receiver_certificate)
       .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
    let encryption_key= receiver_x509.public_key().unwrap();
    let encryption_key_size: usize = encryption_key.size();

    let cipher_text_size = calculate_cipher_text_size(
        security_policy, data.len(), encryption_key_size)?;

    // collect encrypted data in a buffer starting with the security header
    let security_header = AsymmetricSecurityHeader {
        security_policy_uri: UAString::from(security_policy.to_uri()),
        sender_certificate: ByteString{value: Some(sender_certificate.clone()) },
        receiver_certificate_thumbprint: receiver_x509.thumbprint().as_byte_string()
    };
    let mut buffer= vec![0u8; cipher_text_size];
    CodecP::encode(&security_header, &mut buffer);

    // Encrypt data into buffer
    let encrypted_size = security_policy.asymmetric_encrypt(
        &encryption_key, data, &mut buffer)
        .map_err( |_| {FnError::Crypto("Error during signing".to_string())})?;
    // Validate encrypted size is right
    if encrypted_size != cipher_text_size {
        panic!(
            "Encrypted block size {} is not the same as calculated cipher text size {}",
            encrypted_size, cipher_text_size
        );
    }
    Ok(buffer)
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
