// symbolic functions for the UA Secure Channel sub-protocol

use openssl::pkey::{Private};

use puffin::algebra::error::FnError;
use puffin::codec::{CodecP, Reader};
use puffin::error::Error;

use crate::crypto::{KeySize, PKey, PrivateKey, RsaPadding, SecurityPolicy, X509};
use crate::prelude::{AsymmetricSecurityHeader, MessageChunkHeader, SequenceHeader};
use crate::puffin::messages::{ChunkType, DecryptedBody, EncryptedBody, Message, MessageBody, ServiceMessage};
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::encoding::BinaryEncoder;
use crate::types::{ByteString, DiagnosticBits, ExtensionObject, MessageSecurityMode,
    NodeId, RequestHeader, SecurityTokenRequestType, UAString, UtcTime};
use crate::types::service_types::{CloseSecureChannelRequest, OpenSecureChannelRequest};

use extractable_macro::Extractable;


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
    None = 0,
    Aes128Sha256RsaOaep = 1,
    Basic256Sha256 = 2,
    Aes256Sha256RsaPss = 3,
    Basic128Rsa15 = 4,
    Basic256 = 5
}

impl CipherSuite {
    fn security_policy(self) -> SecurityPolicy {
        match self {
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
            SecurityPolicy::Unknown => CipherSuite::None,
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
        bytes.push(*self as u8);
    }

    fn read(&mut self, rd: &mut Reader) -> Result<(), Error> {
        let mut value = 0u8;
        if let Ok(()) = CodecP::read(&mut value, rd){
            if value > 5 {
                return Err(Error::Codec("Cannot read a CipherSuite".to_string()))
            }
            *self = match value {
                0 => CipherSuite::None,
                1 => CipherSuite::Aes128Sha256RsaOaep,
                2 => CipherSuite::Basic256Sha256,
                3 => CipherSuite::Aes256Sha256RsaPss,
                4 => CipherSuite::Basic128Rsa15,
                5 => CipherSuite::Basic256,
                _ => { return Err(Error::Codec("Cannot read a CipherSuite".to_string())); }
            };
            Ok(())
        } else {
            Err(Error::Codec("Cannot read a CipherSuite".to_string()))
        }
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
    request: &ServiceMessage
 ) -> Result<Vec<u8>, FnError> {
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(sequence, &mut buffer);
    CodecP::encode(request, &mut buffer);
    Ok(buffer)
 }

pub fn fn_body(
    channel_token_id: &u32,
    sequence: &SequenceHeader,
    service: &ServiceMessage,
    mac: &Vec<u8>
 ) -> Result<MessageBody, FnError> {
    Ok(MessageBody{
        channel_token_id: *channel_token_id,
        sequence_header: sequence.clone(),
        request: service.clone(),
        mac: mac.clone()
    })
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

// The following functions are a complete revrite of SecureChannel::asymmetric_sign_and_encrypt()
// in crate::core::comms::secure_channel::SecureChannel.

pub fn fn_open_header(
    chunk_header: &MessageChunkHeader,
    cipher_suite: &CipherSuite,
    sender_certificate: &ByteString,
    receiver_certificate: &ByteString,
    data: &Vec<u8>
) -> Result<MessageChunkHeader, FnError> {

    let security_policy = cipher_suite.security_policy();
    let needs_asym_encryption = cipher_suite.needs_asym_encryption();
    let signature_size: usize = {
        if !sender_certificate.is_null_or_empty() {
            let x509 = X509::from_der(sender_certificate.as_ref())
               .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
            x509.public_key().unwrap().size() }
        else { 0 }
    };
    let (receiver_certificate_thumbprint, encryption_key_size) =
        if needs_asym_encryption {
            let receiver_x509 = X509::from_der(receiver_certificate.as_ref())
                .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
            (receiver_x509.thumbprint().as_byte_string(), receiver_x509.public_key().unwrap().size())
        } else {
            (ByteString::null(), 0)
        };
    let (cipher_text_size, padding_size, min_footer_size) =
        if needs_asym_encryption {
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

    let security_header = AsymmetricSecurityHeader {
        security_policy_uri: UAString::from(security_policy.to_uri()),
        sender_certificate: sender_certificate.clone(),
        receiver_certificate_thumbprint
    };
    let mut header = chunk_header.clone();
    header.message_size = (header.byte_len() + security_header.byte_len() + cipher_text_size + padding_size + min_footer_size) as u32;
    Ok(header)
}


pub fn fn_data_to_sign (
    header: &MessageChunkHeader,
    cipher_suite: &CipherSuite,
    sender_certificate: &ByteString,
    receiver_certificate: &ByteString,
    data: &Vec<u8>,
) -> Result<Vec<u8>, FnError> {
    let security_policy = cipher_suite.security_policy();
    let needs_asym_encryption = cipher_suite.needs_asym_encryption();
    let (receiver_certificate_thumbprint, encryption_key_size) =
        if security_policy != SecurityPolicy::None {
            let receiver_x509 = X509::from_der(receiver_certificate.as_ref())
                .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
            (receiver_x509.thumbprint().as_byte_string(), receiver_x509.public_key().unwrap().size())
        } else {
            (ByteString::null(), 0)
        };
    let (padding_size, min_footer_size) =
        if needs_asym_encryption {
            let plain_text_block_size = calculate_plain_text_block_size(security_policy, encryption_key_size)?;
            let min_footer_size: usize = if encryption_key_size > 2048 {2} else {1};
            let plain_text_size = data.len() + min_footer_size;
            let padding_size = plain_text_size % plain_text_block_size;
            (padding_size, min_footer_size)
        } else { (0, 0) };
    // collect data to sign in a buffer:
    let security_header = AsymmetricSecurityHeader {
        security_policy_uri: UAString::from(security_policy.to_uri()),
        sender_certificate: sender_certificate.clone(),
        receiver_certificate_thumbprint
    };
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(header, &mut buffer);
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
    Ok(buffer)
}


pub fn fn_sign(
    data: &Vec<u8>,
    cipher_suite: &CipherSuite,
    sender_certificate: &ByteString,
    private_key: &Vec<u8>
) -> Result<Vec<u8>, FnError> {
    let security_policy = cipher_suite.security_policy();
    if security_policy == SecurityPolicy::None {
        return Err(FnError::Crypto("Cannot sign with SecurityPolicy::None".to_string()))
    }
    let signature_size: usize = {
        let x509 = X509::from_der(sender_certificate.as_ref())
           .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
        x509.public_key().unwrap().size()
    };
    let signing_key: PKey<Private> = openssl::pkey::PKey::private_key_from_pkcs8(private_key)
        .map(|value|{PrivateKey {value}})
        .map_err( |_| {FnError::Crypto("Error reading private key in PKCS #8 format with DER encoding".to_string())})?;
    let mut signature = vec![0u8; signature_size];
    security_policy.asymmetric_sign(&signing_key, data, &mut signature)
        .map_err( |_| {FnError::Crypto("Error during signing".to_string())})?;
    Ok(signature)
}


pub fn fn_data_to_encrypt (
    cipher_suite: &CipherSuite,
    receiver_certificate: &ByteString,
    request: &Vec<u8>,
    signature: &Vec<u8>
) -> Result<Vec<u8>, FnError> {

    let security_policy = cipher_suite.security_policy();
    let needs_asym_encryption = cipher_suite.needs_asym_encryption();

    let (padding_size, min_footer_size) =
        if needs_asym_encryption {
            let receiver_x509 = X509::from_der(receiver_certificate.as_ref())
                .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
            let encryption_key_size: usize = receiver_x509.public_key().unwrap().size();
            let plain_text_block_size = calculate_plain_text_block_size(security_policy, encryption_key_size)?;
            let min_footer_size: usize = if encryption_key_size > 2048 {2} else {1};
            let plain_text_size = request.len() + min_footer_size;
            let padding_size = plain_text_size % plain_text_block_size;
            (padding_size, min_footer_size)
        } else { (0, 0) };

    let mut buffer= Vec::<u8>::new();
    if needs_asym_encryption {
        buffer.extend_from_slice(&request);
        // Add padding in the Message Footer:
        let padding_byte= (padding_size & 0xff) as u8;
        for _ in 0..padding_size+1 {
            buffer.push(padding_byte);
        }
        if min_footer_size == 2 {
            buffer.push((padding_size >> 8) as u8);
        }
    } else {
        buffer.extend_from_slice(&request);
    }
    buffer.extend_from_slice(&signature);
    Ok(buffer)
}


pub fn fn_asym_encrypt (
    cipher_suite: &CipherSuite,
    sender_certificate: &ByteString,
    receiver_certificate: &ByteString,
    data: &Vec<u8>,
) -> Result<EncryptedBody, FnError> {

    let security_policy = cipher_suite.security_policy();
    let needs_asym_encryption = cipher_suite.needs_asym_encryption();
    let mut buffer= Vec::<u8>::new();

    if needs_asym_encryption {
        let receiver_x509 = X509::from_der(receiver_certificate.as_ref())
        .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
        let encryption_key= receiver_x509.public_key().unwrap();
        let encryption_key_size: usize = encryption_key.size();
        let cipher_text_size= {
            let plain_text_block_size = calculate_plain_text_block_size(security_policy, encryption_key_size)?;
            let cipher_text_bloc_size = encryption_key_size;
            let plain_text_size = data.len();
            let padding_size = plain_text_size % plain_text_block_size;
            let block_count = if padding_size == 0 {
                plain_text_size / plain_text_block_size
            } else {
                (plain_text_size / plain_text_block_size) + 1
            };
            block_count * cipher_text_bloc_size
        };
        // collect encrypted data in a buffer, starting with the security header in plain text
        let security_header = AsymmetricSecurityHeader {
            security_policy_uri: UAString::from(security_policy.to_uri()),
            sender_certificate: sender_certificate.clone(),
            receiver_certificate_thumbprint: receiver_x509.thumbprint().as_byte_string()
        };
        CodecP::encode(&security_header, &mut buffer);

        let mut cipher_text= vec![0u8; cipher_text_size];
        // Encrypt data into buffer:
        let encrypted_size = security_policy.asymmetric_encrypt(
            &encryption_key, &data, &mut cipher_text)
            .map_err( |_| {FnError::Crypto("Error during signing".to_string())})?;
        // Validate encrypted size is right:
        if encrypted_size != cipher_text_size {
            return Err(FnError::Crypto(
                format!("Encrypted block size {} is not the same as calculated cipher text size {}",
                encrypted_size, cipher_text_size)
            ))
        }
        buffer.extend_from_slice(&cipher_text);
    }
    else { // No asymmetric encryption.
        let receiver_certificate_thumbprint =
            if security_policy != SecurityPolicy::None {
                let receiver_x509 = X509::from_der(receiver_certificate.as_ref())
                    .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
                receiver_x509.thumbprint().as_byte_string()
            } else {
                ByteString::null()
            };
        let security_header = AsymmetricSecurityHeader {
            security_policy_uri: UAString::from(security_policy.to_uri()),
            sender_certificate: sender_certificate.clone(),
            receiver_certificate_thumbprint
        };
        CodecP::encode(&security_header, &mut buffer);
        buffer.extend_from_slice(&data);
     };
    Ok(EncryptedBody{cipher_text: buffer})
}


pub fn fn_asym_decrypt(
    body: &EncryptedBody,
    private_key: &Vec<u8>
) -> Result<Vec<u8>, FnError> {

    // Read asymmetric security header:
    let mut rd = Reader::init(&body.cipher_text);
    let mut security_header = AsymmetricSecurityHeader::none();
    CodecP::read(&mut security_header, &mut rd)
        .map_err( |_| {FnError::Crypto("Error reading asymmetric security header before decryption".to_string())})?;
    let security_policy = SecurityPolicy::from_uri(security_header.security_policy_uri.as_ref());

    match security_policy {
        SecurityPolicy::None => Ok(rd.rest().to_vec()),
        SecurityPolicy::Unknown => Err(FnError::Crypto("Cannot decrypt with no or an unknown security policy".to_string())),
        _ => {
            // decrypt payload:
            let encrypted_range = security_header.byte_len() .. body.cipher_text.len();
            let encrypted_size= encrypted_range.len();
            let mut decrypted_tmp = vec![0u8; encrypted_size];
            let decryption_key: PKey<Private> = openssl::pkey::PKey::private_key_from_pkcs8(private_key)
                .map(|value|{PrivateKey {value}})
                .map_err( |_| {FnError::Crypto("Error reading private key in PKCS #8 format with DER encoding".to_string())})?;
            let decrypted_size = security_policy.asymmetric_decrypt(&decryption_key,
                &&body.cipher_text[encrypted_range],
                &mut decrypted_tmp)
                .map_err( |_| {FnError::Crypto("Error during asymmetric decryption".to_string())})?;

           Ok(decrypted_tmp[0..decrypted_size].to_vec())
        }
    }
}


pub fn fn_decrypted_body(
    body: &Vec<u8>,
    private_key: &Vec<u8>
) -> Result<DecryptedBody, FnError> {

    let mut rd = Reader::init(body);
    let mut decrypted_body = DecryptedBody::default();
    decrypted_body.sequence_header.read(&mut rd)
        .map_err(|e| FnError::Codec(format!("fn_decrypted_body cannot read sequence header: {e}")))?;
    decrypted_body.request.read(& mut rd)
        .map_err(|e| FnError::Codec(format!("fn_decrypted_body cannot read message: {e}")))?;

    // suppressed padding:
    if private_key.len() > 0 {
        // get decryption key:
        let decryption_key: PKey<Private> = openssl::pkey::PKey::private_key_from_pkcs8(private_key)
        .map(|value|{PrivateKey {value}})
        .map_err( |_| {FnError::Crypto("Error reading private key in PKCS #8 format with DER encoding".to_string())})?;

        let mut padding_byte: u8 = 0;
        padding_byte.read(&mut rd)
            .map_err(|e| FnError::Crypto(format!("fn_decrypted_body cannot read padding: {e}")))?;
        let mut byte = padding_byte;

        if decryption_key.size() <= 2048 {
            for _ in 0..padding_byte {
                byte.read(&mut rd).map_err(|e| FnError::Codec(format!("fn_decrypted_body, error in padding: {e}")))?;
                if byte != padding_byte {
                    return Err(FnError::Crypto(format!("fn_decrypted_body, error in padding, found {}, expected {}",
                            byte, padding_byte)))};
            }
        } else {
            let mut padding_size: u32 = 0;
            byte.read(&mut rd).map_err(|e| FnError::Codec(format!("fn_decrypted_body, error in padding: {e}")))?;
            while byte == padding_byte {
                padding_size += 1;
                byte.read(&mut rd).map_err(|e| FnError::Codec(format!("fn_decrypted_body, error in padding: {e}")))?;
            }
            if padding_size != ((byte as u32) << 8) + (padding_byte as u32) {
                return Err(FnError::Crypto("fn_decrypted_body, error in padding".to_string()))
            }
        };
    };
    decrypted_body.signature.read(&mut rd)
        .map_err(|e| FnError::Codec(format!("fn_decrypted_body cannot read signature: {e}")))?;
    Ok(decrypted_body)
}

pub fn fn_get_channel_token(
    open_response: &DecryptedBody
) -> Result<u32, FnError> {
    if let ServiceMessage::OpenSecureChannelResponse(response) = &open_response.request {
        Ok(response.security_token.token_id)
    } else {
        Err(FnError::Unknown("Cannot get channel token id".to_string()))
    }
}

pub fn fn_get_server_nonce(
    open_response: &DecryptedBody
) -> Result<ByteString, FnError> {
    if let ServiceMessage::OpenSecureChannelResponse(response) = &open_response.request {
        Ok(response.server_nonce.clone())
    } else {
        Err(FnError::Unknown("Cannot get channel nonce".to_string()))
    }
}

pub fn fn_client_mac_key(
    cipher_suite: &CipherSuite,
    client_nonce: &ByteString,
    server_nonce: &ByteString
) -> Result<Vec<u8>, FnError> {
    let security_policy = cipher_suite.security_policy();
    if security_policy == SecurityPolicy::None {
        return Err(FnError::Crypto("Cannot compute MAC for SecurityPolicy::None".to_string()))
    };
    let nonce_length = security_policy.secure_channel_nonce_length();
    if (client_nonce.as_ref().len() != nonce_length) || (server_nonce.as_ref().len() != nonce_length) {
        return Err(FnError::Crypto("Cannot compute symmetric keys: nonce size is incorrect".to_string()))
    }
    // cf. SecureChannel: Our end's set of keys: Symmetric Signing Key, Decrypt Key, IV
    let client_keys = security_policy.make_secure_channel_keys(
        server_nonce.as_ref(), client_nonce.as_ref());
    Ok(client_keys.0)
}

pub fn fn_mac_header (
    cipher_suite: &CipherSuite,
    message_header: &MessageChunkHeader,
    request: &Vec<u8>
) -> Result<MessageChunkHeader, FnError> {
    let security_policy = cipher_suite.security_policy();
    let mac_length: usize = security_policy.symmetric_signature_size();
    let mut header = message_header.clone();
    header.message_size = (header.byte_len() + 4 + request.len() + mac_length) as u32;
    Ok(header)
}

pub fn fn_data_to_mac(
    chunk_header: &MessageChunkHeader,
    channel_token_id: &u32,
    request: &Vec<u8>
) -> Result<Vec<u8>, FnError> {
    let mut buffer= Vec::<u8>::new();
    CodecP::encode(chunk_header, &mut buffer);
    CodecP::encode(channel_token_id, &mut buffer);
    buffer.extend_from_slice(request);
    Ok(buffer)
}

pub fn fn_mac (
    data: &Vec<u8>,
    cipher_suite: &CipherSuite,
    mac_key: &Vec<u8>
) -> Result<Vec<u8>, FnError> {

    let security_policy = cipher_suite.security_policy();
    if security_policy == SecurityPolicy::None {
        return Err(FnError::Crypto("Cannot compute MAC for SecurityPolicy::None".to_string()))
    };
    if mac_key.len() != security_policy.derived_signature_key_size() {
        return Err(FnError::Crypto("Cannot compute MAC: mac key size is incorrect".to_string()))
    };
    let mac_length: usize = security_policy.symmetric_signature_size();
    let mut mac = vec![0u8; mac_length];
    security_policy.symmetric_sign(mac_key, &data, &mut mac)
       .map_err( |_| {FnError::Crypto("Error during MAC computation".to_string())})?;
    Ok(mac)
}

pub fn fn_open_message (
    header: &MessageChunkHeader,
    body: &EncryptedBody,
) -> Result<Message, FnError> { 
    Ok(Message::Open (header.clone(), body.clone()))
}

pub fn fn_message (
    header: &MessageChunkHeader,
    body: &MessageBody,
) -> Result<Message, FnError> {
    Ok(Message::Chunk (header.clone(), body.clone()))
}

pub fn fn_request_header (
    sa_token: &NodeId,
    request_id: &u32,
) -> Result<RequestHeader, FnError> {
    Ok(RequestHeader{
        authentication_token: sa_token.clone(),
        timestamp: UtcTime::default(), // UtcTime::now(),
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
    security_mode: &MessageSecurityMode,
    client_nonce: &ByteString
) -> Result<ServiceMessage, FnError> {
    let request = OpenSecureChannelRequest {
        request_header: request_header.clone(),
        client_protocol_version: 0,
        request_type: *kind,
        security_mode: *security_mode,
        client_nonce: client_nonce.clone(),
        requested_lifetime: 300000,
    };
    Ok(ServiceMessage::OpenSecureChannelRequest(request))
}

pub fn fn_client_close (
    request_header: &RequestHeader,
) -> Result<ServiceMessage, FnError> {
    let request = CloseSecureChannelRequest {
        request_header: request_header.clone(),
    };
    Ok(ServiceMessage::CloseSecureChannelRequest(request))
}