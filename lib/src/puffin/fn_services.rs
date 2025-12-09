use puffin::algebra::error::FnError;

use crate::crypto::{SecurityPolicy, X509, legacy_password_encrypt};
use crate::puffin::messages::ServiceMessage;
use crate::puffin::signature::{CipherSuite};
use crate::types::{ActivateSessionRequest, AnonymousIdentityToken, ApplicationDescription, ApplicationType, BinaryEncoder, ByteString, CreateSessionRequest, ExtensionObject, LocalizedText, ObjectId, RequestHeader, SignatureData, UAString, UserNameIdentityToken, X509IdentityToken};

pub fn fn_create_request (
    request_header: &RequestHeader,
    endpoint_url: &UAString,
    client_nonce: &ByteString,
    client_certificate: &ByteString
) -> Result<ServiceMessage, FnError> {
    let request = CreateSessionRequest {
        request_header: request_header.clone(),
        client_description: ApplicationDescription {
            application_uri: UAString::from("urn:Puffin"),
            product_uri: UAString::from("urn:Puffin"),
            application_name: LocalizedText::from("Puffin"),
            application_type: ApplicationType::Client,
            gateway_server_uri: UAString::null(),
            discovery_profile_uri: UAString::null(),
            discovery_urls: None,
        },
        server_uri:  UAString::null(),
        endpoint_url: endpoint_url.clone(),
        session_name: UAString::null(),
        client_nonce: client_nonce.clone(),
        client_certificate: client_certificate.clone(),
        requested_session_timeout: 1200000.0,
        max_response_message_size: 0,
    };
    Ok(ServiceMessage::CreateSessionRequest(request))
}

pub fn fn_signature_data (
    certificate: &ByteString,
    nonce: &ByteString,
) -> Result<Vec<u8>, FnError> {
    let mut buffer= Vec::<u8>::with_capacity(certificate.byte_len() + nonce.byte_len());
    if let Some(cert) = certificate.clone().value {
        buffer.extend(cert);
    };
    if let Some(n) = nonce.clone().value {
        buffer.extend(n);
    };
    Ok(buffer)
}

// taken from client/session/services/session.rs

fn create_signature (
    security_policy: SecurityPolicy,
    signature: &Vec<u8>,
) -> SignatureData {
    if signature.len() == 0 || security_policy == SecurityPolicy::None {
        SignatureData {
            algorithm: UAString::null(),
            signature: ByteString::null()
        }
    } else {
        SignatureData {
            algorithm: UAString::from(security_policy.asymmetric_signature_algorithm()),
            signature: ByteString::from(&signature)
        }
    }
}

pub fn fn_activate_request(
    request_header: &RequestHeader,
    cipher_suite: &CipherSuite,
    client_signature: &Vec<u8>,
    user_identity_token: &ExtensionObject,
    user_token_signature: &Vec<u8>
) -> Result<ServiceMessage, FnError> {
    let security_policy = cipher_suite.security_policy();
    let request = ActivateSessionRequest {
        request_header: request_header.clone(),
        client_signature: create_signature(
            security_policy, client_signature),
        client_software_certificates: None,
        locale_ids: Some(vec![UAString::from("en-US")]),
        user_identity_token: user_identity_token.clone(),
        user_token_signature: create_signature(
            security_policy, user_token_signature)
    };
    Ok(ServiceMessage::ActivateSessionRequest(request))
}

pub fn fn_anonymous(
    policy_id: &UAString
) -> Result<ExtensionObject, FnError> {
    let identity_token = AnonymousIdentityToken {
        policy_id: policy_id.clone()
    };
    let identity_token = ExtensionObject::from_encodable(
        ObjectId::AnonymousIdentityToken_Encoding_DefaultBinary,
        &identity_token,
    );
    Ok(identity_token)
}

// fn rsa_password_encrypt(
//     password: &str,
//     server_nonce: &[u8],
//     server_cert: &X509,
//     padding: RsaPadding
// ) -> Result<ByteString, FnError> {

//     // This should create the RsaEncryptedSecret structure in the ByteString
//     let buffer = Vec::<u8>::new();
//     Ok(ByteString::null())
// }

// pub fn fn_user_pwd(
//     policy_id: &UAString,
//     cipher_suite: &CipherSuite,
//     user_name: &UAString,
//     password: &UAString,
//     server_cert: &ByteString,
//     server_nonce: &ByteString,
// ) -> Result<ExtensionObject, FnError> {

//     // taken from crypto/user_identity.rs: make_user_name_identity_token
//     let security_policy: SecurityPolicy = cipher_suite.security_policy();
//     let pass: &str = if password.is_empty() {
//         return Err(FnError::Crypto("No password for user name authentication".to_string()))
//     } else {
//         password.as_ref()
//     };
//     let (encrypted_password, encryption_algorithm) = match security_policy {
//         // The fuzzer can send a password in clear even if it is forgotten in mode Sign!
//         SecurityPolicy::None => (ByteString::from(pass.as_bytes()), UAString::null()),
//         security_policy => {
//             // Create a password which is encrypted using the user token policy
//             if server_cert.is_null_or_empty() {
//                 (ByteString::from(pass.as_bytes()), UAString::null())
//             } else {
//                 let cert = X509::from_der(server_cert.as_ref())
//                    .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
//                 let encrypted_password = rsa_password_encrypt(
//                     pass,
//                     server_nonce.as_ref(),
//                     &cert,
//                     security_policy.asymmetric_encryption_padding(),
//                 ).map_err ( |e| {return FnError::Crypto(format!("Error in legacy password encrypt: {:?}", e))})?;
//                 let encryption_algorithm =
//                     UAString::from(security_policy.asymmetric_encryption_algorithm());
//                 (encrypted_password, encryption_algorithm)
//             }
//         }
//     };
//     let identity_token = UserNameIdentityToken {
//         policy_id: policy_id.clone(),
//         user_name: user_name.clone(),
//         password: encrypted_password,
//         encryption_algorithm,
//     };
//     let identity_token = ExtensionObject::from_encodable(
//         ObjectId::UserNameIdentityToken_Encoding_DefaultBinary,
//         &identity_token,
//     );
//     Ok(identity_token)
// }

pub fn fn_legacy_user_pwd(
    policy_id: &UAString,
    cipher_suite: &CipherSuite,
    user_name: &UAString,
    password: &UAString,
    server_cert: &ByteString,
    server_nonce: &ByteString,
) -> Result<ExtensionObject, FnError> {

    // taken from crypto/user_identity.rs: make_user_name_identity_token
    let security_policy: SecurityPolicy = cipher_suite.security_policy();
    let pass: &str = if password.is_empty() {
        return Err(FnError::Crypto("No password for user name authentication".to_string()))
    } else {
        password.as_ref()
    };
    let (encrypted_password, encryption_algorithm) = match security_policy {
        // The fuzzer can send a password in clear even if it is forgotten in mode Sign!
        SecurityPolicy::None => (ByteString::from(pass.as_bytes()), UAString::null()),
        security_policy => {
            // Create a password which is encrypted using the user token policy
            if server_cert.is_null_or_empty() {
                (ByteString::from(pass.as_bytes()), UAString::null())
            } else {
                let cert = X509::from_der(server_cert.as_ref())
                   .map_err( |_| {FnError::Crypto("Error reading certificate X509 with DER encoding".to_string())})?;
                let encrypted_password = legacy_password_encrypt(
                    pass,
                    server_nonce.as_ref(),
                    &cert,
                    security_policy.asymmetric_encryption_padding(),
                ).map_err ( |e| {return FnError::Crypto(format!("Error in legacy password encrypt: {:?}", e))})?;
                let encryption_algorithm =
                    UAString::from(security_policy.asymmetric_encryption_algorithm());
                (encrypted_password, encryption_algorithm)
            }
        }
    };
    let identity_token = UserNameIdentityToken {
        policy_id: policy_id.clone(),
        user_name: user_name.clone(),
        password: encrypted_password,
        encryption_algorithm,
    };
    let identity_token = ExtensionObject::from_encodable(
        ObjectId::UserNameIdentityToken_Encoding_DefaultBinary,
        &identity_token,
    );
    Ok(identity_token)
}

pub fn fn_user_cert(
    policy_id: &UAString,
    user_cert: &ByteString,
) -> Result<ExtensionObject, FnError> {
    let identity_token = X509IdentityToken {
        policy_id: policy_id.clone(),
        certificate_data: user_cert.clone(),
    };
    let identity_token = ExtensionObject::from_encodable(
        ObjectId::X509IdentityToken_Encoding_DefaultBinary,
        &identity_token,
    );
    Ok(identity_token)
}