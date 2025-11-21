use puffin::algebra::error::FnError;

use crate::puffin::messages::ServiceMessage;
use crate::types::{ApplicationDescription, ApplicationType, ByteString, CreateSessionRequest, DiagnosticBits, ExtensionObject, LocalizedText, NodeId, RequestHeader, UAString, UtcTime};

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