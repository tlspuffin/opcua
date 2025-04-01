use crate::prelude::DecodingOptions;
use crate::prelude::BinaryEncoder;
use extractable_macro::Extractable;
use puffin::algebra::dynamic_function::FunctionAttributes;
use puffin::algebra::error::FnError;
use puffin::error::Error;
use puffin::protocol::{Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use puffin::{
    codec, define_signature, dummy_codec, dummy_extract_knowledge, dummy_extract_knowledge_codec,
};
use crate::prelude::ByteString;
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::{MessageSecurityMode, OpenSecureChannelRequest, SecurityTokenRequestType};

crate::impl_codec_p!(OpenSecureChannelRequest, MessageSecurityMode, ByteString);

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
pub fn fn_OpenSecureChannelRequest(security_mode: &MessageSecurityMode, client_nonce: &ByteString) -> Result<OpenSecureChannelRequest, FnError> {
    Ok(OpenSecureChannelRequest {
        request_header: Default::default(),
        client_protocol_version: 0,
        request_type: SecurityTokenRequestType::Issue,
        security_mode: security_mode.clone(),
        client_nonce: client_nonce.clone(),
        requested_lifetime: 0,
    })
}

/* -----------------------------------------------------------------------------
             END TO REMOVE LATER
----------------------------------------------------------------------------- */

define_signature! {
    OPCUA_SIGNATURE<OpcuaProtocolTypes>,
    // constants
    // fn_true
    // fn_false
    // fn_seq_0
    //fn_open_channel_request
    fn_OpenSecureChannelRequest
}
