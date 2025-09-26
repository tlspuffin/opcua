// All result types must implement Extractable<OpcuaProtocolTypes>, and hence CodecP.

use puffin::algebra::error::FnError;

use crate::core::comms::secure_channel::Role;
use crate::types::{Identifier, SecurityTokenRequestType, NodeId};

pub fn fn_true() -> Result<bool, FnError> {
    Ok(true)
}
pub fn fn_false() -> Result<bool, FnError> {
    Ok(false)
}

pub fn fn_seq_0() -> Result<u32, FnError> {
    Ok(0)
}

pub fn fn_issue() -> Result<SecurityTokenRequestType, FnError> {
    Ok(SecurityTokenRequestType::Issue)
}
pub fn fn_renew() -> Result<SecurityTokenRequestType, FnError> {
    Ok(SecurityTokenRequestType::Renew)
}

// pub fn fn_none() -> Result<MessageSecurityMode, FnError> {
//     Ok(MessageSecurityMode::None)
// }
// pub fn fn_sign() -> Result<MessageSecurityMode, FnError> {
//     Ok(MessageSecurityMode::Sign)
// }
// pub fn fn_encrypt() -> Result<MessageSecurityMode, FnError> {
//     Ok(MessageSecurityMode::SignAndEncrypt)
// }

pub fn fn_client() -> Result<Role, FnError> {
    Ok(Role::Client)
}

pub fn fn_server() -> Result<Role, FnError> {
    Ok(Role::Server)
}

pub fn fn_default_size() -> Result<u32, FnError> {
    Ok(32768) // 2^15
}
pub fn fn_size_8192() -> Result<u32, FnError> {
    Ok(8192) // Part 6 § 7.1.2.3 Table 66: Buffer size shall be at least 8192 bytes.
}

pub fn fn_bob_uri() -> Result<Vec<u8>, FnError> {
    Ok("opc.tcp://PenDuick:53530".as_bytes().to_vec())
}

pub fn fn_bob_endpoint() -> Result<Vec<u8>, FnError> {
    Ok("opc.tcp://PenDuick:53530/OPCUA/SimulationServer".as_bytes().to_vec())
}

/// Various constants:
// /!\ The SA Token is a NodeId!
pub fn fn_sa_token_zero() -> Result<NodeId, FnError> {
    Ok(NodeId {
        namespace: 0,
        identifier: Identifier::from(0)
    })
}



// ToDo:
// - add client and server certificates
// - security profiles

