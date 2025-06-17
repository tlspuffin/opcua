// All result types must implement Extractable<OpcuaProtocolTypes>, and hence CodecP.

use puffin::algebra::error::FnError;

use crate::core::comms::secure_channel::Role;
use crate::types::MessageSecurityMode;

pub fn fn_true() -> Result<bool, FnError> {
    Ok(true)
}
pub fn fn_false() -> Result<bool, FnError> {
    Ok(false)
}

pub fn fn_seq_0() -> Result<u32, FnError> {
    Ok(0)
}

pub fn fn_none() -> Result<MessageSecurityMode, FnError> {
    Ok(MessageSecurityMode::None)
}
pub fn fn_sign() -> Result<MessageSecurityMode, FnError> {
    Ok(MessageSecurityMode::Sign)
}
pub fn fn_encrypt() -> Result<MessageSecurityMode, FnError> {
    Ok(MessageSecurityMode::SignAndEncrypt)
}

pub fn fn_client() -> Result<Role, FnError> {
    Ok(Role::Client)
}

pub fn fn_server() -> Result<Role, FnError> {
    Ok(Role::Server)
}

pub fn fn_default_size() -> Result<u32, FnError> {
    // Part 6 § 7.1.2.3 Table 66: Buffer size shall be at least 8192 bytes.
    Ok(32768) // 2^15
}
// ToDo:
// - add client and server certificates
// - security profiles