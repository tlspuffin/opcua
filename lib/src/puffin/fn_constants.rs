// All result types must implement Extractable<OpcuaProtocolTypes>, and hence CodecP.

use puffin::algebra::error::FnError;

pub fn fn_true() -> Result<bool, FnError> {
    Ok(true)
}
pub fn fn_false() -> Result<bool, FnError> {
    Ok(false)
}

pub fn fn_seq_0() -> Result<u32, FnError> {
    Ok(0)
}

use crate::types::MessageSecurityMode;

pub fn fn_none() -> Result<MessageSecurityMode, FnError> {
    Ok(MessageSecurityMode::None)
}
pub fn fn_sign() -> Result<MessageSecurityMode, FnError> {
    Ok(MessageSecurityMode::Sign)
}
pub fn fn_encrypt() -> Result<MessageSecurityMode, FnError> {
    Ok(MessageSecurityMode::SignAndEncrypt)
}
