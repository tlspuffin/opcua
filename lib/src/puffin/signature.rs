use extractable_macro::Extractable;
use puffin::algebra::dynamic_function::FunctionAttributes;
use puffin::algebra::error::FnError;
use puffin::error::Error;
use puffin::protocol::{Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use puffin::{
    codec, define_signature, dummy_codec, dummy_extract_knowledge//, dummy_extract_knowledge_codec,
};

use crate::puffin::types::OpcuaProtocolTypes;
use crate::puffin::fn_constants::*;

/* -----------------------------------------------------------------------------
              TO REMOVE LATER
----------------------------------------------------------------------------- */

#[derive(Clone, Debug, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub struct MessageChunk {
    // msg_header: MessageHeader,
    //sec_header: SecurityHeader,
    payload: Vec<u8>,
}

dummy_extract_knowledge!(OpcuaProtocolTypes, u8);
dummy_codec!(OpcuaProtocolTypes, MessageChunk);

pub fn fn_message_chunk() -> Result<MessageChunk, FnError> {
    Ok(MessageChunk {
        // msg_header: MessageHeader {
        //     msg_type: *(b"OPN"),
        //     // is_final: b'F',
        //     // msg_size: 0x15,
        //     sc_id: fn_new_channel_id().unwrap(),
        // },
        payload: vec![0x01, 0x02, 0x03, 0x04],
    })
}

/* -----------------------------------------------------------------------------
             END TO REMOVE LATER
----------------------------------------------------------------------------- */

define_signature! {
    OPCUA_SIGNATURE<OpcuaProtocolTypes>,
    // constants
    //fn_true
    //fn_false
    fn_none
    fn_sign
    fn_encrypt
    //fn_seq_0
    //fn_open_channel_request
    fn_message_chunk
}
