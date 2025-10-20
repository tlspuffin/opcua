// UA SC sub-protocol:

use std::io::{Read, Write};

use puffin::algebra::error::FnError;

use crate::core::comms::tcp_types::{
    CHUNK_MESSAGE, OPEN_SECURE_CHANNEL_MESSAGE, CLOSE_SECURE_CHANNEL_MESSAGE,
    CHUNK_FINAL, CHUNK_INTERMEDIATE, CHUNK_FINAL_ERROR};
use crate::prelude::{DecodingOptions, EncodingResult, MessageChunk};
use crate::puffin::types::OpcuaProtocolTypes;
use crate::types::encoding::BinaryEncoder;
use crate::types::{StatusCode, process_decode_io_result, process_encode_io_result, status_code, write_u8};

use extractable_macro::Extractable;

/// Size in bytes of an OPC UA secure channel message header
const UASC_HEADER_LEN: usize = 3*4;


#[derive(Clone, Debug, PartialEq)]
pub enum ChunkType {
    Open,
    Intermediate,
    Final,
    FinalError,
    Close
}

#[derive(Debug, Clone, PartialEq, Extractable)]
#[extractable(OpcuaProtocolTypes)]
pub struct ChunkHeader{
    #[extractable_ignore]
    chunk_type: ChunkType,
    #[extractable_ignore]
    message_size: u32,
    secure_channel_id: u32,
}


pub fn fn_chunk_header (
    chunk_type: &ChunkType,
    secure_channel_id: &u32
) -> Result<ChunkHeader, FnError> {
    Ok(ChunkHeader{
        chunk_type: chunk_type.clone(),
        secure_channel_id: *secure_channel_id,
        message_size: 0
    })
}

impl BinaryEncoder<ChunkHeader> for ChunkHeader {
    fn byte_len(&self) -> usize {
        UASC_HEADER_LEN
    }

    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        let result = match self.chunk_type {
            ChunkType::Open =>
               stream.write(OPEN_SECURE_CHANNEL_MESSAGE),
            ChunkType::Intermediate | ChunkType::Final | ChunkType::FinalError =>
               stream.write(CHUNK_MESSAGE),
            ChunkType::Close =>
               stream.write(CLOSE_SECURE_CHANNEL_MESSAGE),

        };
        size += process_encode_io_result(result)?;
        size += match self.chunk_type {
            ChunkType::Open | ChunkType::Final | ChunkType::Close =>
               write_u8(stream, CHUNK_FINAL)?,
            ChunkType::Intermediate =>
               write_u8(stream, CHUNK_INTERMEDIATE)?,
            ChunkType::FinalError =>
               write_u8(stream, CHUNK_FINAL_ERROR)?,
        };
        size += self.secure_channel_id.encode(stream)?;
        size += self.message_size.encode(stream)?;
        Ok(size)
    }

    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<ChunkHeader> {

        let mut header = [0u8; 4];
        let result = stream.read_exact(&mut header);
        process_decode_io_result(result)?;

        let chunk_type = match &header[0..3] {
            OPEN_SECURE_CHANNEL_MESSAGE => ChunkType::Open,
            CLOSE_SECURE_CHANNEL_MESSAGE => ChunkType::Close,
            CHUNK_MESSAGE =>
                match header[3] {
                    CHUNK_INTERMEDIATE => ChunkType::Intermediate,
                    CHUNK_FINAL => ChunkType::Final,
                    CHUNK_FINAL_ERROR => ChunkType::FinalError,
                    _ => return Err(StatusCode::BadDecodingError)
                },
            _ => return Err(StatusCode::BadDecodingError)

        };
        let message_size = u32::decode(stream, decoding_options)?;
        let secure_channel_id = u32::decode(stream, decoding_options)?;

        Ok(ChunkHeader {
            chunk_type,
            message_size,
            secure_channel_id
        })
    }
}
crate::impl_codec_p!(ChunkHeader);


pub fn fn_chunk (
    header: &ChunkHeader,
    //security: &Vec<u8>,
    //body: &Vec<u8>,
) -> Result<MessageChunk, FnError> {
    let mut buffer:Vec<u8> = Vec::<u8>::new();
    let result = header.encode(&mut buffer);
    if let Err(_) = result {
        return Err(FnError::Codec("Error while encoding chunk header".to_string()))
    }
    //buffer.extend_from_slice(security);
    //buffer.extend_from_slice(body);
    Ok(MessageChunk {data: buffer})
}