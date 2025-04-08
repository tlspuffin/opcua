/// Implements CodecP trait for structs that already implement BinaryEncoder
///
/// # Usage
///
/// ```ignore
/// use extractable_macro::Extractable;
/// use crate::puffin::types::OpcuaProtocolTypes;
///
/// #[derive(Debug, Copy, Clone, PartialEq, Extractable)]
/// #[extractable(OpcuaProtocolTypes)]
/// pub struct MyStruct { }
///
/// impl BinaryEncoder<MyStruct> for MyStruct { }
///
/// crate::impl_codec_p!(MyStruct);
/// ```


#[macro_export]
macro_rules! impl_codec_p {
    ($($t:ty),*) => {
        $(impl puffin::codec::CodecP for $t {
        fn encode(&self, bytes: &mut Vec<u8>){
            let _ = BinaryEncoder::encode(self, bytes);
        }
        fn read(&mut self, r: &mut puffin::codec::Reader) -> core::result::Result<(), puffin::error::Error> {
            Ok(<$t as BinaryEncoder<$t>>::decode(r, &DecodingOptions::default())
                .map_err(|e| puffin::error::Error::Codec(
                    format!("CodecP error in opcua-mapper for type {}: {e}",  std::any::type_name::<$t>())))
                .map(|o| {
                    *self = o;
                })?)
        }
        })*
    };
}