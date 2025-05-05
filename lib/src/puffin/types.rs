// The OPC UA protocol types, adapted to puffin.

use puffin::agent::{AgentDescriptor, AgentName, ProtocolDescriptorConfig};
use puffin::algebra::signature::Signature;
use puffin::{atom_extract_knowledge, dummy_extract_knowledge};
use puffin::error::Error;
use puffin::trace::{Knowledge, Source};

use puffin::protocol::{
    //EvaluatedTerm,
    Extractable, //OpaqueProtocolMessage, OpaqueProtocolMessageFlight,
    //ProtocolBehavior, ProtocolMessage, ProtocolMessageDeframer, ProtocolMessageFlight,
    ProtocolTypes,
};
//use puffin::put::PutDescriptor;
//use puffin::trace::{Knowledge, Source, Trace};
//use puffin::{codec, dummy_codec, dummy_extract_knowledge, dummy_extract_knowledge_codec};
use serde::{Deserialize, Serialize};

use crate::puffin::query::OpcuaQueryMatcher;
use crate::puffin::signature::OPCUA_SIGNATURE;

// PUT configuration descriptor:

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum AgentType {
    Client,
    Server,
    User,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum OpcuaVersion {
    V1_4, // only RSA
    V1_5, // with ECC
}

// Can't use the MessageSecurityMode because it requires the Eq trait.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum ChannelMode {
    None,    // unsecure channel
    Sign,    // sign-only
    Encrypt, // sign and encrypt
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum SessionSecurity {
    /// No Application Authentication, i.e. the server is configured
    /// to accept all client certificates and only use them for message security.
    SNoAA,
    SSec, // Client Application Authentication
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum UserToken {
    Anonymous,
    Password,
    Certificate,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct OpcuaDescriptorConfig {
    pub version: OpcuaVersion,
    pub kind: AgentType,
    pub security_policy: String, /// ciphers
    pub mode: ChannelMode,
    pub check: SessionSecurity, /// Default: SSec.
    pub utoken: UserToken,
}

impl Default for OpcuaDescriptorConfig {
    fn default() -> Self {
        Self {
            version: OpcuaVersion::V1_4,
            kind: AgentType::Server,
            security_policy: String::from("Basic256Sha256"),
            mode: ChannelMode::Sign,
            check: SessionSecurity::SSec,
            utoken: UserToken::Certificate,
        }
    }
}

impl OpcuaDescriptorConfig {

    pub fn new_client(
        name: AgentName,
        mode: ChannelMode,
        utoken: UserToken,
    ) -> AgentDescriptor<Self> {
        AgentDescriptor {
            name,
            protocol_config: OpcuaDescriptorConfig {
                kind: AgentType::Client,
                mode,
                utoken,
                ..Self::default()
            }
        }
    }

    pub fn new_server(
        name: AgentName,
        mode: ChannelMode,
        utoken: UserToken,
    ) -> AgentDescriptor<Self> {
        AgentDescriptor {
            name,
            protocol_config: OpcuaDescriptorConfig {
                kind: AgentType::Server,
                mode,
                utoken,
                ..Self::default()
            }
        }
    }
}

impl ProtocolDescriptorConfig for OpcuaDescriptorConfig {
    fn is_reusable_with(&self, _other: &Self) -> bool {
        false
    }
}



// Protocol Types:

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct OpcuaProtocolTypes;

impl ProtocolTypes for OpcuaProtocolTypes {
    type Matcher = OpcuaQueryMatcher;
    type PUTConfig = OpcuaDescriptorConfig;

    fn signature() -> &'static Signature<Self> {
        &OPCUA_SIGNATURE
    }
}

impl std::fmt::Display for OpcuaProtocolTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

// For Basic Types:
atom_extract_knowledge!(OpcuaProtocolTypes, bool);
dummy_extract_knowledge!(OpcuaProtocolTypes, u8);
atom_extract_knowledge!(OpcuaProtocolTypes, u16);
atom_extract_knowledge!(OpcuaProtocolTypes, u32);
//atom_extract_knowledge!(OpcuaProtocolTypes, f64);