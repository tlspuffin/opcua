// The OPC UA protocol types, adapted to puffin.

use puffin::agent::{AgentDescriptor, AgentName, ProtocolDescriptorConfig};
use puffin::algebra::signature::Signature;
use puffin::{atom_extract_knowledge, dummy_extract_knowledge};
use puffin::algebra::AnyMatcher;
use puffin::error::Error;
use puffin::trace::{Knowledge, Source};

use puffin::protocol::{Extractable, ProtocolTypes};

use serde_derive::{Deserialize, Serialize};

use crate::puffin::signature::fn_impl::CipherSuite;
use crate::puffin::signature::OPCUA_SIGNATURE;

// PUT configuration descriptor:

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub enum AgentType {
    Client,
    Server,
    User,
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub enum OpcuaVersion {
    V1_4, // only RSA
    V1_5, // with ECC
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub enum SessionSecurity {
    /// No Application Authentication, i.e. the server is configured
    /// to accept all client certificates and only use them for message security.
    SNoAA, // No client Application Authentication
    SSec,  // Normal Session Security
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub enum UserToken {
    Anonymous,
    Password,
    Certificate,
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct OpcuaDescriptorConfig {
    pub version: OpcuaVersion,
    pub kind: AgentType,
    pub security_policy: CipherSuite,
    pub check: SessionSecurity, /// Default: SSec.
    pub utoken: UserToken,
}

impl Default for OpcuaDescriptorConfig {
    fn default() -> Self {
        Self {
            version: OpcuaVersion::V1_4,
            kind: AgentType::Server,
            security_policy: CipherSuite::Basic256Sha256,
            check: SessionSecurity::SSec,
            utoken: UserToken::Certificate,
        }
    }
}

impl OpcuaDescriptorConfig {

    pub fn new_client(
        name: AgentName,
    ) -> AgentDescriptor<Self> {
        AgentDescriptor {
            name,
            protocol_config: OpcuaDescriptorConfig {
                kind: AgentType::Client,
                ..Self::default()
            }
        }
    }

    pub fn new_server(
        name: AgentName,
    ) -> AgentDescriptor<Self> {
        AgentDescriptor {
            name,
            protocol_config: Self::default()
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
    type Matcher = AnyMatcher; // OpcuaQueryMatcher;
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
dummy_extract_knowledge!(OpcuaProtocolTypes, bool);
atom_extract_knowledge!(OpcuaProtocolTypes, u8);
atom_extract_knowledge!(OpcuaProtocolTypes, u16);
atom_extract_knowledge!(OpcuaProtocolTypes, u32);
//atom_extract_knowledge!(OpcuaProtocolTypes, f64);
