use puffin::algebra::Matcher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Hash, Eq, PartialEq)]
pub enum OpcuaQueryMatcher {
    CreateSessionResponse,
    EnndpointSignMode,
    PolicyIdAnonymous,
    PolicyIdPassword,
    PolicyIdCertificate
}

impl Matcher for OpcuaQueryMatcher {
    fn matches(&self, matcher: &Self) -> bool {
        match matcher {
            OpcuaQueryMatcher::CreateSessionResponse => matches!(self, OpcuaQueryMatcher::CreateSessionResponse),
            OpcuaQueryMatcher::EnndpointSignMode => matches!(self, OpcuaQueryMatcher::EnndpointSignMode),
            OpcuaQueryMatcher::PolicyIdAnonymous => matches!(self, OpcuaQueryMatcher::PolicyIdAnonymous),
            OpcuaQueryMatcher::PolicyIdPassword => matches!(self, OpcuaQueryMatcher::PolicyIdPassword),
            OpcuaQueryMatcher::PolicyIdCertificate => matches!(self, OpcuaQueryMatcher::PolicyIdCertificate),
            _ => false

        }
    }

    fn specificity(&self) -> u32 {
        0
    }
}
