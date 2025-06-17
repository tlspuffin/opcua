use puffin::algebra::Matcher;
use serde::{Deserialize, Serialize};

/// [OpcuaQueryMatcher] contains OPC_UA-related typing information
/// This is currently a dummy implementation
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Hash, Eq, PartialEq)]
pub enum OpcuaQueryMatcher {
    Error,
    Open,
}

impl Matcher for OpcuaQueryMatcher {
    fn matches(&self, matcher: &OpcuaQueryMatcher) -> bool {
        match matcher {
            OpcuaQueryMatcher::Error => matches!(self, OpcuaQueryMatcher::Error),
            OpcuaQueryMatcher::Open => matches!(self, OpcuaQueryMatcher::Open),
        }
    }

    fn specificity(&self) -> u32 { 0 }
}