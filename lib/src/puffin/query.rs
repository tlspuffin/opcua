use puffin::algebra::Matcher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Hash, Eq, PartialEq)]
pub enum OpcuaQueryMatcher {
    CreateSessionResponse,
}

impl Matcher for OpcuaQueryMatcher {
    fn matches(&self, matcher: &Self) -> bool {
        match matcher {
            OpcuaQueryMatcher::CreateSessionResponse => matches!(self, OpcuaQueryMatcher::CreateSessionResponse),
            _ => false

        }
    }

    fn specificity(&self) -> u32 {
        0
    }
}
