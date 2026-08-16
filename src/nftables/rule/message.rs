// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, ErrorContext as _, Parseable};

use crate::nftables::rule::RuleAttribute;
use crate::nlas::parse_all_nlas;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RuleMessage {
    pub attributes: Vec<RuleAttribute>,
}

impl Parseable<[u8]> for RuleMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let attributes = parse_all_nlas(buf, |buf| RuleAttribute::parse(&buf))
            .context("failed to parse rule message nla")?;
        Ok(Self { attributes })
    }
}
