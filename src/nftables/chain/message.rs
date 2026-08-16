// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, ErrorContext as _, Parseable};

use crate::nftables::chain::ChainAttribute;
use crate::nlas::parse_all_nlas;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ChainMessage {
    pub attributes: Vec<ChainAttribute>,
}

impl Parseable<[u8]> for ChainMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let attributes = parse_all_nlas(buf, |buf| ChainAttribute::parse(&buf))
            .context("failed to parse chain message nla")?;
        Ok(Self { attributes })
    }
}
