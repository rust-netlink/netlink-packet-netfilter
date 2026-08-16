// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, ErrorContext as _, Parseable};

use crate::nftables::table::TableAttribute;
use crate::nlas::parse_all_nlas;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TableMessage {
    pub attributes: Vec<TableAttribute>,
}

impl Parseable<[u8]> for TableMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let attributes = parse_all_nlas(buf, |buf| TableAttribute::parse(&buf))
            .context("failed to parse table message nla")?;
        Ok(Self { attributes })
    }
}
