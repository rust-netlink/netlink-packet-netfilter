// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, ErrorContext as _, Parseable};

use crate::nftables::gen::GenAttribute;
use crate::nlas::parse_all_nlas;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GenMessage {
    pub attributes: Vec<GenAttribute>,
}

impl Parseable<[u8]> for GenMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let attributes = parse_all_nlas(buf, |buf| GenAttribute::parse(&buf))
            .context("failed to parse gen message nla")?;
        Ok(Self { attributes })
    }
}
