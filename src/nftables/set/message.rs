// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, ErrorContext as _, Parseable};

use crate::nftables::set::SetAttribute;
use crate::nlas::parse_all_nlas;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SetMessage {
    pub attributes: Vec<SetAttribute>,
}

impl Parseable<[u8]> for SetMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let attributes = parse_all_nlas(buf, |buf| SetAttribute::parse(&buf))
            .context("failed to parse set message nla")?;
        Ok(Self { attributes })
    }
}
