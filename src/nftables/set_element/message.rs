// SPDX-License-Identifier: MIT

use netlink_packet_core::{DecodeError, ErrorContext as _, Parseable};

use crate::nftables::set_element::list::SetElementList;
use crate::nlas::parse_all_nlas;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SetElementMessage {
    // Contrary to the [kernel header doc] SetElementMessages are build out of
    // `nft_set_elem_list_attributes` instead of `nft_set_elem_attributes`
    //
    // [kernel doc]: include/uapi/linux/netfilter/nf_tables.h
    pub attributes: Vec<SetElementList>,
}

impl Parseable<[u8]> for SetElementMessage {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        let attributes = parse_all_nlas(buf, |buf| SetElementList::parse(&buf))
            .context("failed to parse set element message nla")?;
        Ok(Self { attributes })
    }
}
