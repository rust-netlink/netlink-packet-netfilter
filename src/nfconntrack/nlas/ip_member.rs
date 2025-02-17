// SPDX-License-Identifier: MIT

use derive_more::IsVariant;
use std::net::IpAddr;

use netlink_packet_utils::{
    nla::{Nla, NlaBuffer},
    parsers::parse_ip,
    DecodeError, Parseable,
};

use crate::constants::{
    CTA_IP_V4_DST, CTA_IP_V4_SRC, CTA_IP_V6_DST, CTA_IP_V6_SRC,
};

#[derive(Clone, Debug, PartialEq, Eq, IsVariant)]
pub enum IpMember {
    Src(IpAddr),
    Dst(IpAddr),
}

impl Nla for IpMember {
    fn value_len(&self) -> usize {
        match self {
            IpMember::Src(addr) | IpMember::Dst(addr) => match addr {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 16,
            },
        }
    }

    fn kind(&self) -> u16 {
        match self {
            IpMember::Src(addr) => match addr {
                IpAddr::V4(_) => CTA_IP_V4_SRC,
                IpAddr::V6(_) => CTA_IP_V6_SRC,
            },
            IpMember::Dst(addr) => match addr {
                IpAddr::V4(_) => CTA_IP_V4_DST,
                IpAddr::V6(_) => CTA_IP_V6_DST,
            },
        }
    }

    fn emit_value(&self, _buffer: &mut [u8]) {
        todo!()
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for IpMember
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_IP_V4_SRC => IpMember::Src(parse_ip(payload)?),
            CTA_IP_V4_DST => IpMember::Dst(parse_ip(payload)?),
            CTA_IP_V6_SRC => IpMember::Src(parse_ip(payload)?),
            CTA_IP_V6_DST => IpMember::Dst(parse_ip(payload)?),
            _ => return Err(format!("Unhandled IP type: {}", kind).into()),
        };
        Ok(nla)
    }
}
