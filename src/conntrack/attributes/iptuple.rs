// SPDX-License-Identifier: MIT

use netlink_packet_core::{append_bytes, EncodeError};
use netlink_packet_core::{
    parse_ip, DecodeError, DefaultNla, ErrorContext, Nla, NlaBuffer, Parseable,
};
use std::net::IpAddr;

const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_DST: u16 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IPTuple {
    SourceAddress(IpAddr),
    DestinationAddress(IpAddr),
    Other(DefaultNla),
}

// Helper function needed for implementing the Nla trait
pub fn emit_ip(addr: &IpAddr, out: &mut Vec<u8>) {
    match addr {
        IpAddr::V4(ip) => {
            append_bytes(out, ip.octets().as_slice());
        }
        IpAddr::V6(ip) => {
            append_bytes(out, ip.octets().as_slice());
        }
    }
}

impl Nla for IPTuple {
    fn kind(&self) -> u16 {
        match self {
            IPTuple::SourceAddress(attr) => match *attr {
                IpAddr::V4(_) => CTA_IP_V4_SRC,
                IpAddr::V6(_) => CTA_IP_V6_SRC,
            },
            IPTuple::DestinationAddress(attr) => match *attr {
                IpAddr::V4(_) => CTA_IP_V4_DST,
                IpAddr::V6(_) => CTA_IP_V6_DST,
            },
            IPTuple::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            IPTuple::SourceAddress(attr) => emit_ip(attr, out),
            IPTuple::DestinationAddress(attr) => emit_ip(attr, out),
            IPTuple::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
}
impl<'buffer> Parseable<NlaBuffer<'buffer>> for IPTuple {
    fn parse(buf: &NlaBuffer<'buffer>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_IP_V4_SRC | CTA_IP_V6_SRC => Self::SourceAddress(
                parse_ip(payload).context("invalid SourceAddress value")?,
            ),
            CTA_IP_V4_DST | CTA_IP_V6_DST => Self::DestinationAddress(
                parse_ip(payload)
                    .context("invalid DestinationAddress value")?,
            ),
            _ => IPTuple::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
