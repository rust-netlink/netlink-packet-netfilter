// SPDX-License-Identifier: MIT

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

const IPV4_LEN: usize = 4;
const IPV6_LEN: usize = 16;

// Helper function needed for implementing the Nla trait
pub fn emit_ip(addr: &IpAddr, buf: &mut [u8]) {
    match addr {
        IpAddr::V4(ip) => {
            buf[..IPV4_LEN].copy_from_slice(ip.octets().as_slice());
        }
        IpAddr::V6(ip) => {
            buf[..IPV6_LEN].copy_from_slice(ip.octets().as_slice());
        }
    }
}

impl Nla for IPTuple {
    fn value_len(&self) -> usize {
        match self {
            IPTuple::SourceAddress(attr) => match *attr {
                IpAddr::V4(_) => IPV4_LEN,
                IpAddr::V6(_) => IPV6_LEN,
            },
            IPTuple::DestinationAddress(attr) => match *attr {
                IpAddr::V4(_) => IPV4_LEN,
                IpAddr::V6(_) => IPV6_LEN,
            },
            IPTuple::Other(attr) => attr.value_len(),
        }
    }

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

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            IPTuple::SourceAddress(attr) => emit_ip(attr, buffer),
            IPTuple::DestinationAddress(attr) => emit_ip(attr, buffer),
            IPTuple::Other(attr) => attr.emit_value(buffer),
        }
    }
}
impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for IPTuple
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
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
