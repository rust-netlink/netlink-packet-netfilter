// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u16_be, parse_u16_be, parse_u8, DecodeError, DefaultNla, ErrorContext,
    Nla, NlaBuffer, Parseable,
};

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_IGMP: u8 = 2;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_DCCP: u8 = 33;
pub const IPPROTO_GRE: u8 = 47;
pub const IPPROTO_IPV6_ICMP: u8 = 58;
pub const IPPROTO_IPIP: u8 = 94;
pub const IPPROTO_L2TP: u8 = 115;
pub const IPPROTO_SCTP: u8 = 132;
pub const IPPROTO_UDPLITE: u8 = 136;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Protocol {
    Icmp,
    Igmp,
    Tcp,
    Udp,
    Dccp,
    Gre,
    Ipv6Icmp,
    IpIp,
    L2tp,
    Sctp,
    UdpLite,
    Other(u8),
}

impl From<Protocol> for u8 {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Icmp => IPPROTO_ICMP,
            Protocol::Igmp => IPPROTO_IGMP,
            Protocol::Tcp => IPPROTO_TCP,
            Protocol::Udp => IPPROTO_UDP,
            Protocol::Dccp => IPPROTO_DCCP,
            Protocol::Gre => IPPROTO_GRE,
            Protocol::Ipv6Icmp => IPPROTO_IPV6_ICMP,
            Protocol::IpIp => IPPROTO_IPIP,
            Protocol::L2tp => IPPROTO_L2TP,
            Protocol::Sctp => IPPROTO_SCTP,
            Protocol::UdpLite => IPPROTO_UDPLITE,
            Protocol::Other(p) => p,
        }
    }
}

impl From<u8> for Protocol {
    fn from(protocol_num: u8) -> Self {
        match protocol_num {
            IPPROTO_ICMP => Protocol::Icmp,
            IPPROTO_IGMP => Protocol::Igmp,
            IPPROTO_TCP => Protocol::Tcp,
            IPPROTO_UDP => Protocol::Udp,
            IPPROTO_DCCP => Protocol::Dccp,
            IPPROTO_GRE => Protocol::Gre,
            IPPROTO_IPV6_ICMP => Protocol::Ipv6Icmp,
            IPPROTO_IPIP => Protocol::IpIp,
            IPPROTO_L2TP => Protocol::L2tp,
            IPPROTO_SCTP => Protocol::Sctp,
            IPPROTO_UDPLITE => Protocol::UdpLite,
            _ => Protocol::Other(protocol_num),
        }
    }
}

const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtoTuple {
    Protocol(Protocol),
    SourcePort(u16),
    DestinationPort(u16),
    Other(DefaultNla),
}

impl Nla for ProtoTuple {
    fn value_len(&self) -> usize {
        match self {
            ProtoTuple::Protocol(_) => size_of::<u8>(),
            ProtoTuple::SourcePort(attr) => size_of_val(attr),
            ProtoTuple::DestinationPort(attr) => size_of_val(attr),
            ProtoTuple::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ProtoTuple::Protocol(_) => CTA_PROTO_NUM,
            ProtoTuple::SourcePort(_) => CTA_PROTO_SRC_PORT,
            ProtoTuple::DestinationPort(_) => CTA_PROTO_DST_PORT,
            ProtoTuple::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ProtoTuple::Protocol(attr) => buffer[0] = (*attr).into(),
            ProtoTuple::SourcePort(attr) => emit_u16_be(buffer, *attr).unwrap(),
            ProtoTuple::DestinationPort(attr) => {
                emit_u16_be(buffer, *attr).unwrap()
            }
            ProtoTuple::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ProtoTuple
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_PROTO_NUM => ProtoTuple::Protocol(
                parse_u8(payload)
                    .context("invalid CTA_PROTO_NUM value")?
                    .into(),
            ),
            CTA_PROTO_SRC_PORT => ProtoTuple::SourcePort(
                parse_u16_be(payload)
                    .context("invalid CTA_PROTO_SRC_PORT value")?,
            ),
            CTA_PROTO_DST_PORT => ProtoTuple::DestinationPort(
                parse_u16_be(payload)
                    .context("invalid CTA_PROTO_DST_PORT value")?,
            ),
            _ => ProtoTuple::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
