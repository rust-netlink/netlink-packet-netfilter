// SPDX-License-Identifier: MIT

use derive_more::IsVariant;

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    DecodeError, Parseable,
};

use crate::{
    constants::{CTA_TUPLE_IP, CTA_TUPLE_PROTO},
    nfconntrack::nlas::{IpTuple, ProtoTuple},
};

#[derive(Clone, Debug, PartialEq, Eq, IsVariant)]
pub enum ConnectionMember {
    IpTuple(IpTuple),
    ProtoTuple(ProtoTuple),
    Other(DefaultNla),
}

impl Nla for ConnectionMember {
    fn value_len(&self) -> usize {
        match self {
            ConnectionMember::IpTuple(attr) => attr.value_len(),
            ConnectionMember::ProtoTuple(attr) => attr.value_len(),
            ConnectionMember::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ConnectionMember::IpTuple(attr) => attr.kind(),
            ConnectionMember::ProtoTuple(attr) => attr.kind(),
            ConnectionMember::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ConnectionMember::IpTuple(attr) => attr.emit_value(buffer),
            ConnectionMember::ProtoTuple(attr) => attr.emit_value(buffer),
            ConnectionMember::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ConnectionMember
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = NlaBuffer::new(buf.value());
        let nla = match kind {
            CTA_TUPLE_IP => {
                ConnectionMember::IpTuple(IpTuple::parse(&payload)?)
            }
            CTA_TUPLE_PROTO => {
                ConnectionMember::ProtoTuple(ProtoTuple::parse(&payload)?)
            }
            _ => ConnectionMember::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
