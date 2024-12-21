// SPDX-License-Identifier: MIT

use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    Parseable,
};

use crate::constants::{CTA_TUPLE_ORIG, CTA_TUPLE_REPLY};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StatNla {
    Orig(u32),
    Reply(u32),
    Other(DefaultNla),
}

impl Nla for StatNla {
    fn value_len(&self) -> usize {
        match self {
            StatNla::Orig(_) => 4,
            StatNla::Reply(_) => 4,
            StatNla::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            StatNla::Orig(_) => CTA_TUPLE_ORIG,
            StatNla::Reply(_) => CTA_TUPLE_REPLY,
            StatNla::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            StatNla::Orig(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Reply(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for StatNla
{
    fn parse(
        buf: &NlaBuffer<&'buffer T>,
    ) -> Result<Self, netlink_packet_utils::DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_TUPLE_ORIG => StatNla::Orig(BigEndian::read_u32(payload)),
            CTA_TUPLE_REPLY => StatNla::Reply(BigEndian::read_u32(payload)),
            _ => StatNla::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
