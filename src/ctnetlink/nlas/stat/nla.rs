// SPDX-License-Identifier: MIT

use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    Parseable,
};

use crate::constants::{
    CTA_COUNTERS_ORIG, CTA_COUNTERS_REPLY, CTA_ID, CTA_MARK, CTA_NAT_DST,
    CTA_PROTOINFO, CTA_SEQ_ADJ_ORIG, CTA_SEQ_ADJ_REPLY, CTA_TUPLE_MASTER,
    CTA_TUPLE_ORIG, CTA_TUPLE_REPLY, CTA_USE,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StatNla {
    Orig(u32),
    Reply(u32),
    ProtocolInfo(u32),
    Mark(u32),
    CountersOrig(u32),
    CountersReply(u32),
    Use(u32),
    Id(u32),
    NATDst(u32),
    Master(u32),
    SeqAdjOrig(u32),
    SeqAdjReply(u32),
    Other(DefaultNla),
}

impl Nla for StatNla {
    fn value_len(&self) -> usize {
        match self {
            StatNla::Orig(_) => 4,
            StatNla::Reply(_) => 4,
            StatNla::ProtocolInfo(_) => 4,
            StatNla::Mark(_) => 4,
            StatNla::CountersOrig(_) => 4,
            StatNla::CountersReply(_) => 4,
            StatNla::Use(_) => 4,
            StatNla::Id(_) => 4,
            StatNla::NATDst(_) => 4,
            StatNla::Master(_) => 4,
            StatNla::SeqAdjOrig(_) => 4,
            StatNla::SeqAdjReply(_) => 4,
            StatNla::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            StatNla::Orig(_) => CTA_TUPLE_ORIG,
            StatNla::Reply(_) => CTA_TUPLE_REPLY,
            StatNla::ProtocolInfo(_) => CTA_PROTOINFO,
            StatNla::Mark(_) => CTA_MARK,
            StatNla::CountersOrig(_) => CTA_COUNTERS_ORIG,
            StatNla::CountersReply(_) => CTA_COUNTERS_REPLY,
            StatNla::Use(_) => CTA_USE,
            StatNla::Id(_) => CTA_ID,
            StatNla::NATDst(_) => CTA_NAT_DST,
            StatNla::Master(_) => CTA_TUPLE_MASTER,
            StatNla::SeqAdjOrig(_) => CTA_SEQ_ADJ_ORIG,
            StatNla::SeqAdjReply(_) => CTA_SEQ_ADJ_REPLY,
            StatNla::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            StatNla::Orig(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Reply(val) => BigEndian::write_u32(buffer, *val),
            StatNla::ProtocolInfo(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Mark(val) => BigEndian::write_u32(buffer, *val),
            StatNla::CountersOrig(val) => BigEndian::write_u32(buffer, *val),
            StatNla::CountersReply(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Use(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Id(val) => BigEndian::write_u32(buffer, *val),
            StatNla::NATDst(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Master(val) => BigEndian::write_u32(buffer, *val),
            StatNla::SeqAdjOrig(val) => BigEndian::write_u32(buffer, *val),
            StatNla::SeqAdjReply(val) => BigEndian::write_u32(buffer, *val),
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
            CTA_PROTOINFO => {
                StatNla::ProtocolInfo(BigEndian::read_u32(payload))
            }
            CTA_MARK => StatNla::Mark(BigEndian::read_u32(payload)),
            CTA_COUNTERS_ORIG => {
                StatNla::CountersOrig(BigEndian::read_u32(payload))
            }
            CTA_COUNTERS_REPLY => {
                StatNla::CountersReply(BigEndian::read_u32(payload))
            }
            CTA_USE => StatNla::Use(BigEndian::read_u32(payload)),
            CTA_ID => StatNla::Id(BigEndian::read_u32(payload)),
            CTA_NAT_DST => StatNla::NATDst(BigEndian::read_u32(payload)),
            CTA_TUPLE_MASTER => StatNla::Master(BigEndian::read_u32(payload)),
            CTA_SEQ_ADJ_ORIG => {
                StatNla::SeqAdjOrig(BigEndian::read_u32(payload))
            }
            CTA_SEQ_ADJ_REPLY => {
                StatNla::SeqAdjReply(BigEndian::read_u32(payload))
            }
            _ => StatNla::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
