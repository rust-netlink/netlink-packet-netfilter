// SPDX-License-Identifier: MIT

use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NLA_F_NESTED},
    Emitable, Parseable,
};

use crate::constants::{
    CTA_ID, CTA_MARK, CTA_PROTOINFO, CTA_STATUS, CTA_TIMEOUT, CTA_TUPLE_ORIG,
    CTA_TUPLE_REPLY, CTA_USE,
};

use super::{
    ip_tuple::TupleNla, protocol_info::ProtocolInfo, status::ConnectionStatus,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FlowNla {
    Orig(Vec<TupleNla>),
    Reply(Vec<TupleNla>),
    Status(ConnectionStatus),
    ProtocolInfo(ProtocolInfo),
    Timeout(u32),
    Mark(u32),
    Use(u32),
    Id(u32),
    Other(DefaultNla),
}

impl Nla for FlowNla {
    fn value_len(&self) -> usize {
        match self {
            FlowNla::Orig(attrs) => {
                attrs.iter().fold(0, |l, attr| l + attr.buffer_len())
            }
            FlowNla::Reply(attrs) => {
                attrs.iter().fold(0, |l, attr| l + attr.buffer_len())
            }
            FlowNla::Status(attr) => attr.value_len(),
            FlowNla::ProtocolInfo(attr) => attr.value_len(),
            FlowNla::Timeout(_) => 4,
            FlowNla::Mark(_) => 4,
            FlowNla::Use(_) => 4,
            FlowNla::Id(_) => 4,
            FlowNla::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            FlowNla::Orig(_) => CTA_TUPLE_ORIG | NLA_F_NESTED,
            FlowNla::Reply(_) => CTA_TUPLE_REPLY | NLA_F_NESTED,
            FlowNla::Status(_) => CTA_STATUS,
            FlowNla::ProtocolInfo(_) => CTA_PROTOINFO | NLA_F_NESTED,
            FlowNla::Timeout(_) => CTA_TIMEOUT,
            FlowNla::Mark(_) => CTA_MARK,
            FlowNla::Use(_) => CTA_USE,
            FlowNla::Id(_) => CTA_ID,
            FlowNla::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            FlowNla::Orig(attrs) => {
                attrs.as_slice().emit(buffer);
            }
            FlowNla::Reply(attrs) => {
                attrs.as_slice().emit(buffer);
            }
            FlowNla::Status(status) => status.emit_value(buffer),
            FlowNla::ProtocolInfo(info) => info.emit_value(buffer),
            FlowNla::Timeout(val) => BigEndian::write_u32(buffer, *val),
            FlowNla::Mark(val) => BigEndian::write_u32(buffer, *val),
            FlowNla::Use(val) => BigEndian::write_u32(buffer, *val),
            FlowNla::Id(val) => BigEndian::write_u32(buffer, *val),
            FlowNla::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for FlowNla
{
    fn parse(
        buf: &NlaBuffer<&'buffer T>,
    ) -> Result<Self, netlink_packet_utils::DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_TUPLE_ORIG => FlowNla::Orig({
                let b = NlaBuffer::new(payload);
                let ip = TupleNla::parse(&b)?;
                let b = NlaBuffer::new(&payload[ip.buffer_len()..]);
                let proto = TupleNla::parse(&b)?;
                vec![ip, proto]
            }),
            CTA_TUPLE_REPLY => FlowNla::Reply({
                let b = NlaBuffer::new(payload);
                let ip = TupleNla::parse(&b)?;
                let b = NlaBuffer::new(&payload[ip.buffer_len()..]);
                let proto = TupleNla::parse(&b)?;
                vec![ip, proto]
            }),
            CTA_STATUS => FlowNla::Status({
                ConnectionStatus::from(BigEndian::read_u32(payload))
            }),
            CTA_PROTOINFO => {
                FlowNla::ProtocolInfo(ProtocolInfo::parse_from_bytes(payload)?)
            }
            CTA_TIMEOUT => FlowNla::Timeout(BigEndian::read_u32(payload)),
            CTA_MARK => FlowNla::Mark(BigEndian::read_u32(payload)),
            CTA_USE => FlowNla::Use(BigEndian::read_u32(payload)),
            CTA_ID => FlowNla::Id(BigEndian::read_u32(payload)),
            _ => FlowNla::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
