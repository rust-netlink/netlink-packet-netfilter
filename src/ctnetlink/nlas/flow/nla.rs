// SPDX-License-Identifier: MIT

use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NLA_F_NESTED},
    Emitable, Parseable,
};

use super::{
    ip_tuple::TupleNla, protocol_info::ProtocolInfo, status::ConnectionStatus,
};

pub(super) const CTA_STATUS: u16 = 3;

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_PROTOINFO: u16 = 4;
const CTA_TIMEOUT: u16 = 7;
const CTA_MARK: u16 = 8;
const CTA_USE: u16 = 11;
const CTA_ID: u16 = 12;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FlowAttribute {
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

impl Nla for FlowAttribute {
    fn value_len(&self) -> usize {
        match self {
            FlowAttribute::Orig(attrs) => {
                attrs.iter().fold(0, |l, attr| l + attr.buffer_len())
            }
            FlowAttribute::Reply(attrs) => {
                attrs.iter().fold(0, |l, attr| l + attr.buffer_len())
            }
            FlowAttribute::Status(attr) => attr.value_len(),
            FlowAttribute::ProtocolInfo(attr) => attr.value_len(),
            FlowAttribute::Timeout(_) => 4,
            FlowAttribute::Mark(_) => 4,
            FlowAttribute::Use(_) => 4,
            FlowAttribute::Id(_) => 4,
            FlowAttribute::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            FlowAttribute::Orig(_) => CTA_TUPLE_ORIG | NLA_F_NESTED,
            FlowAttribute::Reply(_) => CTA_TUPLE_REPLY | NLA_F_NESTED,
            FlowAttribute::Status(_) => CTA_STATUS,
            FlowAttribute::ProtocolInfo(_) => CTA_PROTOINFO | NLA_F_NESTED,
            FlowAttribute::Timeout(_) => CTA_TIMEOUT,
            FlowAttribute::Mark(_) => CTA_MARK,
            FlowAttribute::Use(_) => CTA_USE,
            FlowAttribute::Id(_) => CTA_ID,
            FlowAttribute::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            FlowAttribute::Orig(attrs) => {
                attrs.as_slice().emit(buffer);
            }
            FlowAttribute::Reply(attrs) => {
                attrs.as_slice().emit(buffer);
            }
            FlowAttribute::Status(status) => status.emit_value(buffer),
            FlowAttribute::ProtocolInfo(info) => info.emit_value(buffer),
            FlowAttribute::Timeout(val) => BigEndian::write_u32(buffer, *val),
            FlowAttribute::Mark(val) => BigEndian::write_u32(buffer, *val),
            FlowAttribute::Use(val) => BigEndian::write_u32(buffer, *val),
            FlowAttribute::Id(val) => BigEndian::write_u32(buffer, *val),
            FlowAttribute::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for FlowAttribute
{
    fn parse(
        buf: &NlaBuffer<&'buffer T>,
    ) -> Result<Self, netlink_packet_utils::DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_TUPLE_ORIG => FlowAttribute::Orig({
                let b = NlaBuffer::new(payload);
                let ip = TupleNla::parse(&b)?;
                let b = NlaBuffer::new(&payload[ip.buffer_len()..]);
                let proto = TupleNla::parse(&b)?;
                vec![ip, proto]
            }),
            CTA_TUPLE_REPLY => FlowAttribute::Reply({
                let b = NlaBuffer::new(payload);
                let ip = TupleNla::parse(&b)?;
                let b = NlaBuffer::new(&payload[ip.buffer_len()..]);
                let proto = TupleNla::parse(&b)?;
                vec![ip, proto]
            }),
            CTA_STATUS => FlowAttribute::Status(ConnectionStatus::from(
                BigEndian::read_u32(payload),
            )),
            CTA_PROTOINFO => FlowAttribute::ProtocolInfo(
                ProtocolInfo::parse_from_bytes(payload)?,
            ),
            CTA_TIMEOUT => FlowAttribute::Timeout(BigEndian::read_u32(payload)),
            CTA_MARK => FlowAttribute::Mark(BigEndian::read_u32(payload)),
            CTA_USE => FlowAttribute::Use(BigEndian::read_u32(payload)),
            CTA_ID => FlowAttribute::Id(BigEndian::read_u32(payload)),
            _ => FlowAttribute::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
