// SPDX-License-Identifier: MIT

use anyhow::Context;
use derive_more::IsVariant;

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u16_be, parse_u8},
    DecodeError, Parseable,
};

use crate::constants::{CTA_PROTO_DST_PORT, CTA_PROTO_NUM, CTA_PROTO_SRC_PORT};

#[derive(Clone, Debug, PartialEq, Eq, IsVariant)]
pub enum ProtoMember {
    ProtoNum(u8),
    SrcPort(u16),
    DstPort(u16),
    Other(DefaultNla),
}

impl Nla for ProtoMember {
    fn value_len(&self) -> usize {
        match self {
            ProtoMember::ProtoNum(_) => 1,
            ProtoMember::SrcPort(_) => 2,
            ProtoMember::DstPort(_) => 2,
            ProtoMember::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ProtoMember::ProtoNum(_) => CTA_PROTO_NUM,
            ProtoMember::SrcPort(_) => CTA_PROTO_SRC_PORT,
            ProtoMember::DstPort(_) => CTA_PROTO_DST_PORT,
            ProtoMember::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, _buffer: &mut [u8]) {
        todo!()
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ProtoMember
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_PROTO_NUM => ProtoMember::ProtoNum(
                parse_u8(payload).context("invalid CTA_PROTO_NUM value")?,
            ),
            CTA_PROTO_SRC_PORT => ProtoMember::SrcPort(
                parse_u16_be(payload)
                    .context("invalid CTA_PROTO_SRC_PORT value")?,
            ),
            CTA_PROTO_DST_PORT => ProtoMember::DstPort(
                parse_u16_be(payload)
                    .context("invalid CTA_PROTO_DST_PORT value")?,
            ),
            _ => ProtoMember::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
