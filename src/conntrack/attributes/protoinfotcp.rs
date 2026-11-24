// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u8, DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer,
    Parseable,
};

use crate::conntrack::attributes::tcp_flags::TCPFlags;
use netlink_packet_core::EncodeError;

const CTA_PROTOINFO_TCP_STATE: u16 = 1;
const CTA_PROTOINFO_TCP_WSCALE_ORIGINAL: u16 = 2;
const CTA_PROTOINFO_TCP_WSCALE_REPLY: u16 = 3;
const CTA_PROTOINFO_TCP_FLAGS_ORIGINAL: u16 = 4;
const CTA_PROTOINFO_TCP_FLAGS_REPLY: u16 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtoInfoTCP {
    State(u8),
    OriginalWindowScale(u8),
    ReplyWindowScale(u8),
    OriginalFlags(TCPFlags),
    ReplyFlags(TCPFlags),
    Other(DefaultNla),
}
impl Nla for ProtoInfoTCP {
    fn kind(&self) -> u16 {
        match self {
            ProtoInfoTCP::State(_) => CTA_PROTOINFO_TCP_STATE,
            ProtoInfoTCP::OriginalWindowScale(_) => {
                CTA_PROTOINFO_TCP_WSCALE_ORIGINAL
            }
            ProtoInfoTCP::ReplyWindowScale(_) => CTA_PROTOINFO_TCP_WSCALE_REPLY,
            ProtoInfoTCP::OriginalFlags(_) => CTA_PROTOINFO_TCP_FLAGS_ORIGINAL,
            ProtoInfoTCP::ReplyFlags(_) => CTA_PROTOINFO_TCP_FLAGS_REPLY,
            ProtoInfoTCP::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            ProtoInfoTCP::State(attr) => out.push(*attr),
            ProtoInfoTCP::OriginalWindowScale(attr) => out.push(*attr),
            ProtoInfoTCP::ReplyWindowScale(attr) => out.push(*attr),
            ProtoInfoTCP::OriginalFlags(attr) => attr.emit(out)?,
            ProtoInfoTCP::ReplyFlags(attr) => attr.emit(out)?,
            ProtoInfoTCP::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
}
impl<'buffer> Parseable<NlaBuffer<'buffer>> for ProtoInfoTCP {
    fn parse(buf: &NlaBuffer<'buffer>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_PROTOINFO_TCP_STATE => ProtoInfoTCP::State(
                parse_u8(payload)
                    .context("invalid CTA_PROTOINFO_TCP_STATE value")?,
            ),
            CTA_PROTOINFO_TCP_WSCALE_ORIGINAL => {
                ProtoInfoTCP::OriginalWindowScale(parse_u8(payload).context(
                    "invalid CTA_PROTOINFO_TCP_WSCALE_ORIGINAL value",
                )?)
            }
            CTA_PROTOINFO_TCP_WSCALE_REPLY => ProtoInfoTCP::ReplyWindowScale(
                parse_u8(payload)
                    .context("invalid CTA_PROTOINFO_TCP_WSCALE_REPLY value")?,
            ),
            CTA_PROTOINFO_TCP_FLAGS_ORIGINAL => {
                ProtoInfoTCP::OriginalFlags(TCPFlags::parse(payload).context(
                    "invalid CTA_PROTOINFO_TCP_FLAGS_ORIGINAL value",
                )?)
            }
            CTA_PROTOINFO_TCP_FLAGS_REPLY => ProtoInfoTCP::ReplyFlags(
                TCPFlags::parse(payload)
                    .context("invalid CTA_PROTOINFO_TCP_FLAGS_REPLY value")?,
            ),
            _ => ProtoInfoTCP::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
