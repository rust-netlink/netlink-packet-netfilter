// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    parse_u8, DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer,
    Parseable,
};

use crate::conntrack::attributes::tcp_flags::{TCPFlags, TCPFlagsBuffer};

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
    fn value_len(&self) -> usize {
        match self {
            ProtoInfoTCP::State(attr) => size_of_val(attr),
            ProtoInfoTCP::OriginalWindowScale(attr) => size_of_val(attr),
            ProtoInfoTCP::ReplyWindowScale(attr) => size_of_val(attr),
            ProtoInfoTCP::OriginalFlags(attr) => attr.buffer_len(),
            ProtoInfoTCP::ReplyFlags(attr) => attr.buffer_len(),
            ProtoInfoTCP::Other(attr) => attr.value_len(),
        }
    }

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

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ProtoInfoTCP::State(attr) => buffer[0] = *attr,
            ProtoInfoTCP::OriginalWindowScale(attr) => buffer[0] = *attr,
            ProtoInfoTCP::ReplyWindowScale(attr) => buffer[0] = *attr,
            ProtoInfoTCP::OriginalFlags(attr) => attr.emit(buffer),
            ProtoInfoTCP::ReplyFlags(attr) => attr.emit(buffer),
            ProtoInfoTCP::Other(attr) => attr.emit_value(buffer),
        }
    }
}
impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ProtoInfoTCP
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
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
            CTA_PROTOINFO_TCP_FLAGS_ORIGINAL => ProtoInfoTCP::OriginalFlags(
                TCPFlags::parse(&TCPFlagsBuffer::new(payload)).context(
                    "invalid CTA_PROTOINFO_TCP_FLAGS_ORIGINAL value",
                )?,
            ),
            CTA_PROTOINFO_TCP_FLAGS_REPLY => ProtoInfoTCP::ReplyFlags(
                TCPFlags::parse(&TCPFlagsBuffer::new(payload))
                    .context("invalid CTA_PROTOINFO_TCP_FLAGS_REPLY value")?,
            ),
            _ => ProtoInfoTCP::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
