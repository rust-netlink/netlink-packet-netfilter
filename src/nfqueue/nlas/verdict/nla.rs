// SPDX-License-Identifier: MIT

use derive_more::IsVariant;

use netlink_packet_utils::{
    errors::DecodeError,
    nla::{DefaultNla, Nla, NlaBuffer},
    Emitable, Parseable,
};

use crate::{constants::NFQA_VERDICT_HDR, nfqueue::nlas::verdict::VerdictHdr};

#[derive(Debug, PartialEq, Eq, Clone, IsVariant)]
pub enum VerdictNla {
    Verdict(VerdictHdr),
    Other(DefaultNla),
}

impl Nla for VerdictNla {
    fn value_len(&self) -> usize {
        match self {
            VerdictNla::Verdict(attr) => attr.buffer_len(),
            VerdictNla::Other(attr) => attr.buffer_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            VerdictNla::Verdict(_) => NFQA_VERDICT_HDR,
            VerdictNla::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            VerdictNla::Verdict(attr) => attr.emit(buffer),
            VerdictNla::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for VerdictNla
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        match kind {
            NFQA_VERDICT_HDR => match VerdictHdr::parse(payload) {
                Ok(payload) => Ok(VerdictNla::Verdict(payload)),
                Err(error) => Err(error),
            },
            _ => match DefaultNla::parse(buf) {
                Ok(attr) => Ok(VerdictNla::Other(attr)),
                Err(error) => Err(error),
            },
        }
    }
}
