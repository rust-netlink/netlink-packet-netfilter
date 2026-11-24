// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_u32_be, parse_u32_be, DecodeError, DefaultNla, ErrorContext as _,
    Nla, NlaBuffer, Parseable, NLA_F_NESTED,
};

use crate::nftables::attributes::{expression::Register, DataAttribute};
use netlink_packet_core::EncodeError;

const NFTA_IMMEDIATE_UNSPEC: u16 = 0;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Immediate {
    Unspecified,
    DestinationRegister(Register),
    /// Data to load.
    Data(DataAttribute),
    Other(DefaultNla),
}

impl Nla for Immediate {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_IMMEDIATE_UNSPEC,
            Self::DestinationRegister(_) => NFTA_IMMEDIATE_DREG,
            Self::Data(_) => NFTA_IMMEDIATE_DATA | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::DestinationRegister(reg) => append_u32_be(out, (*reg).into()),
            Self::Data(data) => data.emit(out)?,
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Data(_)) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for Immediate {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_IMMEDIATE_UNSPEC => Self::Unspecified,
            NFTA_IMMEDIATE_DREG => Self::DestinationRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_IMMEDIATE_DREG value")?
                    .into(),
            ),
            NFTA_IMMEDIATE_DATA => Self::Data(
                DataAttribute::parse(&NlaBuffer::new(payload)?).context(
                    format!("invalid NFTA_IMMEDIATE_DATA {:?}", payload),
                )?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
