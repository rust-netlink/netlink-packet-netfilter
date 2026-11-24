// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_u32_be, parse_u32_be, DecodeError, DefaultNla, ErrorContext as _,
    Nla, NlaBuffer, Parseable, NLA_F_NESTED,
};

use crate::nftables::attributes::{expression::Register, DataAttribute};
use netlink_packet_core::EncodeError;

const NFTA_BITWISE_UNSPEC: u16 = 0;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFTA_BITWISE_OP: u16 = 6;
const NFTA_BITWISE_DATA: u16 = 7;
const NFTA_BITWISE_SREG2: u16 = 8;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Bitwise {
    Unspecified,
    SourceRegister(Register),
    DestinationRegister(Register),
    Length(u32),
    Mask(DataAttribute),
    Xor(DataAttribute),
    Op(u32),
    /// Argument for non-boolean operations
    Data(DataAttribute),
    SourceRegister2(Register),
    Other(DefaultNla),
}

impl Nla for Bitwise {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_BITWISE_UNSPEC,
            Self::SourceRegister(_) => NFTA_BITWISE_SREG,
            Self::DestinationRegister(_) => NFTA_BITWISE_DREG,
            Self::Length(_) => NFTA_BITWISE_LEN,
            Self::Mask(_) => NFTA_BITWISE_MASK | NLA_F_NESTED,
            Self::Xor(_) => NFTA_BITWISE_XOR | NLA_F_NESTED,
            Self::Op(_) => NFTA_BITWISE_OP,
            Self::Data(_) => NFTA_BITWISE_DATA | NLA_F_NESTED,
            Self::SourceRegister2(_) => NFTA_BITWISE_SREG2,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::SourceRegister(reg)
            | Self::DestinationRegister(reg)
            | Self::SourceRegister2(reg) => append_u32_be(out, (*reg).into()),
            Self::Mask(data) | Self::Xor(data) | Self::Data(data) => {
                data.emit(out)?
            }
            Self::Length(nr) | Self::Op(nr) => append_u32_be(out, *nr),
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Mask(_) | Self::Xor(_) | Self::Data(_))
            || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for Bitwise {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_BITWISE_UNSPEC => Self::Unspecified,
            NFTA_BITWISE_SREG => Self::SourceRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_BITWISE_SREG value")?
                    .into(),
            ),
            NFTA_BITWISE_DREG => Self::DestinationRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_BITWISE_DREG value")?
                    .into(),
            ),
            NFTA_BITWISE_LEN => Self::Length(
                parse_u32_be(payload)
                    .context("invalid NFTA_BITWISE_LEN value")?,
            ),
            NFTA_BITWISE_MASK => Self::Mask(
                DataAttribute::parse(&NlaBuffer::new(payload)?).context(
                    format!("invalid NFTA_BITWISE_MASK {:?}", payload),
                )?,
            ),
            NFTA_BITWISE_XOR => Self::Xor(
                DataAttribute::parse(&NlaBuffer::new(payload)?).context(
                    format!("invalid NFTA_BITWISE_XOR {:?}", payload),
                )?,
            ),
            NFTA_BITWISE_OP => Self::Op(
                parse_u32_be(payload)
                    .context("invalid NFTA_BITWISE_OP value")?,
            ),
            NFTA_BITWISE_DATA => Self::Data(
                DataAttribute::parse(&NlaBuffer::new(payload)?).context(
                    format!("invalid NFTA_BITWISE_DATA {:?}", payload),
                )?,
            ),
            NFTA_BITWISE_SREG2 => Self::SourceRegister2(
                parse_u32_be(payload)
                    .context("invalid NFTA_BITWISE_SREG2 value")?
                    .into(),
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
