// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_u32_be, parse_string, parse_u32_be, DecodeError, DefaultNla,
    ErrorContext as _, Nla, NlaBuffer, Parseable,
};

use crate::nftables::attributes::expression::Register;
use netlink_packet_core::{append_bytes, EncodeError};

const NFTA_LOOKUP_UNSPEC: u16 = 0;
const NFTA_LOOKUP_SET: u16 = 1;
const NFTA_LOOKUP_SREG: u16 = 2;
const NFTA_LOOKUP_DREG: u16 = 3;
const NFTA_LOOKUP_SET_ID: u16 = 4;
const NFTA_LOOKUP_FLAGS: u16 = 5;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Lookup {
    Unspecified,
    /// Name of the set to look in.
    Set(String),
    /// Source register containing data to look up.
    SourceRegister(Register),
    DestinationRegister(Register),
    /// Uniquely identifies a set in a transaction.
    SetId(u32),
    /// Lookup flags.
    Flags(u32),
    Other(DefaultNla),
}

impl Nla for Lookup {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_LOOKUP_UNSPEC,
            Self::Set(_) => NFTA_LOOKUP_SET,
            Self::SourceRegister(_) => NFTA_LOOKUP_SREG,
            Self::DestinationRegister(_) => NFTA_LOOKUP_DREG,
            Self::SetId(_) => NFTA_LOOKUP_SET_ID,
            Self::Flags(_) => NFTA_LOOKUP_FLAGS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::Set(string) => {
                append_bytes(out, string.as_bytes());
                out.push(0);
            }
            Self::SourceRegister(reg) | Self::DestinationRegister(reg) => {
                append_u32_be(out, (*reg).into())
            }
            Self::SetId(value) | Self::Flags(value) => {
                append_u32_be(out, *value)
            }
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for Lookup {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_LOOKUP_UNSPEC => Self::Unspecified,
            NFTA_LOOKUP_SET => Self::Set(
                parse_string(payload)
                    .context("invalid NFTA_LOOKUP_SET value")?,
            ),
            NFTA_LOOKUP_SREG => Self::SourceRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_LOOKUP_SREG value")?
                    .into(),
            ),
            NFTA_LOOKUP_DREG => Self::DestinationRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_LOOKUP_DREG value")?
                    .into(),
            ),
            NFTA_LOOKUP_SET_ID => Self::SetId(
                parse_u32_be(payload)
                    .context("invalid NFTA_LOOKUP_SET_ID value")?,
            ),
            NFTA_LOOKUP_FLAGS => Self::Flags(
                parse_u32_be(payload)
                    .context("invalid NFTA_LOOKUP_FLAGS value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
