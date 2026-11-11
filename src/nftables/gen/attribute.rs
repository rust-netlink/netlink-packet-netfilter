// SPDX-License-Identifier: MIT

use netlink_packet_core::{append_bytes, EncodeError};
use netlink_packet_core::{
    append_u32_be, parse_string, parse_u32_be, DecodeError, DefaultNla,
    ErrorContext as _, Nla, NlaBuffer, Parseable,
};

// Defined in Linux kernel: include/uapi/linux/netfilter/nf_tables.h
const NFTA_GEN_UNSPEC: u16 = 0;
const NFTA_GEN_ID: u16 = 1;
const NFTA_GEN_PROC_PID: u16 = 2;
const NFTA_GEN_PROC_NAME: u16 = 3;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum GenAttribute {
    Unspecified,
    /// Ruleset generation id.
    Id(u32),
    ProcPid(u32),
    ProcName(String),
    Other(DefaultNla),
}

impl Nla for GenAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_GEN_UNSPEC,
            Self::Id(_) => NFTA_GEN_ID,
            Self::ProcPid(_) => NFTA_GEN_PROC_PID,
            Self::ProcName(_) => NFTA_GEN_PROC_NAME,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::Id(value) | GenAttribute::ProcPid(value) => {
                append_u32_be(out, *value)
            }
            Self::ProcName(string) => {
                append_bytes(out, string.as_bytes());
                out.push(0);
            }
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for GenAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_GEN_UNSPEC => Self::Unspecified,
            NFTA_GEN_ID => Self::Id(
                parse_u32_be(payload).context("invalid NFTA_GEN_ID value")?,
            ),
            NFTA_GEN_PROC_PID => Self::ProcPid(
                parse_u32_be(payload)
                    .context("invalid NFTA_GEN_PROC_PID value")?,
            ),
            NFTA_GEN_PROC_NAME => Self::ProcName(
                parse_string(payload)
                    .context("invalid NFTA_GEN_PROC_NAME value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
