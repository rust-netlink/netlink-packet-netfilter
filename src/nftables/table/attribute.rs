// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_u32_be, append_u64_be, parse_string, parse_u32_be, parse_u64_be,
    DecodeError, DefaultNla, ErrorContext as _, Nla, NlaBuffer, Parseable,
};

use crate::nftables::table::TableFlags;
use netlink_packet_core::{append_bytes, EncodeError};

// Defined in Linux kernel: include/uapi/linux/netfilter/nf_tables.h
const NFTA_TABLE_UNSPEC: u16 = 0;
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;
const NFTA_TABLE_USE: u16 = 3;
const NFTA_TABLE_HANDLE: u16 = 4;
//const NFTA_TABLE_PAD: u16 = 5;
const NFTA_TABLE_USERDATA: u16 = 6;
const NFTA_TABLE_OWNER: u16 = 7;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum TableAttribute {
    Unspecified,
    /// Name of this table.
    Name(String),
    Flags(TableFlags),
    /// Number of chains in this table.
    Use(u32),
    Handle(u64),
    UserData(Vec<u8>),
    /// Owner of this table through netlink portID.
    Owner(u32),
    Other(DefaultNla),
}

impl Nla for TableAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_TABLE_UNSPEC,
            Self::Name(_) => NFTA_TABLE_NAME,
            Self::Flags(_) => NFTA_TABLE_FLAGS,
            Self::Use(_) => NFTA_TABLE_USE,
            Self::Handle(_) => NFTA_TABLE_HANDLE,
            Self::UserData(_) => NFTA_TABLE_USERDATA,
            Self::Owner(_) => NFTA_TABLE_OWNER,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::Name(string) => {
                append_bytes(out, string.as_bytes());
                out.push(0);
            }
            Self::UserData(bytes) => append_bytes(out, bytes.as_slice()),
            Self::Flags(flags) => append_u32_be(out, flags.bits()),
            Self::Use(value) | TableAttribute::Owner(value) => {
                append_u32_be(out, *value)
            }
            Self::Handle(value) => append_u64_be(out, *value),
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for TableAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_TABLE_UNSPEC => Self::Unspecified,
            NFTA_TABLE_NAME => Self::Name(
                parse_string(payload)
                    .context("invalid NFTA_TABLE_NAME value")?,
            ),
            NFTA_TABLE_FLAGS => Self::Flags(TableFlags::from_bits_retain(
                parse_u32_be(payload)
                    .context("invalid NFTA_TABLE_FLAGS value")?,
            )),
            NFTA_TABLE_USE => Self::Use(
                parse_u32_be(payload)
                    .context("invalid NFTA_TABLE_USE value")?,
            ),
            NFTA_TABLE_HANDLE => Self::Handle(
                parse_u64_be(payload)
                    .context("invalid NFTA_TABLE_HANDLE value")?,
            ),
            NFTA_TABLE_USERDATA => Self::UserData(payload.to_vec()),
            NFTA_TABLE_OWNER => Self::Owner(
                parse_u32_be(payload)
                    .context("invalid NFTA_TABLE_OWNER value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
