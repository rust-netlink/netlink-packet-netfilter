// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32_be, emit_u64_be, parse_string, parse_u32_be, parse_u64_be,
    DecodeError, DefaultNla, ErrorContext as _, Nla, NlaBuffer, Parseable,
};

use crate::nftables::table::TableFlags;

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
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::Name(string) => string.len() + 1,
            Self::UserData(bytes) => bytes.len(),
            Self::Flags(_) | Self::Use(_) | Self::Owner(_) => 4,
            Self::Handle(_) => 8,
            Self::Other(attr) => attr.value_len(),
        }
    }

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

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::Name(string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }
            Self::UserData(bytes) => {
                buffer[..bytes.len()].copy_from_slice(bytes.as_slice())
            }
            Self::Flags(flags) => emit_u32_be(buffer, flags.bits()).unwrap(),
            Self::Use(value) | TableAttribute::Owner(value) => {
                emit_u32_be(buffer, *value).unwrap()
            }
            Self::Handle(value) => emit_u64_be(buffer, *value).unwrap(),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for TableAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
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
