// SPDX-License-Identifier: MIT

use bitflags::bitflags;
use netlink_packet_core::{
    emit_u32_be, emit_u64_be, parse_u32_be, parse_u64_be, DecodeError,
    DefaultNla, ErrorContext as _, Nla, NlaBuffer, Parseable,
};

const NFT_LIMIT_PKTS: u32 = 0;
const NFT_LIMIT_PKT_BYTES: u32 = 1;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum LimitType {
    /// Rate is counted in packets
    Packets,
    /// Rate is counted in bytes
    Bytes,
    Other(u32),
}

impl From<LimitType> for u32 {
    fn from(limit_type: LimitType) -> Self {
        match limit_type {
            LimitType::Packets => NFT_LIMIT_PKTS,
            LimitType::Bytes => NFT_LIMIT_PKT_BYTES,
            LimitType::Other(num) => num,
        }
    }
}

impl From<u32> for LimitType {
    fn from(num: u32) -> Self {
        match num {
            NFT_LIMIT_PKTS => Self::Packets,
            NFT_LIMIT_PKT_BYTES => Self::Bytes,
            _ => Self::Other(num),
        }
    }
}

const NFT_LIMIT_F_INV: u32 = 1 << 0;

bitflags! {
    #[derive(Clone, Eq, PartialEq, Debug, Copy, Default)]
    #[non_exhaustive]
    pub struct LimitFlags: u32 {
        /// Match packets over the limit instead of under it
        const Invert = NFT_LIMIT_F_INV;
        const _ = !0;
    }
}

const NFTA_LIMIT_UNSPEC: u16 = 0;
const NFTA_LIMIT_RATE: u16 = 1;
const NFTA_LIMIT_UNIT: u16 = 2;
const NFTA_LIMIT_BURST: u16 = 3;
const NFTA_LIMIT_TYPE: u16 = 4;
const NFTA_LIMIT_FLAGS: u16 = 5;
//const NFTA_LIMIT_PAD: u16 = 6;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Limit {
    Unspecified,
    /// Refill rate: packets or bytes per unit.
    Rate(u64),
    /// Refill unit in seconds.
    Unit(u64),
    /// Burst on top of the rate.
    Burst(u32),
    Type(LimitType),
    Flags(LimitFlags),
    Other(DefaultNla),
}

impl Nla for Limit {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::Rate(_) | Self::Unit(_) => 8,
            Self::Burst(_) | Self::Type(_) | Self::Flags(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_LIMIT_UNSPEC,
            Self::Rate(_) => NFTA_LIMIT_RATE,
            Self::Unit(_) => NFTA_LIMIT_UNIT,
            Self::Burst(_) => NFTA_LIMIT_BURST,
            Self::Type(_) => NFTA_LIMIT_TYPE,
            Self::Flags(_) => NFTA_LIMIT_FLAGS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::Rate(value) | Self::Unit(value) => {
                emit_u64_be(buffer, *value).unwrap()
            }
            Self::Burst(value) => emit_u32_be(buffer, *value).unwrap(),
            Self::Type(limit_type) => {
                emit_u32_be(buffer, (*limit_type).into()).unwrap()
            }
            Self::Flags(flags) => emit_u32_be(buffer, flags.bits()).unwrap(),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Limit {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_LIMIT_UNSPEC => Self::Unspecified,
            NFTA_LIMIT_RATE => Self::Rate(
                parse_u64_be(payload)
                    .context("invalid NFTA_LIMIT_RATE value")?,
            ),
            NFTA_LIMIT_UNIT => Self::Unit(
                parse_u64_be(payload)
                    .context("invalid NFTA_LIMIT_UNIT value")?,
            ),
            NFTA_LIMIT_BURST => Self::Burst(
                parse_u32_be(payload)
                    .context("invalid NFTA_LIMIT_BURST value")?,
            ),
            NFTA_LIMIT_TYPE => Self::Type(
                parse_u32_be(payload)
                    .context("invalid NFTA_LIMIT_TYPE value")?
                    .into(),
            ),
            NFTA_LIMIT_FLAGS => Self::Flags(LimitFlags::from_bits_retain(
                parse_u32_be(payload)
                    .context("invalid NFTA_LIMIT_FLAGS value")?,
            )),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
