// SPDX-License-Identifier: MIT

use bitflags::bitflags;
use netlink_packet_core::{
    append_u32_be, parse_u32_be, DecodeError, DefaultNla, ErrorContext as _,
    Nla, NlaBuffer, Parseable,
};

use crate::nftables::attributes::expression::Register;
use netlink_packet_core::EncodeError;

const NFT_PAYLOAD_CSUM_NONE: u32 = 0;
const NFT_PAYLOAD_CSUM_INET: u32 = 1;
const NFT_PAYLOAD_CSUM_SCTP: u32 = 2;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ChecksumType {
    /// No Checksumming
    None,
    ///internet checksum (RFC 791)
    Inet,
    /// CRC-32c, for use in SCTP header (RFC 3309)
    Sctp,
    Other(u32),
}
impl From<ChecksumType> for u32 {
    fn from(csum_type: ChecksumType) -> Self {
        match csum_type {
            ChecksumType::None => NFT_PAYLOAD_CSUM_NONE,
            ChecksumType::Inet => NFT_PAYLOAD_CSUM_INET,
            ChecksumType::Sctp => NFT_PAYLOAD_CSUM_SCTP,
            ChecksumType::Other(num) => num,
        }
    }
}

impl From<u32> for ChecksumType {
    fn from(num: u32) -> Self {
        match num {
            NFT_PAYLOAD_CSUM_NONE => Self::None,
            NFT_PAYLOAD_CSUM_INET => Self::Inet,
            NFT_PAYLOAD_CSUM_SCTP => Self::Sctp,
            _ => Self::Other(num),
        }
    }
}

const NFT_PAYLOAD_L4CSUM_PSEUDOHDR: u32 = 1;

bitflags! {
    #[derive(Clone, Eq, PartialEq, Debug, Copy, Default)]
    #[non_exhaustive]
    pub struct ChecksumFlags: u32 {
        /// Calculates checksum over pseudo-headers for Layer 4 protocols like TCP/UDP
        const L4PseudoHeader = NFT_PAYLOAD_L4CSUM_PSEUDOHDR;
        const _ = !0;
    }
}

const NFTA_PAYLOAD_UNSPEC: u16 = 0;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_PAYLOAD_SREG: u16 = 5;
const NFTA_PAYLOAD_CSUM_TYPE: u16 = 6;
const NFTA_PAYLOAD_CSUM_OFFSET: u16 = 7;
const NFTA_PAYLOAD_CSUM_FLAGS: u16 = 8;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Payload {
    Unspecified,
    DestinationRegister(Register),
    /// Payload base.
    Base(u32),
    /// Payload offset relative to base.
    Offset(u32),
    /// Payload length.
    Len(u32),
    SourceRegister(Register),
    CsumType(ChecksumType),
    /// Checksum offset relative to base.
    CsumOffset(u32),
    CsumFlags(ChecksumFlags),
    Other(DefaultNla),
}

impl Nla for Payload {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_PAYLOAD_UNSPEC,
            Self::DestinationRegister(_) => NFTA_PAYLOAD_DREG,
            Self::Base(_) => NFTA_PAYLOAD_BASE,
            Self::Offset(_) => NFTA_PAYLOAD_OFFSET,
            Self::Len(_) => NFTA_PAYLOAD_LEN,
            Self::SourceRegister(_) => NFTA_PAYLOAD_SREG,
            Self::CsumType(_) => NFTA_PAYLOAD_CSUM_TYPE,
            Self::CsumOffset(_) => NFTA_PAYLOAD_CSUM_OFFSET,
            Self::CsumFlags(_) => NFTA_PAYLOAD_CSUM_FLAGS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::DestinationRegister(reg) | Self::SourceRegister(reg) => {
                append_u32_be(out, (*reg).into())
            }
            Self::Base(value)
            | Self::Offset(value)
            | Self::Len(value)
            | Self::CsumOffset(value) => append_u32_be(out, *value),
            Self::CsumFlags(flags) => append_u32_be(out, flags.bits()),
            Self::CsumType(csum_type) => {
                append_u32_be(out, (*csum_type).into())
            }
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for Payload {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_PAYLOAD_UNSPEC => Self::Unspecified,
            NFTA_PAYLOAD_DREG => Self::DestinationRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_PAYLOAD_DREG value")?
                    .into(),
            ),
            NFTA_PAYLOAD_BASE => Self::Base(
                parse_u32_be(payload)
                    .context("invalid NFTA_PAYLOAD_BASE value")?,
            ),
            NFTA_PAYLOAD_OFFSET => Self::Offset(
                parse_u32_be(payload)
                    .context("invalid NFTA_PAYLOAD_OFFSET value")?,
            ),
            NFTA_PAYLOAD_LEN => Self::Len(
                parse_u32_be(payload)
                    .context("invalid NFTA_PAYLOAD_LEN value")?,
            ),
            NFTA_PAYLOAD_SREG => Self::SourceRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_PAYLOAD_SREG value")?
                    .into(),
            ),
            NFTA_PAYLOAD_CSUM_TYPE => Self::CsumType(
                parse_u32_be(payload)
                    .context("invalid NFTA_PAYLOAD_CSUM_TYPE value")?
                    .into(),
            ),
            NFTA_PAYLOAD_CSUM_OFFSET => Self::CsumOffset(
                parse_u32_be(payload)
                    .context("invalid NFTA_PAYLOAD_CSUM_OFFSET value")?,
            ),
            NFTA_PAYLOAD_CSUM_FLAGS => {
                Self::CsumFlags(ChecksumFlags::from_bits_retain(
                    parse_u32_be(payload)
                        .context("invalid NFTA_PAYLOAD_CSUM_FLAGS value")?,
                ))
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
