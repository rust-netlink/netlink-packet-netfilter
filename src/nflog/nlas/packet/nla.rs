// SPDX-License-Identifier: MIT

use std::ffi::{CStr, CString};

use derive_more::{From, IsVariant};
use netlink_packet_core::{
    append_u16_be, append_u32_be, parse_u16_be, parse_u32_be, DecodeError,
    DefaultNla, ErrorContext, Nla, NlaBuffer, Parseable,
};

use crate::nflog::nlas::packet::{
    hw_addr::HwAddr, packet_hdr::PacketHdr, timestamp::TimeStamp,
};
use netlink_packet_core::{append_bytes, EncodeError};

const NFULA_GID: u16 = libc::NFULA_GID as u16;
const NFULA_HWADDR: u16 = libc::NFULA_HWADDR as u16;
const NFULA_HWHEADER: u16 = libc::NFULA_HWHEADER as u16;
const NFULA_HWLEN: u16 = libc::NFULA_HWLEN as u16;
const NFULA_HWTYPE: u16 = libc::NFULA_HWTYPE as u16;
const NFULA_IFINDEX_INDEV: u16 = libc::NFULA_IFINDEX_INDEV as u16;
const NFULA_IFINDEX_OUTDEV: u16 = libc::NFULA_IFINDEX_OUTDEV as u16;
const NFULA_IFINDEX_PHYSINDEV: u16 = libc::NFULA_IFINDEX_PHYSINDEV as u16;
const NFULA_IFINDEX_PHYSOUTDEV: u16 = libc::NFULA_IFINDEX_PHYSOUTDEV as u16;
const NFULA_MARK: u16 = libc::NFULA_MARK as u16;
const NFULA_PACKET_HDR: u16 = libc::NFULA_PACKET_HDR as u16;
const NFULA_PAYLOAD: u16 = libc::NFULA_PAYLOAD as u16;
const NFULA_PREFIX: u16 = libc::NFULA_PREFIX as u16;
const NFULA_SEQ: u16 = libc::NFULA_SEQ as u16;
const NFULA_SEQ_GLOBAL: u16 = libc::NFULA_SEQ_GLOBAL as u16;
const NFULA_TIMESTAMP: u16 = libc::NFULA_TIMESTAMP as u16;
const NFULA_UID: u16 = libc::NFULA_UID as u16;

#[derive(Clone, Debug, PartialEq, Eq, From, IsVariant)]
#[non_exhaustive]
pub enum PacketNla {
    #[from]
    PacketHdr(PacketHdr),
    Mark(u32),
    #[from]
    Timestamp(TimeStamp),
    IfIndexInDev(u32),
    IfIndexOutDev(u32),
    IfIndexPhysInDev(u32),
    IfIndexPhysOutDev(u32),
    #[from]
    HwAddr(HwAddr),
    Payload(Vec<u8>),
    Prefix(CString),
    Uid(u32),
    Seq(u32),
    SeqGlobal(u32),
    Gid(u32),
    HwType(u16),
    HwHeader(Vec<u8>),
    HwHeaderLen(u16),
    #[from]
    Other(DefaultNla),
}

impl Nla for PacketNla {
    fn kind(&self) -> u16 {
        match self {
            PacketNla::PacketHdr(attr) => attr.kind(),
            PacketNla::Mark(_) => NFULA_MARK,
            PacketNla::Timestamp(attr) => attr.kind(),
            PacketNla::IfIndexInDev(_) => NFULA_IFINDEX_INDEV,
            PacketNla::IfIndexOutDev(_) => NFULA_IFINDEX_OUTDEV,
            PacketNla::IfIndexPhysInDev(_) => NFULA_IFINDEX_PHYSINDEV,
            PacketNla::IfIndexPhysOutDev(_) => NFULA_IFINDEX_PHYSOUTDEV,
            PacketNla::HwAddr(attr) => attr.kind(),
            PacketNla::Payload(_) => NFULA_PAYLOAD,
            PacketNla::Prefix(_) => NFULA_PREFIX,
            PacketNla::Uid(_) => NFULA_UID,
            PacketNla::Seq(_) => NFULA_SEQ,
            PacketNla::SeqGlobal(_) => NFULA_SEQ_GLOBAL,
            PacketNla::Gid(_) => NFULA_GID,
            PacketNla::HwType(_) => NFULA_HWTYPE,
            PacketNla::HwHeader(_) => NFULA_HWHEADER,
            PacketNla::HwHeaderLen(_) => NFULA_HWLEN,
            PacketNla::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            PacketNla::PacketHdr(attr) => return attr.emit_value(out),
            PacketNla::Mark(value) => {
                append_u32_be(out, *value);
            }
            PacketNla::Timestamp(attr) => return attr.emit_value(out),
            PacketNla::IfIndexInDev(value) => {
                append_u32_be(out, *value);
            }
            PacketNla::IfIndexOutDev(value) => {
                append_u32_be(out, *value);
            }
            PacketNla::IfIndexPhysInDev(value) => {
                append_u32_be(out, *value);
            }
            PacketNla::IfIndexPhysOutDev(value) => {
                append_u32_be(out, *value);
            }
            PacketNla::HwAddr(attr) => return attr.emit_value(out),
            PacketNla::Payload(vec) => append_bytes(out, vec),
            PacketNla::Prefix(cstring) => {
                append_bytes(out, cstring.as_bytes_with_nul())
            }
            PacketNla::Uid(value) => {
                append_u32_be(out, *value);
            }
            PacketNla::Seq(value) => {
                append_u32_be(out, *value);
            }
            PacketNla::SeqGlobal(value) => {
                append_u32_be(out, *value);
            }
            PacketNla::Gid(value) => {
                append_u32_be(out, *value);
            }
            PacketNla::HwType(value) => {
                append_u16_be(out, *value);
            }
            PacketNla::HwHeader(vec) => append_bytes(out, vec),
            PacketNla::HwHeaderLen(value) => {
                append_u16_be(out, *value);
            }
            PacketNla::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
}

impl<'buffer> Parseable<NlaBuffer<'buffer>> for PacketNla {
    fn parse(buf: &NlaBuffer<'buffer>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            NFULA_PACKET_HDR => PacketHdr::parse(payload)
                .context("invalid NFULA_PACKET_HDR value")?
                .into(),

            NFULA_MARK => PacketNla::Mark(
                parse_u32_be(payload).context("invalid NFULA_MARK value")?,
            ),
            NFULA_TIMESTAMP => PacketNla::Timestamp(
                TimeStamp::parse(payload)
                    .context("invalid NFULA_TIMESTAMP value")?,
            ),
            NFULA_IFINDEX_INDEV => PacketNla::IfIndexInDev(
                parse_u32_be(payload)
                    .context("invalid NFULA_IFINDEX_INDEV value")?,
            ),
            NFULA_IFINDEX_OUTDEV => PacketNla::IfIndexOutDev(
                parse_u32_be(payload)
                    .context("invalid NFULA_IFINDEX_OUTDEV value")?,
            ),
            NFULA_IFINDEX_PHYSINDEV => PacketNla::IfIndexPhysInDev(
                parse_u32_be(payload)
                    .context("invalid NFULA_IFINDEX_PHYSINDEV value")?,
            ),
            NFULA_IFINDEX_PHYSOUTDEV => PacketNla::IfIndexPhysOutDev(
                parse_u32_be(payload)
                    .context("invalid NFULA_IFINDEX_PHYSOUTDEV value")?,
            ),
            NFULA_HWADDR => PacketNla::HwAddr(
                HwAddr::parse(payload).context("invalid NFULA_HWADDR value")?,
            ),
            NFULA_PAYLOAD => PacketNla::Payload(payload.to_vec()),
            NFULA_PREFIX => PacketNla::Prefix(
                CStr::from_bytes_with_nul(payload)
                    .map_err(|e| DecodeError::from(e.to_string()))
                    .context("invalid NFULA_PREFIX value")?
                    .to_owned(),
            ),
            NFULA_UID => PacketNla::Uid(
                parse_u32_be(payload).context("invalid NFULA_UID value")?,
            ),
            NFULA_SEQ => PacketNla::Seq(
                parse_u32_be(payload).context("invalid NFULA_SEQ value")?,
            ),
            NFULA_SEQ_GLOBAL => PacketNla::SeqGlobal(
                parse_u32_be(payload)
                    .context("invalid NFULA_SEQ_GLOBAL value")?,
            ),
            NFULA_GID => PacketNla::Gid(
                parse_u32_be(payload).context("invalid NFULA_GID value")?,
            ),
            NFULA_HWTYPE => PacketNla::HwType(
                parse_u16_be(payload).context("invalid NFULA_HWTYPE value")?,
            ),
            NFULA_HWHEADER => PacketNla::HwHeader(payload.to_vec()),
            NFULA_HWLEN => PacketNla::HwHeaderLen(
                parse_u16_be(payload).context("invalid NFULA_HWLEN value")?,
            ),

            _ => PacketNla::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
