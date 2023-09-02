// SPDX-License-Identifier: MIT

use byteorder::{BigEndian, ByteOrder};

use netlink_packet_utils::{
    errors::DecodeError,
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::parse_u32_be,
    Emitable, Parseable,
};

use crate::{
    constants::{
        NFQA_CAP_LEN, NFQA_CT, NFQA_CT_INFO, NFQA_EXP, NFQA_GID, NFQA_HWADDR,
        NFQA_IFINDEX_INDEV, NFQA_IFINDEX_OUTDEV, NFQA_IFINDEX_PHYSINDEV,
        NFQA_IFINDEX_PHYSOUTDEV, NFQA_L2HDR, NFQA_MARK, NFQA_PACKET_HDR,
        NFQA_PAYLOAD, NFQA_PRIORITY, NFQA_SECCTX, NFQA_SKB_INFO,
        NFQA_TIMESTAMP, NFQA_UID, NFQA_VLAN,
    },
    nfqueue::nlas::packet::{HwAddr, PacketHdr, SkbFlags, TimeStamp},
};

const U32_BYTES_SIZE: usize = 4;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PacketNla {
    PacketHdr(PacketHdr),
    Mark(u32),
    TimeStamp(TimeStamp),
    IfIndexInDev(u32),
    IfIndexOutDev(u32),
    IfIndexPhysInDev(u32),
    IfIndexPhysOutDev(u32),
    HwAddr(HwAddr),
    Payload(Vec<u8>),
    Conntrack(Vec<u8>),
    ConntrackInfo(u32),
    CapLen(u32),
    SkbInfo(SkbFlags),
    Exp(Vec<u8>),
    Uid(u32),
    Gid(u32),
    SecCtx(Vec<u8>),
    Vlan(Vec<u8>),
    L2Hdr(Vec<u8>),
    Priotity(u32),
    Other(DefaultNla),
}

impl Nla for PacketNla {
    fn value_len(&self) -> usize {
        match self {
            PacketNla::PacketHdr(payload) => payload.buffer_len(),
            PacketNla::Mark(_) => U32_BYTES_SIZE,
            PacketNla::TimeStamp(payload) => payload.buffer_len(),
            PacketNla::IfIndexInDev(_) => U32_BYTES_SIZE,
            PacketNla::IfIndexOutDev(_) => U32_BYTES_SIZE,
            PacketNla::IfIndexPhysInDev(_) => U32_BYTES_SIZE,
            PacketNla::IfIndexPhysOutDev(_) => U32_BYTES_SIZE,
            PacketNla::HwAddr(payload) => payload.buffer_len(),
            PacketNla::Payload(payload) => payload.len(),
            PacketNla::Conntrack(payload) => payload.len(),
            PacketNla::ConntrackInfo(_) => U32_BYTES_SIZE,
            PacketNla::CapLen(_) => U32_BYTES_SIZE,
            PacketNla::SkbInfo(payload) => payload.buffer_len(),
            PacketNla::Exp(payload) => payload.len(),
            PacketNla::Uid(_) => U32_BYTES_SIZE,
            PacketNla::Gid(_) => U32_BYTES_SIZE,
            PacketNla::SecCtx(payload) => payload.len(),
            PacketNla::Vlan(payload) => payload.len(),
            PacketNla::L2Hdr(payload) => payload.len(),
            PacketNla::Priotity(_) => U32_BYTES_SIZE,
            PacketNla::Other(attr) => attr.buffer_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            PacketNla::PacketHdr(_) => NFQA_PACKET_HDR,
            PacketNla::Mark(_) => NFQA_MARK,
            PacketNla::TimeStamp(_) => NFQA_TIMESTAMP,
            PacketNla::IfIndexInDev(_) => NFQA_IFINDEX_INDEV,
            PacketNla::IfIndexOutDev(_) => NFQA_IFINDEX_OUTDEV,
            PacketNla::IfIndexPhysInDev(_) => NFQA_IFINDEX_PHYSINDEV,
            PacketNla::IfIndexPhysOutDev(_) => NFQA_IFINDEX_PHYSOUTDEV,
            PacketNla::HwAddr(_) => NFQA_HWADDR,
            PacketNla::Payload(_) => NFQA_PAYLOAD,
            PacketNla::Conntrack(_) => NFQA_CT,
            PacketNla::ConntrackInfo(_) => NFQA_CT_INFO,
            PacketNla::CapLen(_) => NFQA_CAP_LEN,
            PacketNla::SkbInfo(_) => NFQA_SKB_INFO,
            PacketNla::Exp(_) => NFQA_EXP,
            PacketNla::Uid(_) => NFQA_UID,
            PacketNla::Gid(_) => NFQA_GID,
            PacketNla::SecCtx(_) => NFQA_SECCTX,
            PacketNla::Vlan(_) => NFQA_VLAN,
            PacketNla::L2Hdr(_) => NFQA_L2HDR,
            PacketNla::Priotity(_) => NFQA_PRIORITY,
            PacketNla::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            PacketNla::PacketHdr(payload) => payload.emit(buffer),
            PacketNla::Mark(payload) => BigEndian::write_u32(buffer, *payload),
            PacketNla::TimeStamp(payload) => payload.emit(buffer),
            PacketNla::IfIndexInDev(payload) => {
                BigEndian::write_u32(buffer, *payload)
            }
            PacketNla::IfIndexOutDev(payload) => {
                BigEndian::write_u32(buffer, *payload)
            }
            PacketNla::IfIndexPhysInDev(payload) => {
                BigEndian::write_u32(buffer, *payload)
            }
            PacketNla::IfIndexPhysOutDev(payload) => {
                BigEndian::write_u32(buffer, *payload)
            }
            PacketNla::HwAddr(payload) => payload.emit(buffer),
            PacketNla::Payload(payload) => buffer.copy_from_slice(payload),
            PacketNla::Conntrack(payload) => buffer.copy_from_slice(payload),
            PacketNla::ConntrackInfo(payload) => {
                BigEndian::write_u32(buffer, *payload)
            }
            PacketNla::CapLen(payload) => {
                BigEndian::write_u32(buffer, *payload)
            }
            PacketNla::SkbInfo(payload) => payload.emit(buffer),
            PacketNla::Exp(payload) => buffer.copy_from_slice(payload),
            PacketNla::Uid(payload) => BigEndian::write_u32(buffer, *payload),
            PacketNla::Gid(payload) => BigEndian::write_u32(buffer, *payload),
            PacketNla::SecCtx(payload) => buffer.copy_from_slice(payload),
            PacketNla::Vlan(payload) => buffer.copy_from_slice(payload),
            PacketNla::L2Hdr(payload) => buffer.copy_from_slice(payload),
            PacketNla::Priotity(payload) => {
                BigEndian::write_u32(buffer, *payload)
            }
            PacketNla::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for PacketNla
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        match kind {
            NFQA_PACKET_HDR => match PacketHdr::parse(payload) {
                Ok(payload) => Ok(PacketNla::PacketHdr(payload)),
                Err(error) => Err(error),
            },
            NFQA_MARK => match parse_u32_be(payload) {
                Ok(payload) => Ok(PacketNla::Mark(payload)),
                Err(error) => Err(error),
            },
            NFQA_TIMESTAMP => match TimeStamp::parse(payload) {
                Ok(payload) => Ok(PacketNla::TimeStamp(payload)),
                Err(error) => Err(error),
            },
            NFQA_IFINDEX_INDEV => match parse_u32_be(payload) {
                Ok(payload) => Ok(PacketNla::IfIndexInDev(payload)),
                Err(error) => Err(error),
            },
            NFQA_IFINDEX_OUTDEV => match parse_u32_be(payload) {
                Ok(payload) => Ok(PacketNla::IfIndexOutDev(payload)),
                Err(error) => Err(error),
            },
            NFQA_IFINDEX_PHYSINDEV => match parse_u32_be(payload) {
                Ok(payload) => Ok(PacketNla::IfIndexPhysInDev(payload)),
                Err(error) => Err(error),
            },
            NFQA_IFINDEX_PHYSOUTDEV => match parse_u32_be(payload) {
                Ok(payload) => Ok(PacketNla::IfIndexPhysOutDev(payload)),
                Err(error) => Err(error),
            },
            NFQA_HWADDR => match HwAddr::parse(payload) {
                Ok(payload) => Ok(PacketNla::HwAddr(payload)),
                Err(error) => Err(error),
            },
            NFQA_PAYLOAD => Ok(PacketNla::Payload(payload.to_vec())),
            NFQA_CT => Ok(PacketNla::Conntrack(payload.to_vec())),
            NFQA_CT_INFO => match parse_u32_be(payload) {
                Ok(payload) => Ok(PacketNla::ConntrackInfo(payload)),
                Err(error) => Err(error),
            },
            NFQA_SKB_INFO => match SkbFlags::parse(payload) {
                Ok(payload) => Ok(PacketNla::SkbInfo(payload)),
                Err(error) => Err(error),
            },
            NFQA_EXP => Ok(PacketNla::Exp(payload.to_vec())),
            NFQA_UID => match parse_u32_be(payload) {
                Ok(payload) => Ok(PacketNla::Uid(payload)),
                Err(error) => Err(error),
            },
            NFQA_GID => match parse_u32_be(payload) {
                Ok(payload) => Ok(PacketNla::Gid(payload)),
                Err(error) => Err(error),
            },
            NFQA_SECCTX => Ok(PacketNla::SecCtx(payload.to_vec())),
            NFQA_VLAN => Ok(PacketNla::Vlan(payload.to_vec())),
            NFQA_L2HDR => Ok(PacketNla::L2Hdr(payload.to_vec())),
            NFQA_PRIORITY => match parse_u32_be(payload) {
                Ok(payload) => Ok(PacketNla::Priotity(payload)),
                Err(error) => Err(error),
            },
            _ => match DefaultNla::parse(buf) {
                Ok(attr) => Ok(PacketNla::Other(attr)),
                Err(error) => Err(error),
            },
        }
    }
}
