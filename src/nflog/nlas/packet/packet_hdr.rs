// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Nla};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const NFULA_PACKET_HDR: u16 = libc::NFULA_PACKET_HDR as u16;

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct PacketHdrBuffer {
    hw_protocol: u16,
    hook: u8,
    pad: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketHdr {
    hw_protocol: u16,
    hook: u8,
}

impl PacketHdr {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            PacketHdrBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<PacketHdrBuffer>(),
                )
            })?;
        Ok(Self {
            hw_protocol: u16::from_be(raw.hw_protocol),
            hook: raw.hook,
        })
    }
}

impl From<&PacketHdr> for PacketHdrBuffer {
    fn from(value: &PacketHdr) -> Self {
        Self {
            hw_protocol: value.hw_protocol.to_be(),
            hook: value.hook,
            pad: 0,
        }
    }
}

impl Nla for PacketHdr {
    fn value_len(&self) -> usize {
        size_of::<PacketHdrBuffer>()
    }

    fn kind(&self) -> u16 {
        NFULA_PACKET_HDR
    }

    fn emit_value(&self, buf: &mut [u8]) {
        let raw = PacketHdrBuffer::from(self);
        buf.copy_from_slice(raw.as_bytes());
    }
}
