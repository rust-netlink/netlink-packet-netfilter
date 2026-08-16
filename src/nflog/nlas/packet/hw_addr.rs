// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Nla};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::constants::NFULA_HWADDR;

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
pub struct HwAddrBuffer {
    hw_addr_len: u16,
    _pad: [u8; 2],
    hw_addr: [u8; 8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HwAddr {
    len: u16,
    address: [u8; 8],
}

impl HwAddr {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            HwAddrBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<HwAddrBuffer>(),
                )
            })?;
        Ok(Self {
            len: u16::from_be(raw.hw_addr_len),
            address: raw.hw_addr,
        })
    }
}

impl From<&HwAddr> for HwAddrBuffer {
    fn from(value: &HwAddr) -> Self {
        Self {
            hw_addr_len: value.len.to_be(),
            _pad: [0; 2],
            hw_addr: value.address,
        }
    }
}

impl Nla for HwAddr {
    fn value_len(&self) -> usize {
        size_of::<HwAddrBuffer>()
    }

    fn kind(&self) -> u16 {
        NFULA_HWADDR
    }

    fn emit_value(&self, buf: &mut [u8]) {
        let raw = HwAddrBuffer::from(self);
        buf.copy_from_slice(raw.as_bytes());
    }
}
