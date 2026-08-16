// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Emitable};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

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
pub struct TCPFlagsBuffer {
    flags: u8,
    mask: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TCPFlags {
    pub flags: u8,
    pub mask: u8,
}

impl TCPFlags {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            TCPFlagsBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<TCPFlagsBuffer>(),
                )
            })?;
        Ok(Self {
            flags: raw.flags,
            mask: raw.mask,
        })
    }
}

impl From<&TCPFlags> for TCPFlagsBuffer {
    fn from(value: &TCPFlags) -> Self {
        Self {
            flags: value.flags,
            mask: value.mask,
        }
    }
}

impl Emitable for TCPFlags {
    fn buffer_len(&self) -> usize {
        size_of::<TCPFlagsBuffer>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let raw = TCPFlagsBuffer::from(self);
        buffer.copy_from_slice(raw.as_bytes());
    }
}
