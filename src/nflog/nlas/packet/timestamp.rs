// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{append_bytes, EncodeError};
use netlink_packet_core::{DecodeError, Nla};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

const NFULA_TIMESTAMP: u16 = libc::NFULA_TIMESTAMP as u16;

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
pub struct TimeStampBuffer {
    sec: u64,
    usec: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeStamp {
    sec: u64,
    usec: u64,
}

impl TimeStamp {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            TimeStampBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<TimeStampBuffer>(),
                )
            })?;
        Ok(Self {
            sec: u64::from_be(raw.sec),
            usec: u64::from_be(raw.usec),
        })
    }
}

impl From<&TimeStamp> for TimeStampBuffer {
    fn from(value: &TimeStamp) -> Self {
        Self {
            sec: value.sec.to_be(),
            usec: value.usec.to_be(),
        }
    }
}

impl Nla for TimeStamp {
    fn kind(&self) -> u16 {
        NFULA_TIMESTAMP
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = TimeStampBuffer::from(self);
        append_bytes(out, raw.as_bytes());
        Ok(())
    }
}
