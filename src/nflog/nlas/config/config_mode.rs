// SPDX-License-Identifier: MIT

use std::mem::size_of;

use netlink_packet_core::{DecodeError, Nla};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

const NFULA_CFG_MODE: u16 = libc::NFULA_CFG_MODE as u16;
const NFULNL_COPY_NONE: u8 = libc::NFULNL_COPY_NONE as u8;
const NFULNL_COPY_META: u8 = libc::NFULNL_COPY_META as u8;
const NFULNL_COPY_PACKET: u8 = libc::NFULNL_COPY_PACKET as u8;

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
pub struct ConfigModeBuffer {
    copy_range: u32,
    copy_mode: u8,
    _pad: [u8; 1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CopyMode {
    None,
    Meta,
    Packet,
    Other(u8),
}

impl From<CopyMode> for u8 {
    fn from(cmd: CopyMode) -> Self {
        match cmd {
            CopyMode::None => NFULNL_COPY_NONE,
            CopyMode::Meta => NFULNL_COPY_META,
            CopyMode::Packet => NFULNL_COPY_PACKET,
            CopyMode::Other(cmd) => cmd,
        }
    }
}

impl From<u8> for CopyMode {
    fn from(cmd: u8) -> Self {
        match cmd {
            NFULNL_COPY_NONE => CopyMode::None,
            NFULNL_COPY_META => CopyMode::Meta,
            NFULNL_COPY_PACKET => CopyMode::Packet,
            cmd => CopyMode::Other(cmd),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigMode {
    copy_range: u32,
    copy_mode: CopyMode,
}

impl ConfigMode {
    pub const NONE: Self = Self {
        copy_range: 0,
        copy_mode: CopyMode::None,
    };

    pub const META: Self = Self {
        copy_range: 0,
        copy_mode: CopyMode::Meta,
    };

    pub const PACKET_MAX: Self = Self {
        copy_range: 0,
        copy_mode: CopyMode::Packet,
    };

    pub fn new(copy_range: u32, copy_mode: CopyMode) -> Self {
        Self {
            copy_range,
            copy_mode,
        }
    }

    pub fn new_packet(copy_range: u32) -> Self {
        Self::new(copy_range, CopyMode::Packet)
    }

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            ConfigModeBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    size_of::<ConfigModeBuffer>(),
                )
            })?;
        Ok(Self {
            copy_range: u32::from_be(raw.copy_range),
            copy_mode: raw.copy_mode.into(),
        })
    }
}

impl From<&ConfigMode> for ConfigModeBuffer {
    fn from(value: &ConfigMode) -> Self {
        Self {
            copy_range: value.copy_range.to_be(),
            copy_mode: value.copy_mode.into(),
            _pad: [0; 1],
        }
    }
}

impl Nla for ConfigMode {
    fn value_len(&self) -> usize {
        size_of::<ConfigModeBuffer>()
    }

    fn kind(&self) -> u16 {
        NFULA_CFG_MODE
    }

    fn emit_value(&self, buf: &mut [u8]) {
        let raw = ConfigModeBuffer::from(self);
        buf.copy_from_slice(raw.as_bytes());
    }
}
