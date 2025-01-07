// SPDX-License-Identifier: MIT

use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::nla::Nla;

use crate::constants::CTA_STATUS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConnectionStatusFlag {
    Offload = 1 << 14,
    Helper = 1 << 13,
    Untracked = 1 << 12,
    Template = 1 << 11,
    FixedTimeout = 1 << 10,
    Dying = 1 << 9,
    DestinationNATDone = 1 << 8,
    SourceNATDone = 1 << 7,
    SequenceAdjust = 1 << 6,
    DestinationNAT = 1 << 5,
    SourceNAT = 1 << 4,
    Confirmed = 1 << 3,
    Assured = 1 << 2,
    SeenReply = 1 << 1,
    Expected = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct ConnectionStatus {
    inner: u32,
}

impl ConnectionStatus {
    pub fn get(&self) -> u32 {
        self.inner
    }

    pub fn set(&mut self, flag: ConnectionStatusFlag) {
        self.inner += flag as u32
    }

    pub fn is_set(&self, flag: ConnectionStatusFlag) -> bool {
        self.inner & flag as u32 == flag as u32
    }
}

impl From<u32> for ConnectionStatus {
    fn from(value: u32) -> Self {
        Self { inner: value }
    }
}

impl From<ConnectionStatusFlag> for ConnectionStatus {
    fn from(value: ConnectionStatusFlag) -> Self {
        Self {
            inner: value as u32,
        }
    }
}

impl Nla for ConnectionStatus {
    fn value_len(&self) -> usize {
        4
    }

    fn kind(&self) -> u16 {
        CTA_STATUS
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        BigEndian::write_u32(buffer, self.inner);
    }
}
