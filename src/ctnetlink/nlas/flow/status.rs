// SPDX-License-Identifier: MIT

use bitflags::bitflags;
use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::nla::Nla;

use super::nla::CTA_STATUS;

bitflags! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ConnectionStatusFlag: u32 {
        const Expected = 1;
        const SeenReply = 1 << 1;
        const Assured = 1 << 2;
        const Confirmed = 1 << 3;
        const SourceNAT = 1 << 4;
        const DestinationNAT = 1 << 5;
        const SequenceAdjust = 1 << 6;
        const SourceNATDone = 1 << 7;
        const DestinationNATDone = 1 << 8;
        const Dying = 1 << 9;
        const FixedTimeout = 1 << 10;
        const Template = 1 << 11;
        const Untracked = 1 << 12;
        const Helper = 1 << 13;
        const Offload = 1 << 14;
    }
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
        self.inner += flag.bits();
    }

    pub fn is_set(&self, flag: ConnectionStatusFlag) -> bool {
        self.inner & flag.bits() == flag.bits()
    }
}

impl From<u32> for ConnectionStatus {
    fn from(value: u32) -> Self {
        Self { inner: value }
    }
}

impl From<ConnectionStatusFlag> for ConnectionStatus {
    fn from(flag: ConnectionStatusFlag) -> Self {
        Self { inner: flag.bits() }
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

#[cfg(test)]
mod tests {
    use super::{ConnectionStatus, ConnectionStatusFlag};

    #[test]
    fn test_connection_status_flag_set() {
        let mut status = ConnectionStatus::from(ConnectionStatusFlag::Expected);
        assert!(status.is_set(ConnectionStatusFlag::Expected));

        status.set(ConnectionStatusFlag::Assured);
        assert!(status.is_set(ConnectionStatusFlag::Assured));

        assert_eq!(
            status.get(),
            ConnectionStatusFlag::Assured.bits()
                + ConnectionStatusFlag::Expected.bits()
        );
    }
}
