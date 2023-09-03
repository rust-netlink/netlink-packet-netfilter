// SPDX-License-Identifier: MIT

use std::mem::size_of;

use bitflags::bitflags;
use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::parsers::parse_u32_be;
use netlink_packet_utils::{DecodeError, Emitable, Parseable};

use crate::constants::{
    NFQA_CFG_F_CONNTRACK, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_GSO,
    NFQA_CFG_F_SECCTX, NFQA_CFG_F_UID_GID,
};

bitflags! {
    #[derive(Clone, Debug, Copy, PartialEq, Eq)]
    pub struct ConfigFlags: u32 {
        const FAIL_OPEN = NFQA_CFG_F_FAIL_OPEN;
        const CONNTRACK = NFQA_CFG_F_CONNTRACK;
        const GSO = NFQA_CFG_F_GSO;
        const UID_GID = NFQA_CFG_F_UID_GID;
        const SECCTX = NFQA_CFG_F_SECCTX;
    }
}

// see https://github.com/bitflags/bitflags/issues/263
impl ConfigFlags {
    pub fn from_bits_preserve(bits: u32) -> Self {
        ConfigFlags::from_bits_truncate(bits)
    }
}

impl Parseable<[u8]> for ConfigFlags {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        match parse_u32_be(buf) {
            Ok(value) => Ok(ConfigFlags::from_bits_preserve(value)),
            Err(error) => Err(error),
        }
    }
}

impl Emitable for ConfigFlags {
    fn buffer_len(&self) -> usize {
        size_of::<Self>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        BigEndian::write_u32(buffer, self.bits());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit() {
        let flags = ConfigFlags::FAIL_OPEN | ConfigFlags::CONNTRACK;

        let mut buffer = vec![0; size_of::<ConfigFlags>()];
        flags.emit(&mut buffer);

        assert_eq!(
            buffer,
            [
                0x00, 0x00, 0x00,
                0x03 // ConfigFlags::FAIL_OPEN | ConfigFlags::CONNTRACK
            ]
        );
    }

    #[test]
    fn test_parse() {
        let buffer: [u8; size_of::<ConfigFlags>()] = [
            0x00, 0x00, 0x00,
            0x03, // ConfigFlags::FAIL_OPEN | ConfigFlags::CONNTRACK
        ];
        match ConfigFlags::parse(&buffer) {
            Ok(flags) => assert_eq!(
                flags,
                ConfigFlags::FAIL_OPEN | ConfigFlags::CONNTRACK
            ),
            Err(_) => assert!(false),
        }
    }
}
