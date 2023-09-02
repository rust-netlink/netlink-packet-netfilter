// SPDX-License-Identifier: MIT

use std::mem::size_of;

use bitflags::bitflags;
use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::parsers::parse_u32_be;
use netlink_packet_utils::{DecodeError, Emitable, Parseable};

use crate::constants::{
    NFQA_SKB_CSUMNOTREADY, NFQA_SKB_CSUM_NOTVERIFIED, NFQA_SKB_GSO,
};

bitflags! {
    #[derive(Clone, Debug, Copy, PartialEq, Eq)]
    pub struct SkbFlags: u32 {
        const CSUMNOTREADY = NFQA_SKB_CSUMNOTREADY;
        const GSO = NFQA_SKB_GSO;
        const CSUM_NOTVERIFIED = NFQA_SKB_CSUM_NOTVERIFIED;
    }
}

// see https://github.com/bitflags/bitflags/issues/263
impl SkbFlags {
    pub fn from_bits_preserve(bits: u32) -> Self {
        SkbFlags::from_bits_truncate(bits)
    }
}

impl Parseable<[u8]> for SkbFlags {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        match parse_u32_be(buf) {
            Ok(value) => Ok(SkbFlags::from_bits_preserve(value)),
            Err(error) => Err(error),
        }
    }
}

impl Emitable for SkbFlags {
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
        let flags = SkbFlags::CSUMNOTREADY | SkbFlags::GSO;

        let mut buffer = vec![0; size_of::<SkbFlags>()];
        flags.emit(&mut buffer);

        assert_eq!(
            buffer,
            [
                0x00, 0x00, 0x00,
                0x03 // SkbFlags::CSUMNOTREADY | SkbFlags::GSO
            ]
        );
    }

    #[test]
    fn test_parse() {
        let buffer: [u8; size_of::<SkbFlags>()] = [
            0x00, 0x00, 0x00,
            0x03, // SkbFlags::CSUMNOTREADY | SkbFlags::GSO
        ];
        match SkbFlags::parse(&buffer) {
            Ok(flags) => {
                assert_eq!(flags, SkbFlags::CSUMNOTREADY | SkbFlags::GSO)
            }
            Err(_) => assert!(false),
        }
    }
}
