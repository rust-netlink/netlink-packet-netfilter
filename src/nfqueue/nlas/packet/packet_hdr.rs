// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, errors::DecodeError, Emitable, Parseable};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketHdr {
    pub packet_id: u32,
    pub hw_protocol: u16,
    pub hook: u8,
}

impl PacketHdr {
    pub fn new(packet_id: u32, hw_protocol: u16, hook: u8) -> Self {
        Self {
            packet_id,
            hw_protocol,
            hook,
        }
    }
}

const PACKET_HDR_LEN: usize = 7;

buffer!(PacketHdrBuffer(PACKET_HDR_LEN) {
    packet_id: (u32, 0..4),
    hw_protocol: (u16, 4..6),
    hook: (u8, 6),
});

impl From<&PacketHdrBuffer<&[u8]>> for PacketHdr {
    fn from(buffer: &PacketHdrBuffer<&[u8]>) -> Self {
        PacketHdr::new(
            u32::from_be(buffer.packet_id()),
            u16::from_be(buffer.hw_protocol()),
            buffer.hook(),
        )
    }
}

impl Parseable<[u8]> for PacketHdr {
    fn parse(buffer: &[u8]) -> Result<Self, DecodeError> {
        match PacketHdrBuffer::new_checked(buffer) {
            Ok(buffer) => Ok(PacketHdr::from(&buffer)),
            Err(error) => Err(error),
        }
    }
}

impl Emitable for PacketHdr {
    fn buffer_len(&self) -> usize {
        PACKET_HDR_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = PacketHdrBuffer::new(buffer);
        buffer.set_packet_id(u32::to_be(self.packet_id));
        buffer.set_hw_protocol(u16::to_be(self.hw_protocol));
        buffer.set_hook(self.hook);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let buffer: [u8; PACKET_HDR_LEN] = [
            0x00, 0x01, 0x02, 0x03, // packet_id 0x010203
            0x04, 0x05, // hw_protocol 0x0405
            0x06, // hook 0x06
        ];
        match PacketHdr::parse(&buffer) {
            Ok(packet) => {
                assert_eq!(packet.packet_id, 0x00010203);
                assert_eq!(packet.hw_protocol, 0x0405);
                assert_eq!(packet.hook, 0x06);
            }
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_emit() {
        let mut buffer = vec![0; PACKET_HDR_LEN];
        PacketHdr::new(0x00010203, 0x0405, 0x06).emit(&mut buffer);
        assert_eq!(
            buffer,
            [
                0x00, 0x01, 0x02, 0x03, // packet_id 0x010203
                0x04, 0x05, // hw_protocol 0x0405
                0x06, // hook 0x06
            ]
        );
    }
}
