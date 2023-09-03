// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, errors::DecodeError, Emitable, Parseable};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HwAddr {
    len: u16,
    address: [u8; 8],
}

impl HwAddr {
    pub fn new(len: u16, address: [u8; 8]) -> Self {
        Self { len, address }
    }
}

const HW_ADDR_LEN: usize = 12;

buffer!(HwAddrBuffer(HW_ADDR_LEN) {
    hw_addr_len: (u16, 0..2),
    hw_addr_0: (u8, 4),
    hw_addr_1: (u8, 5),
    hw_addr_2: (u8, 6),
    hw_addr_3: (u8, 7),
    hw_addr_4: (u8, 8),
    hw_addr_5: (u8, 9),
    hw_addr_6: (u8, 10),
    hw_addr_7: (u8, 11),
});

impl From<&HwAddrBuffer<&[u8]>> for HwAddr {
    fn from(buffer: &HwAddrBuffer<&[u8]>) -> Self {
        Self {
            len: u16::from_be(buffer.hw_addr_len()),
            address: [
                buffer.hw_addr_0(),
                buffer.hw_addr_1(),
                buffer.hw_addr_2(),
                buffer.hw_addr_3(),
                buffer.hw_addr_4(),
                buffer.hw_addr_5(),
                buffer.hw_addr_6(),
                buffer.hw_addr_7(),
            ],
        }
    }
}

impl Parseable<[u8]> for HwAddr {
    fn parse(buffer: &[u8]) -> Result<Self, DecodeError> {
        match HwAddrBuffer::new_checked(buffer) {
            Ok(buffer) => Ok(HwAddr::from(&buffer)),
            Err(error) => Err(error),
        }
    }
}

impl Emitable for HwAddr {
    fn buffer_len(&self) -> usize {
        HW_ADDR_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = HwAddrBuffer::new(buffer);
        buffer.set_hw_addr_len(self.len.to_be());
        buffer.set_hw_addr_0(self.address[0]);
        buffer.set_hw_addr_1(self.address[1]);
        buffer.set_hw_addr_2(self.address[2]);
        buffer.set_hw_addr_3(self.address[3]);
        buffer.set_hw_addr_4(self.address[4]);
        buffer.set_hw_addr_5(self.address[5]);
        buffer.set_hw_addr_6(self.address[6]);
        buffer.set_hw_addr_7(self.address[7]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let buffer: [u8; HW_ADDR_LEN] = [
            0x00, 0x06, // len 0x0006
            0x00, 0x00, //
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // 0xAABBCCDDEEFF
            0x00, 0x00, //
        ];
        match HwAddr::parse(&buffer) {
            Ok(addr) => {
                assert_eq!(addr.len, 0x0006);
                assert_eq!(
                    addr.address,
                    [
                        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, //
                        0x00, 0x00,
                    ]
                );
            }
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_emit() {
        let mut buffer = vec![0; HW_ADDR_LEN];
        let address = HwAddr::new(
            0x0006,
            [
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, //
                0x00, 0x00,
            ],
        );
        address.emit(&mut buffer);
        assert_eq!(
            buffer,
            [
                0x00, 0x06, // len 0x0006
                0x00, 0x00, //
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // 0xAABBCCDDEEFF
                0x00, 0x00, //
            ]
        );
    }
}
