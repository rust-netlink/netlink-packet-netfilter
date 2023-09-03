// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, errors::DecodeError, Emitable, Parseable};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeStamp {
    sec: u64,
    usec: u64,
}

impl TimeStamp {
    pub fn new(sec: u64, usec: u64) -> Self {
        Self { sec, usec }
    }
}

const TIMESTAMP_LEN: usize = 16;

buffer!(TimeStampBuffer(TIMESTAMP_LEN) {
    sec: (u64, 0..8),
    usec: (u64, 8..16),
});

impl From<&TimeStampBuffer<&[u8]>> for TimeStamp {
    fn from(buffer: &TimeStampBuffer<&[u8]>) -> Self {
        TimeStamp::new(u64::from_be(buffer.sec()), u64::from_be(buffer.usec()))
    }
}

impl Parseable<[u8]> for TimeStamp {
    fn parse(buffer: &[u8]) -> Result<Self, DecodeError> {
        match TimeStampBuffer::new_checked(buffer) {
            Ok(buffer) => Ok(TimeStamp::from(&buffer)),
            Err(error) => Err(error),
        }
    }
}

impl Emitable for TimeStamp {
    fn buffer_len(&self) -> usize {
        TIMESTAMP_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = TimeStampBuffer::new(buffer);
        buffer.set_sec(u64::to_be(self.sec));
        buffer.set_usec(u64::to_be(self.usec));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let buffer: [u8; TIMESTAMP_LEN] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // sec
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, // usec
        ];
        match TimeStamp::parse(&buffer) {
            Ok(timestamp) => {
                assert_eq!(timestamp.sec, 0x0001020304050607);
                assert_eq!(timestamp.usec, 0x08090A0B0C0D0E0F);
            }
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_emit() {
        let mut buffer = vec![0; TIMESTAMP_LEN];
        TimeStamp::new(0x0001020304050607, 0x08090A0B0C0D0E0F)
            .emit(&mut buffer);
        assert_eq!(
            buffer,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // sec
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, // usec
            ]
        );
    }
}
