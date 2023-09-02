// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, DecodeError, Emitable, Parseable};

use crate::constants::{
    NF_ACCEPT, NF_DROP, NF_QUEUE, NF_REPEAT, NF_STOLEN, NF_STOP,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerdictType {
    Drop,
    Accept,
    Stolen,
    Queue,
    Repeat,
    Stop,
    Other(u32),
}

impl From<VerdictType> for u32 {
    fn from(verdict: VerdictType) -> Self {
        match verdict {
            VerdictType::Drop => NF_DROP,
            VerdictType::Accept => NF_ACCEPT,
            VerdictType::Stolen => NF_STOLEN,
            VerdictType::Queue => NF_QUEUE,
            VerdictType::Repeat => NF_REPEAT,
            VerdictType::Stop => NF_STOP,
            VerdictType::Other(verdict) => verdict,
        }
    }
}

impl From<u32> for VerdictType {
    fn from(verdict: u32) -> Self {
        match verdict {
            NF_DROP => VerdictType::Drop,
            NF_ACCEPT => VerdictType::Accept,
            NF_STOLEN => VerdictType::Stolen,
            NF_QUEUE => VerdictType::Queue,
            NF_REPEAT => VerdictType::Repeat,
            NF_STOP => VerdictType::Stop,
            verdict => VerdictType::Other(verdict),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VerdictHdr {
    verdict: VerdictType,
    id: u32,
}

impl VerdictHdr {
    pub fn new(verdict: VerdictType, id: u32) -> Self {
        Self { verdict, id }
    }
}

const VERDICT_HDR_LEN: usize = 8;

buffer!(VerdictBuffer(VERDICT_HDR_LEN) {
    verdict: (u32, 0..4),
    id: (u32, 4..8),
});

impl From<&VerdictBuffer<&[u8]>> for VerdictHdr {
    fn from(buffer: &VerdictBuffer<&[u8]>) -> Self {
        Self::new(
            VerdictType::from(u32::from_be(buffer.verdict())),
            u32::from_be(buffer.id()),
        )
    }
}

impl Parseable<[u8]> for VerdictHdr {
    fn parse(buffer: &[u8]) -> Result<Self, DecodeError> {
        match VerdictBuffer::new_checked(buffer) {
            Ok(buffer) => Ok(VerdictHdr::from(&buffer)),
            Err(error) => Err(error),
        }
    }
}

impl Emitable for VerdictHdr {
    fn buffer_len(&self) -> usize {
        VERDICT_HDR_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = VerdictBuffer::new(buffer);
        buffer.set_verdict(u32::from_be(u32::from(self.verdict)));
        buffer.set_id(u32::from_be(self.id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let buffer: [u8; VERDICT_HDR_LEN] = [
            0x00, 0x00, 0x00, 0x01, // NF_ACCEPT 0x00000001
            0x01, 0x02, 0x03, 0x04, // id 0x01020304
        ];
        match VerdictHdr::parse(&buffer) {
            Ok(verdict) => {
                assert_eq!(verdict.verdict, VerdictType::Accept);
                assert_eq!(verdict.id, 0x01020304);
            }
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_emit() {
        let mut buffer = vec![0; VERDICT_HDR_LEN];
        VerdictHdr::new(VerdictType::Accept, 0x01020304).emit(&mut buffer);
        assert_eq!(
            buffer,
            [
                0x00, 0x00, 0x00, 0x01, // NF_ACCEPT 0x00000001
                0x01, 0x02, 0x03, 0x04 // id 0x01020304
            ]
        );
    }
}
