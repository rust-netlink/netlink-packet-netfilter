// SPDX-License-Identifier: MIT

use netlink_packet_utils::{buffer, DecodeError, Emitable, Parseable};

use crate::constants::{NFQNL_COPY_META, NFQNL_COPY_NONE, NFQNL_COPY_PACKET};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyMode {
    None,
    Meta,
    Packet,
    Other(u8),
}

impl From<CopyMode> for u8 {
    fn from(cmd: CopyMode) -> Self {
        match cmd {
            CopyMode::None => NFQNL_COPY_NONE,
            CopyMode::Meta => NFQNL_COPY_META,
            CopyMode::Packet => NFQNL_COPY_PACKET,
            CopyMode::Other(cmd) => cmd,
        }
    }
}

impl From<u8> for CopyMode {
    fn from(cmd: u8) -> Self {
        match cmd {
            NFQNL_COPY_NONE => CopyMode::None,
            NFQNL_COPY_META => CopyMode::Meta,
            NFQNL_COPY_PACKET => CopyMode::Packet,
            cmd => CopyMode::Other(cmd),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigParams {
    copy_range: u32,
    copy_mode: CopyMode,
}

impl ConfigParams {
    pub fn new(copy_range: u32, copy_mode: CopyMode) -> Self {
        Self {
            copy_range,
            copy_mode,
        }
    }
}

const CONFIG_PARAMS_BUFFER_SIZE: usize = 8;

buffer!(ConfigParamsBuffer(CONFIG_PARAMS_BUFFER_SIZE) {
    copy_range: (u32, 0..4),
    copy_mode: (u8, 4),
    pad0: (u8, 5),
    pad1: (u8, 6),
    pad2: (u8, 7),
});

impl From<&ConfigParamsBuffer<&[u8]>> for ConfigParams {
    fn from(buffer: &ConfigParamsBuffer<&[u8]>) -> Self {
        Self::new(
            u32::from_be(buffer.copy_range()),
            CopyMode::from(buffer.copy_mode()),
        )
    }
}

impl Parseable<[u8]> for ConfigParams {
    fn parse(buffer: &[u8]) -> Result<Self, DecodeError> {
        match ConfigParamsBuffer::new_checked(buffer) {
            Ok(buffer) => Ok(ConfigParams::from(&buffer)),
            Err(error) => Err(error),
        }
    }
}

impl Emitable for ConfigParams {
    fn buffer_len(&self) -> usize {
        CONFIG_PARAMS_BUFFER_SIZE
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = ConfigParamsBuffer::new(buffer);
        buffer.set_copy_range(u32::to_be(self.copy_range));
        buffer.set_copy_mode(u8::from(self.copy_mode));
        buffer.set_pad0(0);
        buffer.set_pad1(0);
        buffer.set_pad2(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let buffer: [u8; CONFIG_PARAMS_BUFFER_SIZE] = [
            0x00, 0x01, 0x02, 0x03, // copy_range 0x00010203
            0x01, // copy_mode NFQNL_COPY_META
            0x00, 0x00, 0x00, //
        ];

        match ConfigParams::parse(&buffer) {
            Ok(params) => {
                assert_eq!(params.copy_range, 0x00010203);
                assert_eq!(params.copy_mode, CopyMode::Meta);
            }
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_emit() {
        let mut buffer = vec![0; CONFIG_PARAMS_BUFFER_SIZE];
        ConfigParams::new(0x00010203, CopyMode::Meta).emit(&mut buffer);
        assert_eq!(
            buffer,
            [
                0x00, 0x01, 0x02, 0x03, // copy_range 0x00010203
                0x01, // copy_mode NFQNL_COPY_META
                0x00, 0x00, 0x00, //
            ]
        )
    }
}
