// SPDX-License-Identifier: MIT

use std::{convert::TryInto, time::Duration};

use netlink_packet_core::EncodeError;
use netlink_packet_core::{append_u32_be, Nla};

const NFULA_CFG_TIMEOUT: u16 = libc::NFULA_CFG_TIMEOUT as u16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeout {
    hundredth: u32,
}

impl Timeout {
    pub fn new(hundredth: u32) -> Self {
        Self { hundredth }
    }
}

impl From<Duration> for Timeout {
    fn from(duration: Duration) -> Self {
        let hundredth =
            (duration.as_millis() / 10).try_into().unwrap_or(u32::MAX);
        Self { hundredth }
    }
}

impl Nla for Timeout {
    fn kind(&self) -> u16 {
        NFULA_CFG_TIMEOUT
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u32_be(out, self.hundredth);
        Ok(())
    }
}
