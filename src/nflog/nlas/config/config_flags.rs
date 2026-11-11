// SPDX-License-Identifier: MIT

use bitflags::bitflags;
use netlink_packet_core::EncodeError;
use netlink_packet_core::{append_u16_be, Nla};

const NFULA_CFG_FLAGS: u16 = libc::NFULA_CFG_FLAGS as u16;

bitflags! {
    #[derive(Clone, Debug, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct ConfigFlags: u16 {
        const SEQ = libc:: NFULNL_CFG_F_SEQ as u16;
        const SEQ_GLOBAL = libc:: NFULNL_CFG_F_SEQ_GLOBAL as u16;
        const CONNTRACK = libc:: NFULNL_CFG_F_CONNTRACK as u16;
    }
}

// see https://github.com/bitflags/bitflags/issues/263
impl ConfigFlags {
    pub fn from_bits_preserve(bits: u16) -> Self {
        ConfigFlags::from_bits_truncate(bits)
    }
}

impl Nla for ConfigFlags {
    fn kind(&self) -> u16 {
        NFULA_CFG_FLAGS
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        append_u16_be(out, self.bits());
        Ok(())
    }
}
