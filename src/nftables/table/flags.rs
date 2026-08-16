// SPDX-License-Identifier: MIT

use bitflags::bitflags;

const NFT_TABLE_F_DORMANT: u32 = 0x1;
const NFT_TABLE_F_OWNER: u32 = 0x2;
const NFT_TABLE_F_PERSIST: u32 = 0x4;

bitflags! {
    #[derive(Clone, Eq, PartialEq, Debug, Copy, Default)]
    #[non_exhaustive]
    pub struct TableFlags: u32 {
        /// Table is inactive.
        const Dormant = NFT_TABLE_F_DORMANT;
        /// Table is owned by a process.
        const Owner = NFT_TABLE_F_OWNER;
        /// Table shall outlive its owner.
        const Persisent = NFT_TABLE_F_PERSIST;
        const _ = !0;
    }
}
