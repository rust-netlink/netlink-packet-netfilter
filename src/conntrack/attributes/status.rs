// SPDX-License-Identifier: MIT

use bitflags::bitflags;

// Conntrack status flags from uapi/linux/netfilter/nf_conntrack_common.h
const IPS_EXPECTED: u32 = 1;
const IPS_SEEN_REPLY: u32 = 1 << 1;
const IPS_ASSURED: u32 = 1 << 2;
const IPS_CONFIRMED: u32 = 1 << 3;
const IPS_SRC_NAT: u32 = 1 << 4;
const IPS_DST_NAT: u32 = 1 << 5;
const IPS_SEQ_ADJUST: u32 = 1 << 6;
const IPS_SRC_NAT_DONE: u32 = 1 << 7;
const IPS_DST_NAT_DONE: u32 = 1 << 8;
const IPS_DYING: u32 = 1 << 9;
const IPS_FIXED_TIMEOUT: u32 = 1 << 10;
const IPS_TEMPLATE: u32 = 1 << 11;
const IPS_UNTRACKED: u32 = 1 << 12;
const IPS_HELPER: u32 = 1 << 13;
const IPS_OFFLOAD: u32 = 1 << 14;

const IPS_NAT_MASK: u32 = IPS_SRC_NAT | IPS_DST_NAT;
const IPS_NAT_DONE_MASK: u32 = IPS_SRC_NAT_DONE | IPS_DST_NAT_DONE;

bitflags! {
    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Status: u32 {
        const Expected      = IPS_EXPECTED;
        const SeenReply     = IPS_SEEN_REPLY;
        const Assured       = IPS_ASSURED;
        const Confirmed     = IPS_CONFIRMED;
        const SrcNat        = IPS_SRC_NAT;
        const DstNat        = IPS_DST_NAT;
        const SeqAdjust     = IPS_SEQ_ADJUST;
        const SrcNatDone    = IPS_SRC_NAT_DONE;
        const DstNatDone    = IPS_DST_NAT_DONE;
        const Dying         = IPS_DYING;
        const FixedTimeout  = IPS_FIXED_TIMEOUT;
        const Template      = IPS_TEMPLATE;
        const Untracked     = IPS_UNTRACKED;
        const Helper        = IPS_HELPER;
        const Offload       = IPS_OFFLOAD;
        const NatMask       = IPS_NAT_MASK;
        const NatDoneMask   = IPS_NAT_DONE_MASK;
        const _ = !0;
    }
}
