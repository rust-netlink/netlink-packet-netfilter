// SPDX-License-Identifier: MIT

use netlink_packet_core::EncodeError;
use netlink_packet_core::{
    append_u32_be, parse_u32_be, DecodeError, DefaultNla, ErrorContext as _,
    Nla, NlaBuffer, Parseable,
};

use crate::nftables::attributes::expression::Register;

const NFT_RT_CLASSID: u32 = 0;
const NFT_RT_NEXTHOP4: u32 = 1;
const NFT_RT_NEXTHOP6: u32 = 2;
const NFT_RT_TCPMSS: u32 = 3;
const NFT_RT_XFRM: u32 = 4;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum RtKey {
    /// Realm value of packet's route (skb->dst->tclassid)
    Classid,
    /// Routing nexthop for IPv4
    Nexthop4,
    /// Routing nexthop for IPv6
    Nexthop6,
    /// Current path TCP MSS
    TcpMss,
    /// Boolean, whether the route carries an IPsec transform
    /// (skb->dst->xfrm != NULL)
    Xfrm,
    Other(u32),
}

impl From<RtKey> for u32 {
    fn from(key: RtKey) -> Self {
        match key {
            RtKey::Classid => NFT_RT_CLASSID,
            RtKey::Nexthop4 => NFT_RT_NEXTHOP4,
            RtKey::Nexthop6 => NFT_RT_NEXTHOP6,
            RtKey::TcpMss => NFT_RT_TCPMSS,
            RtKey::Xfrm => NFT_RT_XFRM,
            RtKey::Other(key_num) => key_num,
        }
    }
}

impl From<u32> for RtKey {
    fn from(key_num: u32) -> Self {
        match key_num {
            NFT_RT_CLASSID => RtKey::Classid,
            NFT_RT_NEXTHOP4 => RtKey::Nexthop4,
            NFT_RT_NEXTHOP6 => RtKey::Nexthop6,
            NFT_RT_TCPMSS => RtKey::TcpMss,
            NFT_RT_XFRM => RtKey::Xfrm,
            key_num => RtKey::Other(key_num),
        }
    }
}

const NFTA_RT_UNSPEC: u16 = 0;
const NFTA_RT_DREG: u16 = 1;
const NFTA_RT_KEY: u16 = 2;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Rt {
    Unspecified,
    DestinationRegister(Register),
    /// Routing data item to load.
    Key(RtKey),
    Other(DefaultNla),
}

impl Nla for Rt {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_RT_UNSPEC,
            Self::DestinationRegister(_) => NFTA_RT_DREG,
            Self::Key(_) => NFTA_RT_KEY,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::DestinationRegister(reg) => append_u32_be(out, (*reg).into()),
            Self::Key(key) => append_u32_be(out, (*key).into()),
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for Rt {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_RT_UNSPEC => Self::Unspecified,
            NFTA_RT_DREG => Self::DestinationRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_RT_DREG value")?
                    .into(),
            ),
            NFTA_RT_KEY => Self::Key(
                parse_u32_be(payload)
                    .context("invalid NFTA_RT_KEY value")?
                    .into(),
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
