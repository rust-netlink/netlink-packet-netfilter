// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_u32_be, parse_u32_be, DecodeError, DefaultNla, ErrorContext as _,
    Nla, NlaBuffer, Parseable,
};

use crate::nftables::attributes::expression::Register;
use netlink_packet_core::EncodeError;

// SPDX-License-Identifier: MIT

const NFT_META_LEN: u32 = 0;
const NFT_META_PROTOCOL: u32 = 1;
const NFT_META_PRIORITY: u32 = 2;
const NFT_META_MARK: u32 = 3;
const NFT_META_IIF: u32 = 4;
const NFT_META_OIF: u32 = 5;
const NFT_META_IIFNAME: u32 = 6;
const NFT_META_OIFNAME: u32 = 7;
const NFT_META_IFTYPE: u32 = 8;
const NFT_META_OIFTYPE: u32 = 9;
const NFT_META_SKUID: u32 = 10;
const NFT_META_SKGID: u32 = 11;
const NFT_META_NFTRACE: u32 = 12;
const NFT_META_RTCLASSID: u32 = 13;
const NFT_META_SECMARK: u32 = 14;
const NFT_META_NFPROTO: u32 = 15;
const NFT_META_L4PROTO: u32 = 16;
const NFT_META_BRI_IIFNAME: u32 = 17;
const NFT_META_BRI_OIFNAME: u32 = 18;
const NFT_META_PKTTYPE: u32 = 19;
const NFT_META_CPU: u32 = 20;
const NFT_META_IIFGROUP: u32 = 21;
const NFT_META_OIFGROUP: u32 = 22;
const NFT_META_CGROUP: u32 = 23;
const NFT_META_PRANDOM: u32 = 24;
const NFT_META_SECPATH: u32 = 25;
const NFT_META_IIFKIND: u32 = 26;
const NFT_META_OIFKIND: u32 = 27;
const NFT_META_BRI_IIFPVID: u32 = 28;
const NFT_META_BRI_IIFVPROTO: u32 = 29;
const NFT_META_TIME_NS: u32 = 30;
const NFT_META_TIME_DAY: u32 = 31;
const NFT_META_TIME_HOUR: u32 = 32;
const NFT_META_SDIF: u32 = 33;
const NFT_META_SDIFNAME: u32 = 34;
const NFT_META_BRI_BROUTE: u32 = 35;
//const __NFT_META_IIFTYPE: u32 = 36;
const NFT_META_BRI_IIFHWADDR: u32 = 37;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum MetaKey {
    Length,
    EtherTypeProtocol,
    Priority,
    Mark,
    /// Packet input interface index
    Iif,
    /// Packet output interface index
    Oif,
    /// Packet input interface name
    Iifname,
    /// Packet output interface name
    Oifname,
    /// Packet input interface type
    Iftype,
    /// Packet output interface type
    Oiftype,
    SocketUserId,
    SocketGroupId,
    NftraceBit,
    /// Realm value of packet's route (skb->dst->tclassid)
    Rtclassid,
    Secmark,
    Nfproto,
    /// Layer 4 protocol number
    L4Proto,
    /// Packet input bridge interface name
    BriIifname,
    /// Packet output bridge interface name
    BriOifname,
    PacketType,
    Cpu,
    Iifgroup,
    Oifgroup,
    /// Socket control group
    Cgroup,
    /// A 32bit pseudo-random number
    PseudoRandom,
    Secpath,
    Iifkind,
    Oifkind,
    BriIifpvid,
    BriIifvproto,
    TimeNs,
    TimeDay,
    TimeHour,
    /// Slave device interface index
    Sdif,
    /// Slave device interface name
    Sdifname,
    BriBroute,
    /// Packet input bridge interface ethernet address
    BriIifhwaddr,
    Other(u32),
}

impl From<MetaKey> for u32 {
    fn from(key: MetaKey) -> Self {
        match key {
            MetaKey::Length => NFT_META_LEN,
            MetaKey::EtherTypeProtocol => NFT_META_PROTOCOL,
            MetaKey::Priority => NFT_META_PRIORITY,
            MetaKey::Mark => NFT_META_MARK,
            MetaKey::Iif => NFT_META_IIF,
            MetaKey::Oif => NFT_META_OIF,
            MetaKey::Iifname => NFT_META_IIFNAME,
            MetaKey::Oifname => NFT_META_OIFNAME,
            MetaKey::Iftype => NFT_META_IFTYPE,
            MetaKey::Oiftype => NFT_META_OIFTYPE,
            MetaKey::SocketUserId => NFT_META_SKUID,
            MetaKey::SocketGroupId => NFT_META_SKGID,
            MetaKey::NftraceBit => NFT_META_NFTRACE,
            MetaKey::Rtclassid => NFT_META_RTCLASSID,
            MetaKey::Secmark => NFT_META_SECMARK,
            MetaKey::Nfproto => NFT_META_NFPROTO,
            MetaKey::L4Proto => NFT_META_L4PROTO,
            MetaKey::BriIifname => NFT_META_BRI_IIFNAME,
            MetaKey::BriOifname => NFT_META_BRI_OIFNAME,
            MetaKey::PacketType => NFT_META_PKTTYPE,
            MetaKey::Cpu => NFT_META_CPU,
            MetaKey::Iifgroup => NFT_META_IIFGROUP,
            MetaKey::Oifgroup => NFT_META_OIFGROUP,
            MetaKey::Cgroup => NFT_META_CGROUP,
            MetaKey::PseudoRandom => NFT_META_PRANDOM,
            MetaKey::Secpath => NFT_META_SECPATH,
            MetaKey::Iifkind => NFT_META_IIFKIND,
            MetaKey::Oifkind => NFT_META_OIFKIND,
            MetaKey::BriIifpvid => NFT_META_BRI_IIFPVID,
            MetaKey::BriIifvproto => NFT_META_BRI_IIFVPROTO,
            MetaKey::TimeNs => NFT_META_TIME_NS,
            MetaKey::TimeDay => NFT_META_TIME_DAY,
            MetaKey::TimeHour => NFT_META_TIME_HOUR,
            MetaKey::Sdif => NFT_META_SDIF,
            MetaKey::Sdifname => NFT_META_SDIFNAME,
            MetaKey::BriBroute => NFT_META_BRI_BROUTE,
            MetaKey::BriIifhwaddr => NFT_META_BRI_IIFHWADDR,
            MetaKey::Other(key_num) => key_num,
        }
    }
}

impl From<u32> for MetaKey {
    fn from(key_num: u32) -> Self {
        match key_num {
            NFT_META_LEN => MetaKey::Length,
            NFT_META_PROTOCOL => MetaKey::EtherTypeProtocol,
            NFT_META_PRIORITY => MetaKey::Priority,
            NFT_META_MARK => MetaKey::Mark,
            NFT_META_IIF => MetaKey::Iif,
            NFT_META_OIF => MetaKey::Oif,
            NFT_META_IIFNAME => MetaKey::Iifname,
            NFT_META_OIFNAME => MetaKey::Oifname,
            NFT_META_IFTYPE => MetaKey::Iftype,
            NFT_META_OIFTYPE => MetaKey::Oiftype,
            NFT_META_SKUID => MetaKey::SocketUserId,
            NFT_META_SKGID => MetaKey::SocketGroupId,
            NFT_META_NFTRACE => MetaKey::NftraceBit,
            NFT_META_RTCLASSID => MetaKey::Rtclassid,
            NFT_META_SECMARK => MetaKey::Secmark,
            NFT_META_NFPROTO => MetaKey::Nfproto,
            NFT_META_L4PROTO => MetaKey::L4Proto,
            NFT_META_BRI_IIFNAME => MetaKey::BriIifname,
            NFT_META_BRI_OIFNAME => MetaKey::BriOifname,
            NFT_META_PKTTYPE => MetaKey::PacketType,
            NFT_META_CPU => MetaKey::Cpu,
            NFT_META_IIFGROUP => MetaKey::Iifgroup,
            NFT_META_OIFGROUP => MetaKey::Oifgroup,
            NFT_META_CGROUP => MetaKey::Cgroup,
            NFT_META_PRANDOM => MetaKey::PseudoRandom,
            NFT_META_SECPATH => MetaKey::Secpath,
            NFT_META_IIFKIND => MetaKey::Iifkind,
            NFT_META_OIFKIND => MetaKey::Oifkind,
            NFT_META_BRI_IIFPVID => MetaKey::BriIifpvid,
            NFT_META_BRI_IIFVPROTO => MetaKey::BriIifvproto,
            NFT_META_TIME_NS => MetaKey::TimeNs,
            NFT_META_TIME_DAY => MetaKey::TimeDay,
            NFT_META_TIME_HOUR => MetaKey::TimeHour,
            NFT_META_SDIF => MetaKey::Sdif,
            NFT_META_SDIFNAME => MetaKey::Sdifname,
            NFT_META_BRI_BROUTE => MetaKey::BriBroute,
            NFT_META_BRI_IIFHWADDR => MetaKey::BriIifhwaddr,
            key_num => MetaKey::Other(key_num),
        }
    }
}

const NFTA_META_UNSPEC: u16 = 0;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_META_SREG: u16 = 3;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Meta {
    Unspecified,
    DestinationRegister(Register),
    Key(MetaKey),
    SourceRegister(Register),
    Other(DefaultNla),
}

impl Nla for Meta {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_META_UNSPEC,
            Self::DestinationRegister(_) => NFTA_META_DREG,
            Self::Key(_) => NFTA_META_KEY,
            Self::SourceRegister(_) => NFTA_META_SREG,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::DestinationRegister(reg) | Self::SourceRegister(reg) => {
                append_u32_be(out, (*reg).into())
            }
            Self::Key(value) => append_u32_be(out, (*value).into()),
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for Meta {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_META_UNSPEC => Self::Unspecified,
            NFTA_META_DREG => Self::DestinationRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_META_DREG value")?
                    .into(),
            ),
            NFTA_META_KEY => Self::Key(
                parse_u32_be(payload)
                    .context("invalid NFTA_META_KEY value")?
                    .into(),
            ),
            NFTA_META_SREG => Self::SourceRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_META_SREG value")?
                    .into(),
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
