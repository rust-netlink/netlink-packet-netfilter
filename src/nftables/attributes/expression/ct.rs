// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32_be, parse_u32_be, parse_u8, DecodeError, DefaultNla,
    ErrorContext as _, Nla, NlaBuffer, Parseable,
};

use crate::nftables::attributes::expression::Register;

const NFT_CT_STATE: u32 = 0;
const NFT_CT_DIRECTION: u32 = 1;
const NFT_CT_STATUS: u32 = 2;
const NFT_CT_MARK: u32 = 3;
const NFT_CT_SECMARK: u32 = 4;
const NFT_CT_EXPIRATION: u32 = 5;
const NFT_CT_HELPER: u32 = 6;
const NFT_CT_L3PROTOCOL: u32 = 7;
const NFT_CT_SRC: u32 = 8;
const NFT_CT_DST: u32 = 9;
const NFT_CT_PROTOCOL: u32 = 10;
const NFT_CT_PROTO_SRC: u32 = 11;
const NFT_CT_PROTO_DST: u32 = 12;
const NFT_CT_LABELS: u32 = 13;
const NFT_CT_PKTS: u32 = 14;
const NFT_CT_BYTES: u32 = 15;
const NFT_CT_AVGPKT: u32 = 16;
const NFT_CT_ZONE: u32 = 17;
const NFT_CT_EVENTMASK: u32 = 18;
const NFT_CT_SRC_IP: u32 = 19;
const NFT_CT_DST_IP: u32 = 20;
const NFT_CT_SRC_IP6: u32 = 21;
const NFT_CT_DST_IP6: u32 = 22;
const NFT_CT_ID: u32 = 23;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum CtKey {
    /// Conntrack state (bitmask of enum ip_conntrack_info)
    State,
    /// Conntrack direction (enum ip_conntrack_dir)
    Direction,
    /// Conntrack status (bitmask of enum ip_conntrack_status)
    Status,
    Mark,
    Secmark,
    /// Relative conntrack expiration time in ms
    Expiration,
    /// Connection tracking helper assigned to conntrack
    Helper,
    L3Protocol,
    /// Layer 3 source address (IPv4/IPv6, deprecated)
    Src,
    /// Layer 3 destination address (IPv4/IPv6, deprecated)
    Dst,
    /// Layer 4 protocol number
    Protocol,
    /// Layer 4 source port
    ProtoSrc,
    /// Layer 4 destination port
    ProtoDst,
    Labels,
    Packets,
    Bytes,
    /// Average bytes per packet
    AvgPacket,
    Zone,
    /// ctnetlink events to be generated for this conntrack
    EventMask,
    /// Layer 3 source address (IPv4)
    SrcIp,
    /// Layer 3 destination address (IPv4)
    DstIp,
    /// Layer 3 source address (IPv6)
    SrcIp6,
    /// Layer 3 destination address (IPv6)
    DstIp6,
    Id,
    Other(u32),
}

impl From<CtKey> for u32 {
    fn from(key: CtKey) -> Self {
        match key {
            CtKey::State => NFT_CT_STATE,
            CtKey::Direction => NFT_CT_DIRECTION,
            CtKey::Status => NFT_CT_STATUS,
            CtKey::Mark => NFT_CT_MARK,
            CtKey::Secmark => NFT_CT_SECMARK,
            CtKey::Expiration => NFT_CT_EXPIRATION,
            CtKey::Helper => NFT_CT_HELPER,
            CtKey::L3Protocol => NFT_CT_L3PROTOCOL,
            CtKey::Src => NFT_CT_SRC,
            CtKey::Dst => NFT_CT_DST,
            CtKey::Protocol => NFT_CT_PROTOCOL,
            CtKey::ProtoSrc => NFT_CT_PROTO_SRC,
            CtKey::ProtoDst => NFT_CT_PROTO_DST,
            CtKey::Labels => NFT_CT_LABELS,
            CtKey::Packets => NFT_CT_PKTS,
            CtKey::Bytes => NFT_CT_BYTES,
            CtKey::AvgPacket => NFT_CT_AVGPKT,
            CtKey::Zone => NFT_CT_ZONE,
            CtKey::EventMask => NFT_CT_EVENTMASK,
            CtKey::SrcIp => NFT_CT_SRC_IP,
            CtKey::DstIp => NFT_CT_DST_IP,
            CtKey::SrcIp6 => NFT_CT_SRC_IP6,
            CtKey::DstIp6 => NFT_CT_DST_IP6,
            CtKey::Id => NFT_CT_ID,
            CtKey::Other(key_num) => key_num,
        }
    }
}

impl From<u32> for CtKey {
    fn from(key_num: u32) -> Self {
        match key_num {
            NFT_CT_STATE => CtKey::State,
            NFT_CT_DIRECTION => CtKey::Direction,
            NFT_CT_STATUS => CtKey::Status,
            NFT_CT_MARK => CtKey::Mark,
            NFT_CT_SECMARK => CtKey::Secmark,
            NFT_CT_EXPIRATION => CtKey::Expiration,
            NFT_CT_HELPER => CtKey::Helper,
            NFT_CT_L3PROTOCOL => CtKey::L3Protocol,
            NFT_CT_SRC => CtKey::Src,
            NFT_CT_DST => CtKey::Dst,
            NFT_CT_PROTOCOL => CtKey::Protocol,
            NFT_CT_PROTO_SRC => CtKey::ProtoSrc,
            NFT_CT_PROTO_DST => CtKey::ProtoDst,
            NFT_CT_LABELS => CtKey::Labels,
            NFT_CT_PKTS => CtKey::Packets,
            NFT_CT_BYTES => CtKey::Bytes,
            NFT_CT_AVGPKT => CtKey::AvgPacket,
            NFT_CT_ZONE => CtKey::Zone,
            NFT_CT_EVENTMASK => CtKey::EventMask,
            NFT_CT_SRC_IP => CtKey::SrcIp,
            NFT_CT_DST_IP => CtKey::DstIp,
            NFT_CT_SRC_IP6 => CtKey::SrcIp6,
            NFT_CT_DST_IP6 => CtKey::DstIp6,
            NFT_CT_ID => CtKey::Id,
            key_num => CtKey::Other(key_num),
        }
    }
}

// Defined in Linux kernel:
// include/uapi/linux/netfilter/nf_conntrack_tuple_common.h
const IP_CT_DIR_ORIGINAL: u8 = 0;
const IP_CT_DIR_REPLY: u8 = 1;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum CtDirection {
    Original,
    Reply,
    Other(u8),
}

impl From<CtDirection> for u8 {
    fn from(dir: CtDirection) -> Self {
        match dir {
            CtDirection::Original => IP_CT_DIR_ORIGINAL,
            CtDirection::Reply => IP_CT_DIR_REPLY,
            CtDirection::Other(num) => num,
        }
    }
}

impl From<u8> for CtDirection {
    fn from(num: u8) -> Self {
        match num {
            IP_CT_DIR_ORIGINAL => Self::Original,
            IP_CT_DIR_REPLY => Self::Reply,
            _ => Self::Other(num),
        }
    }
}

const NFTA_CT_UNSPEC: u16 = 0;
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const NFTA_CT_DIRECTION: u16 = 3;
const NFTA_CT_SREG: u16 = 4;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Ct {
    Unspecified,
    DestinationRegister(Register),
    /// Conntrack data item to load.
    Key(CtKey),
    /// Direction for the directional keys (addresses, ports, packet and byte
    /// counters). Omitted when the key is not directional.
    Direction(CtDirection),
    SourceRegister(Register),
    Other(DefaultNla),
}

impl Nla for Ct {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::DestinationRegister(_)
            | Self::Key(_)
            | Self::SourceRegister(_) => 4,
            Self::Direction(_) => 1,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_CT_UNSPEC,
            Self::DestinationRegister(_) => NFTA_CT_DREG,
            Self::Key(_) => NFTA_CT_KEY,
            Self::Direction(_) => NFTA_CT_DIRECTION,
            Self::SourceRegister(_) => NFTA_CT_SREG,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::DestinationRegister(reg) | Self::SourceRegister(reg) => {
                emit_u32_be(buffer, (*reg).into()).unwrap()
            }
            Self::Key(key) => emit_u32_be(buffer, (*key).into()).unwrap(),
            Self::Direction(dir) => buffer[0] = (*dir).into(),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Ct {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_CT_UNSPEC => Self::Unspecified,
            NFTA_CT_DREG => Self::DestinationRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_CT_DREG value")?
                    .into(),
            ),
            NFTA_CT_KEY => Self::Key(
                parse_u32_be(payload)
                    .context("invalid NFTA_CT_KEY value")?
                    .into(),
            ),
            NFTA_CT_DIRECTION => Self::Direction(
                parse_u8(payload)
                    .context("invalid NFTA_CT_DIRECTION value")?
                    .into(),
            ),
            NFTA_CT_SREG => Self::SourceRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_CT_SREG value")?
                    .into(),
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
