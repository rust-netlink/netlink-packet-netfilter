// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, NetlinkDeserializable,
    NetlinkHeader, NetlinkPayload, NetlinkSerializable, ParseableParametrized,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    conntrack::ConntrackMessage, nflog::ULogMessage, nftables::NfTablesMessage,
    none::ControlMessage,
};

// NetfilterProtoFamily represents a protocol family in the Netfilter header
// (nfgenmsg).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetfilterProtoFamily {
    Unspec,
    Inet,
    IPv4,
    ARP,
    NetDev,
    Bridge,
    IPv6,
    DECNet,
    Other(u8),
}

const NFPROTO_UNSPEC: u8 = 0;
const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_ARP: u8 = 3;
const NFPROTO_NETDEV: u8 = 5;
const NFPROTO_BRIDGE: u8 = 7;
const NFPROTO_IPV6: u8 = 10;
const NFPROTO_DECNET: u8 = 12;

impl From<NetfilterProtoFamily> for u8 {
    fn from(proto_family: NetfilterProtoFamily) -> Self {
        match proto_family {
            NetfilterProtoFamily::Unspec => NFPROTO_UNSPEC,
            NetfilterProtoFamily::Inet => NFPROTO_INET,
            NetfilterProtoFamily::IPv4 => NFPROTO_IPV4,
            NetfilterProtoFamily::ARP => NFPROTO_ARP,
            NetfilterProtoFamily::NetDev => NFPROTO_NETDEV,
            NetfilterProtoFamily::Bridge => NFPROTO_BRIDGE,
            NetfilterProtoFamily::IPv6 => NFPROTO_IPV6,
            NetfilterProtoFamily::DECNet => NFPROTO_DECNET,
            NetfilterProtoFamily::Other(p) => p,
        }
    }
}

impl From<u8> for NetfilterProtoFamily {
    fn from(proto_family_num: u8) -> Self {
        match proto_family_num {
            NFPROTO_UNSPEC => NetfilterProtoFamily::Unspec,
            NFPROTO_INET => NetfilterProtoFamily::Inet,
            NFPROTO_IPV4 => NetfilterProtoFamily::IPv4,
            NFPROTO_ARP => NetfilterProtoFamily::ARP,
            NFPROTO_NETDEV => NetfilterProtoFamily::NetDev,
            NFPROTO_BRIDGE => NetfilterProtoFamily::Bridge,
            NFPROTO_IPV6 => NetfilterProtoFamily::IPv6,
            NFPROTO_DECNET => NetfilterProtoFamily::DECNet,
            _ => NetfilterProtoFamily::Other(proto_family_num),
        }
    }
}

pub(crate) const NETFILTER_HEADER_LEN: usize = 4;

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub struct NetfilterHeaderBuffer {
    family: u8,
    version: u8,
    res_id: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetfilterHeader {
    pub family: NetfilterProtoFamily,
    pub version: u8,
    pub res_id: u16,
}

impl NetfilterHeader {
    pub fn new(family: NetfilterProtoFamily, version: u8, res_id: u16) -> Self {
        Self {
            family,
            version,
            res_id,
        }
    }

    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) = NetfilterHeaderBuffer::ref_from_prefix(payload)
            .map_err(|_| {
                DecodeError::buffer_too_small(
                    payload.len(),
                    NETFILTER_HEADER_LEN,
                )
            })?;
        Ok(Self {
            family: raw.family.into(),
            version: raw.version,
            res_id: u16::from_be(raw.res_id),
        })
    }
}

impl From<&NetfilterHeader> for NetfilterHeaderBuffer {
    fn from(header: &NetfilterHeader) -> Self {
        Self {
            family: header.family.into(),
            version: header.version,
            res_id: header.res_id.to_be(),
        }
    }
}

impl Emitable for NetfilterHeader {
    fn buffer_len(&self) -> usize {
        NETFILTER_HEADER_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let raw = NetfilterHeaderBuffer::from(self);
        buf[..NETFILTER_HEADER_LEN].copy_from_slice(raw.as_bytes());
    }
}

// Defined in Linux kernel: include/uapi/linux/netfilter/nfnetlink.h
const NFNL_SUBSYS_NONE: u8 = 0;
const NFNL_SUBSYS_CTNETLINK: u8 = 1;
const NFNL_SUBSYS_ULOG: u8 = 4;
const NFNL_SUBSYS_NFTABLES: u8 = 10;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum NetfilterSubsystem {
    None,
    ULog,
    Conntrack,
    NfTables,
    Other(u8),
}

impl From<u8> for NetfilterSubsystem {
    fn from(value: u8) -> Self {
        match value {
            NFNL_SUBSYS_NONE => Self::None,
            NFNL_SUBSYS_ULOG => Self::ULog,
            NFNL_SUBSYS_CTNETLINK => Self::Conntrack,
            NFNL_SUBSYS_NFTABLES => Self::NfTables,
            v => Self::Other(v),
        }
    }
}

impl From<NetfilterSubsystem> for u8 {
    fn from(value: NetfilterSubsystem) -> Self {
        match value {
            NetfilterSubsystem::None => NFNL_SUBSYS_NONE,
            NetfilterSubsystem::ULog => NFNL_SUBSYS_ULOG,
            NetfilterSubsystem::Conntrack => NFNL_SUBSYS_CTNETLINK,
            NetfilterSubsystem::NfTables => NFNL_SUBSYS_NFTABLES,
            NetfilterSubsystem::Other(v) => v,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum NetfilterMessageInner {
    None(ControlMessage),
    ULog(ULogMessage),
    Conntrack(ConntrackMessage),
    NfTables(NfTablesMessage),
    Other {
        subsys: NetfilterSubsystem,
        message_type: u8,
        attributes: Vec<DefaultNla>,
    },
}

impl From<ULogMessage> for NetfilterMessageInner {
    fn from(message: ULogMessage) -> Self {
        Self::ULog(message)
    }
}

impl From<ConntrackMessage> for NetfilterMessageInner {
    fn from(message: ConntrackMessage) -> Self {
        Self::Conntrack(message)
    }
}

impl From<NfTablesMessage> for NetfilterMessageInner {
    fn from(message: NfTablesMessage) -> Self {
        Self::NfTables(message)
    }
}

impl From<ControlMessage> for NetfilterMessageInner {
    fn from(message: ControlMessage) -> Self {
        Self::None(message)
    }
}

impl Emitable for NetfilterMessageInner {
    fn buffer_len(&self) -> usize {
        match self {
            NetfilterMessageInner::None(message) => message.buffer_len(),
            NetfilterMessageInner::ULog(message) => message.buffer_len(),
            NetfilterMessageInner::Conntrack(message) => message.buffer_len(),
            NetfilterMessageInner::NfTables(message) => message.buffer_len(),
            NetfilterMessageInner::Other { attributes, .. } => {
                attributes.as_slice().buffer_len()
            }
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            NetfilterMessageInner::None(message) => message.emit(buffer),
            NetfilterMessageInner::ULog(message) => message.emit(buffer),
            NetfilterMessageInner::Conntrack(message) => message.emit(buffer),
            NetfilterMessageInner::NfTables(message) => message.emit(buffer),
            NetfilterMessageInner::Other { attributes, .. } => {
                attributes.as_slice().emit(buffer)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct NetfilterMessage {
    pub header: NetfilterHeader,
    pub inner: NetfilterMessageInner,
}

impl NetfilterMessage {
    pub fn new<T: Into<NetfilterMessageInner>>(
        header: NetfilterHeader,
        inner: T,
    ) -> Self {
        Self {
            header,
            inner: inner.into(),
        }
    }

    pub fn subsys(&self) -> NetfilterSubsystem {
        match self.inner {
            NetfilterMessageInner::None(_) => NetfilterSubsystem::None,
            NetfilterMessageInner::ULog(_) => NetfilterSubsystem::ULog,
            NetfilterMessageInner::Conntrack(_) => {
                NetfilterSubsystem::Conntrack
            }
            NetfilterMessageInner::NfTables(_) => NetfilterSubsystem::NfTables,
            NetfilterMessageInner::Other { subsys, .. } => subsys,
        }
    }

    fn message_type(&self) -> u8 {
        match self.inner {
            NetfilterMessageInner::None(ref message) => {
                message.message_type().into()
            }
            NetfilterMessageInner::ULog(ref message) => {
                message.message_type().into()
            }
            NetfilterMessageInner::Conntrack(ref message) => {
                message.message_type().into()
            }
            NetfilterMessageInner::NfTables(ref message) => {
                message.message_type().into()
            }
            NetfilterMessageInner::Other { message_type, .. } => message_type,
        }
    }
}

impl ParseableParametrized<[u8], u16> for NetfilterMessage {
    fn parse_with_param(
        buf: &[u8],
        message_type: u16,
    ) -> Result<Self, DecodeError> {
        let header = NetfilterHeader::parse(buf)
            .context("failed to parse netfilter header")?;
        let subsys = (message_type >> 8) as u8;
        let message_type = message_type as u8;
        let inner = match NetfilterSubsystem::from(subsys) {
            NetfilterSubsystem::None => NetfilterMessageInner::None(
                ControlMessage::parse_with_param(
                    &buf[NETFILTER_HEADER_LEN..],
                    message_type,
                )
                .context("failed to parse nfnetlink control message payload")?,
            ),
            NetfilterSubsystem::ULog => NetfilterMessageInner::ULog(
                ULogMessage::parse_with_param(
                    &buf[NETFILTER_HEADER_LEN..],
                    message_type,
                )
                .context("failed to parse nflog payload")?,
            ),
            NetfilterSubsystem::Conntrack => NetfilterMessageInner::Conntrack(
                ConntrackMessage::parse_with_param(
                    &buf[NETFILTER_HEADER_LEN..],
                    message_type,
                )
                .context("failed to parse conntrack payload")?,
            ),
            NetfilterSubsystem::NfTables => NetfilterMessageInner::NfTables(
                NfTablesMessage::parse_with_param(
                    &buf[NETFILTER_HEADER_LEN..],
                    message_type,
                )
                .context("failed to parse nftables payload")?,
            ),
            subsys_enum @ NetfilterSubsystem::Other(_) => {
                NetfilterMessageInner::Other {
                    subsys: subsys_enum,
                    message_type,
                    attributes: crate::nlas::default_nlas(
                        &buf[NETFILTER_HEADER_LEN..],
                    )?,
                }
            }
        };
        Ok(NetfilterMessage::new(header, inner))
    }
}

impl Emitable for NetfilterMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.inner.buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.inner.emit(&mut buffer[self.header.buffer_len()..]);
    }
}

impl NetlinkSerializable for NetfilterMessage {
    fn message_type(&self) -> u16 {
        ((u8::from(self.subsys()) as u16) << 8) | self.message_type() as u16
    }

    fn buffer_len(&self) -> usize {
        <Self as Emitable>::buffer_len(self)
    }

    fn serialize(&self, buffer: &mut [u8]) {
        self.emit(buffer)
    }
}

impl NetlinkDeserializable for NetfilterMessage {
    type Error = DecodeError;
    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, Self::Error> {
        NetfilterMessage::parse_with_param(payload, header.message_type)
    }
}

impl From<NetfilterMessage> for NetlinkPayload<NetfilterMessage> {
    fn from(message: NetfilterMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}
