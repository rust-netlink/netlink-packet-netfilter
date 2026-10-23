// SPDX-License-Identifier: MIT

use bitflags::bitflags;
use netlink_packet_core::{
    emit_u16_be, emit_u32_be, parse_string, parse_u16_be, parse_u32_be,
    DecodeError, DefaultNla, ErrorContext as _, Nla, NlaBuffer, Parseable,
};

const NFT_LOGLEVEL_EMERG: u32 = 0;
const NFT_LOGLEVEL_ALERT: u32 = 1;
const NFT_LOGLEVEL_CRIT: u32 = 2;
const NFT_LOGLEVEL_ERR: u32 = 3;
const NFT_LOGLEVEL_WARNING: u32 = 4;
const NFT_LOGLEVEL_NOTICE: u32 = 5;
const NFT_LOGLEVEL_INFO: u32 = 6;
const NFT_LOGLEVEL_DEBUG: u32 = 7;
const NFT_LOGLEVEL_AUDIT: u32 = 8;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum LogLevel {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
    /// Log to the audit subsystem instead of the kernel log
    Audit,
    Other(u32),
}

impl From<LogLevel> for u32 {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Emergency => NFT_LOGLEVEL_EMERG,
            LogLevel::Alert => NFT_LOGLEVEL_ALERT,
            LogLevel::Critical => NFT_LOGLEVEL_CRIT,
            LogLevel::Error => NFT_LOGLEVEL_ERR,
            LogLevel::Warning => NFT_LOGLEVEL_WARNING,
            LogLevel::Notice => NFT_LOGLEVEL_NOTICE,
            LogLevel::Info => NFT_LOGLEVEL_INFO,
            LogLevel::Debug => NFT_LOGLEVEL_DEBUG,
            LogLevel::Audit => NFT_LOGLEVEL_AUDIT,
            LogLevel::Other(num) => num,
        }
    }
}

impl From<u32> for LogLevel {
    fn from(num: u32) -> Self {
        match num {
            NFT_LOGLEVEL_EMERG => Self::Emergency,
            NFT_LOGLEVEL_ALERT => Self::Alert,
            NFT_LOGLEVEL_CRIT => Self::Critical,
            NFT_LOGLEVEL_ERR => Self::Error,
            NFT_LOGLEVEL_WARNING => Self::Warning,
            NFT_LOGLEVEL_NOTICE => Self::Notice,
            NFT_LOGLEVEL_INFO => Self::Info,
            NFT_LOGLEVEL_DEBUG => Self::Debug,
            NFT_LOGLEVEL_AUDIT => Self::Audit,
            _ => Self::Other(num),
        }
    }
}

// Defined in Linux kernel: include/uapi/linux/netfilter/nf_log.h
const NF_LOG_TCPSEQ: u32 = 0x01;
const NF_LOG_TCPOPT: u32 = 0x02;
const NF_LOG_IPOPT: u32 = 0x04;
const NF_LOG_UID: u32 = 0x08;
const NF_LOG_MACDECODE: u32 = 0x20;

bitflags! {
    #[derive(Clone, Eq, PartialEq, Debug, Copy, Default)]
    #[non_exhaustive]
    pub struct LogFlags: u32 {
        /// Log TCP sequence numbers
        const TcpSequence = NF_LOG_TCPSEQ;
        /// Log TCP options
        const TcpOptions = NF_LOG_TCPOPT;
        /// Log IP options
        const IpOptions = NF_LOG_IPOPT;
        /// Log UID owning local socket
        const Uid = NF_LOG_UID;
        /// Decode MAC header
        const MacDecode = NF_LOG_MACDECODE;
        const _ = !0;
    }
}

const NFTA_LOG_UNSPEC: u16 = 0;
const NFTA_LOG_GROUP: u16 = 1;
const NFTA_LOG_PREFIX: u16 = 2;
const NFTA_LOG_SNAPLEN: u16 = 3;
const NFTA_LOG_QTHRESHOLD: u16 = 4;
const NFTA_LOG_LEVEL: u16 = 5;
const NFTA_LOG_FLAGS: u16 = 6;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Log {
    Unspecified,
    /// NFLOG group to send packets to; selects nfnetlink_log over the kernel
    /// log.
    Group(u16),
    /// Prefix to prepend to log messages.
    Prefix(String),
    /// Length of payload to include in the netlink message.
    Snaplen(u32),
    /// Number of packets queued in the kernel before they are sent.
    QueueThreshold(u16),
    Level(LogLevel),
    Flags(LogFlags),
    Other(DefaultNla),
}

impl Nla for Log {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::Group(_) | Self::QueueThreshold(_) => 2,
            Self::Prefix(string) => string.len() + 1,
            Self::Snaplen(_) | Self::Level(_) | Self::Flags(_) => 4,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_LOG_UNSPEC,
            Self::Group(_) => NFTA_LOG_GROUP,
            Self::Prefix(_) => NFTA_LOG_PREFIX,
            Self::Snaplen(_) => NFTA_LOG_SNAPLEN,
            Self::QueueThreshold(_) => NFTA_LOG_QTHRESHOLD,
            Self::Level(_) => NFTA_LOG_LEVEL,
            Self::Flags(_) => NFTA_LOG_FLAGS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::Group(value) | Self::QueueThreshold(value) => {
                emit_u16_be(buffer, *value).unwrap()
            }
            Self::Prefix(string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }
            Self::Snaplen(value) => emit_u32_be(buffer, *value).unwrap(),
            Self::Level(level) => emit_u32_be(buffer, (*level).into()).unwrap(),
            Self::Flags(flags) => emit_u32_be(buffer, flags.bits()).unwrap(),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Log {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_LOG_UNSPEC => Self::Unspecified,
            NFTA_LOG_GROUP => Self::Group(
                parse_u16_be(payload)
                    .context("invalid NFTA_LOG_GROUP value")?,
            ),
            NFTA_LOG_PREFIX => Self::Prefix(
                parse_string(payload)
                    .context("invalid NFTA_LOG_PREFIX value")?,
            ),
            NFTA_LOG_SNAPLEN => Self::Snaplen(
                parse_u32_be(payload)
                    .context("invalid NFTA_LOG_SNAPLEN value")?,
            ),
            NFTA_LOG_QTHRESHOLD => Self::QueueThreshold(
                parse_u16_be(payload)
                    .context("invalid NFTA_LOG_QTHRESHOLD value")?,
            ),
            NFTA_LOG_LEVEL => Self::Level(
                parse_u32_be(payload)
                    .context("invalid NFTA_LOG_LEVEL value")?
                    .into(),
            ),
            NFTA_LOG_FLAGS => Self::Flags(LogFlags::from_bits_retain(
                parse_u32_be(payload)
                    .context("invalid NFTA_LOG_FLAGS value")?,
            )),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
