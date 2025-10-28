// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, Parseable, ParseableParametrized,
};

use crate::{
    buffer::NetfilterBuffer,
    nflog::nlas::{config::ConfigNla, packet::PacketNla},
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ULogMessage {
    Config(Vec<ConfigNla>),
    Packet(Vec<PacketNla>),
    Other {
        message_type: u8,
        nlas: Vec<DefaultNla>,
    },
}

const NFULNL_MSG_CONFIG: u8 = libc::NFULNL_MSG_CONFIG as u8;
const NFULNL_MSG_PACKET: u8 = libc::NFULNL_MSG_PACKET as u8;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum ULogMessageType {
    Config,
    Packet,
    Other(u8),
}

impl From<u8> for ULogMessageType {
    fn from(value: u8) -> Self {
        match value {
            NFULNL_MSG_CONFIG => Self::Config,
            NFULNL_MSG_PACKET => Self::Packet,
            v => Self::Other(v),
        }
    }
}

impl From<ULogMessageType> for u8 {
    fn from(value: ULogMessageType) -> Self {
        match value {
            ULogMessageType::Config => NFULNL_MSG_CONFIG,
            ULogMessageType::Packet => NFULNL_MSG_PACKET,
            ULogMessageType::Other(v) => v,
        }
    }
}

impl ULogMessage {
    pub fn message_type(&self) -> ULogMessageType {
        match self {
            ULogMessage::Config(_) => ULogMessageType::Config,
            ULogMessage::Packet(_) => ULogMessageType::Packet,
            ULogMessage::Other { message_type, .. } => (*message_type).into(),
        }
    }
}

impl Emitable for ULogMessage {
    fn buffer_len(&self) -> usize {
        match self {
            ULogMessage::Config(nlas) => nlas.as_slice().buffer_len(),
            ULogMessage::Packet(nlas) => nlas.as_slice().buffer_len(),
            ULogMessage::Other { nlas, .. } => nlas.as_slice().buffer_len(),
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            ULogMessage::Config(nlas) => nlas.as_slice().emit(buffer),
            ULogMessage::Packet(nlas) => nlas.as_slice().emit(buffer),
            ULogMessage::Other { nlas, .. } => nlas.as_slice().emit(buffer),
        };
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NetfilterBuffer<&'a T>, u8> for ULogMessage
{
    fn parse_with_param(
        buf: &NetfilterBuffer<&'a T>,
        message_type: u8,
    ) -> Result<Self, DecodeError> {
        Ok(match ULogMessageType::from(message_type) {
            ULogMessageType::Config => {
                let nlas =
                    buf.parse_all_nlas(|nla_buf| ConfigNla::parse(&nla_buf))?;
                ULogMessage::Config(nlas)
            }
            ULogMessageType::Packet => {
                let nlas =
                    buf.parse_all_nlas(|nla_buf| PacketNla::parse(&nla_buf))?;
                ULogMessage::Packet(nlas)
            }
            ULogMessageType::Other(message_type) => ULogMessage::Other {
                message_type,
                nlas: buf.default_nlas()?,
            },
        })
    }
}
