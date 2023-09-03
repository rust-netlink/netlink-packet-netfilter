// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::DefaultNla, DecodeError, Emitable, Parseable, ParseableParametrized,
};

use crate::{
    buffer::NetfilterBuffer,
    constants::{
        NFNL_SUBSYS_QUEUE, NFQNL_MSG_CONFIG, NFQNL_MSG_PACKET,
        NFQNL_MSG_VERDICT,
    },
    nfqueue::nlas::{
        config::ConfigNla, packet::PacketNla, verdict::VerdictNla,
    },
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NfQueueMessage {
    Config(Vec<ConfigNla>),
    Packet(Vec<PacketNla>),
    Verdict(Vec<VerdictNla>),
    Other {
        message_type: u8,
        nlas: Vec<DefaultNla>,
    },
}

impl NfQueueMessage {
    pub const SUBSYS: u8 = NFNL_SUBSYS_QUEUE;

    pub fn message_type(&self) -> u8 {
        match self {
            NfQueueMessage::Config(_) => NFQNL_MSG_CONFIG,
            NfQueueMessage::Packet(_) => NFQNL_MSG_PACKET,
            NfQueueMessage::Verdict(_) => NFQNL_MSG_VERDICT,
            NfQueueMessage::Other { message_type, .. } => *message_type,
        }
    }
}

impl Emitable for NfQueueMessage {
    fn buffer_len(&self) -> usize {
        match self {
            NfQueueMessage::Config(nlas) => nlas.as_slice().buffer_len(),
            NfQueueMessage::Packet(nlas) => nlas.as_slice().buffer_len(),
            NfQueueMessage::Verdict(nlas) => nlas.as_slice().buffer_len(),
            NfQueueMessage::Other { nlas, .. } => nlas.as_slice().buffer_len(),
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            NfQueueMessage::Config(nlas) => nlas.as_slice().emit(buffer),
            NfQueueMessage::Packet(nlas) => nlas.as_slice().emit(buffer),
            NfQueueMessage::Verdict(nlas) => nlas.as_slice().emit(buffer),
            NfQueueMessage::Other { nlas, .. } => nlas.as_slice().emit(buffer),
        };
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NetfilterBuffer<&'a T>, u8> for NfQueueMessage
{
    fn parse_with_param(
        buffer: &NetfilterBuffer<&'a T>,
        message_type: u8,
    ) -> Result<Self, DecodeError> {
        match message_type {
            NFQNL_MSG_CONFIG => {
                match buffer.parse_all_nlas(|nla| ConfigNla::parse(&nla)) {
                    Ok(nlas) => Ok(NfQueueMessage::Config(nlas)),
                    Err(error) => Err(error),
                }
            }
            NFQNL_MSG_PACKET => {
                match buffer.parse_all_nlas(|nla| PacketNla::parse(&nla)) {
                    Ok(nlas) => Ok(NfQueueMessage::Packet(nlas)),
                    Err(error) => Err(error),
                }
            }
            NFQNL_MSG_VERDICT => {
                match buffer.parse_all_nlas(|nla| VerdictNla::parse(&nla)) {
                    Ok(nlas) => Ok(NfQueueMessage::Verdict(nlas)),
                    Err(error) => Err(error),
                }
            }
            _ => match buffer.default_nlas() {
                Ok(nlas) => Ok(NfQueueMessage::Other { message_type, nlas }),
                Err(error) => Err(error),
            },
        }
    }
}
