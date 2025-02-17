// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::DefaultNla, DecodeError, Emitable, Parseable, ParseableParametrized,
};

use crate::{
    buffer::NetfilterBuffer,
    constants::{
        IPCTNL_MSG_CT_DELETE, IPCTNL_MSG_CT_NEW, NFNL_SUBSYS_CTNETLINK,
    },
    nfconntrack::nlas::ConnectionNla,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NfConntrackMessage {
    ConnectionNew(Vec<ConnectionNla>),
    ConnectionDelete(Vec<ConnectionNla>),
    Other {
        message_type: u8,
        nlas: Vec<DefaultNla>,
    },
}

impl NfConntrackMessage {
    pub const SUBSYS: u8 = NFNL_SUBSYS_CTNETLINK;

    pub fn message_type(&self) -> u8 {
        match self {
            NfConntrackMessage::ConnectionNew(_) => IPCTNL_MSG_CT_NEW,
            NfConntrackMessage::ConnectionDelete(_) => IPCTNL_MSG_CT_DELETE,
            NfConntrackMessage::Other { message_type, .. } => *message_type,
        }
    }
}

impl Emitable for NfConntrackMessage {
    fn buffer_len(&self) -> usize {
        match self {
            NfConntrackMessage::ConnectionNew(nlas)
            | NfConntrackMessage::ConnectionDelete(nlas) => {
                nlas.as_slice().buffer_len()
            }
            NfConntrackMessage::Other { nlas, .. } => {
                nlas.as_slice().buffer_len()
            }
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            NfConntrackMessage::ConnectionNew(nlas)
            | NfConntrackMessage::ConnectionDelete(nlas) => {
                nlas.as_slice().emit(buffer)
            }
            NfConntrackMessage::Other { nlas, .. } => {
                nlas.as_slice().emit(buffer)
            }
        };
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NetfilterBuffer<&'a T>, u8> for NfConntrackMessage
{
    fn parse_with_param(
        buf: &NetfilterBuffer<&'a T>,
        message_type: u8,
    ) -> Result<Self, DecodeError> {
        Ok(match message_type {
            IPCTNL_MSG_CT_NEW => {
                let nlas = buf
                    .parse_all_nlas(|nla_buf| ConnectionNla::parse(&nla_buf))?;
                NfConntrackMessage::ConnectionNew(nlas)
            }
            IPCTNL_MSG_CT_DELETE => {
                let nlas = buf
                    .parse_all_nlas(|nla_buf| ConnectionNla::parse(&nla_buf))?;
                NfConntrackMessage::ConnectionDelete(nlas)
            }
            _ => NfConntrackMessage::Other {
                message_type,
                nlas: buf.default_nlas()?,
            },
        })
    }
}
