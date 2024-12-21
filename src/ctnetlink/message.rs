// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::DefaultNla, DecodeError, Emitable, Parseable, ParseableParametrized,
};

use crate::{
    buffer::NetfilterBuffer,
    constants::{
        IPCTNL_MSG_CT_DELETE, IPCTNL_MSG_CT_GET, IPCTNL_MSG_CT_NEW,
        NFNL_SUBSYS_CTNETLINK,
    },
};

use super::nlas::flow::nla::FlowNla;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CtNetlinkMessage {
    New(Vec<FlowNla>),
    Get(Option<Vec<FlowNla>>),
    Delete(Vec<FlowNla>),
    // GetCrtZero,
    // GetStatsCPU,
    // GetStats,
    // GetDying,
    // GetUnconfirmed,
    Other {
        message_type: u8,
        nlas: Vec<DefaultNla>,
    },
}

impl CtNetlinkMessage {
    pub const SUBSYS: u8 = NFNL_SUBSYS_CTNETLINK;

    pub fn message_type(&self) -> u8 {
        match self {
            CtNetlinkMessage::New(_) => IPCTNL_MSG_CT_NEW,
            CtNetlinkMessage::Get(_) => IPCTNL_MSG_CT_GET,
            CtNetlinkMessage::Delete(_) => IPCTNL_MSG_CT_DELETE,
            CtNetlinkMessage::Other { message_type, .. } => *message_type,
        }
    }
}

impl Emitable for CtNetlinkMessage {
    fn buffer_len(&self) -> usize {
        match self {
            CtNetlinkMessage::New(nlas) => nlas.as_slice().buffer_len(),
            CtNetlinkMessage::Get(nlas) => match nlas {
                Some(nlas) => nlas.as_slice().buffer_len(),
                None => 0,
            },
            CtNetlinkMessage::Delete(nlas) => nlas.as_slice().buffer_len(),
            CtNetlinkMessage::Other { nlas, .. } => {
                nlas.as_slice().buffer_len()
            }
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            CtNetlinkMessage::New(nlas) => nlas.as_slice().emit(buffer),
            CtNetlinkMessage::Get(nlas) => {
                if let Some(nlas) = nlas {
                    nlas.as_slice().emit(buffer);
                }
            }
            CtNetlinkMessage::Delete(nlas) => nlas.as_slice().emit(buffer),
            CtNetlinkMessage::Other { nlas, .. } => {
                nlas.as_slice().emit(buffer)
            }
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NetfilterBuffer<&'a T>, u8> for CtNetlinkMessage
{
    fn parse_with_param(
        buf: &NetfilterBuffer<&'a T>,
        message_type: u8,
    ) -> Result<Self, DecodeError> {
        Ok(match message_type {
            IPCTNL_MSG_CT_NEW => {
                let nlas =
                    buf.parse_all_nlas(|nla_buf| FlowNla::parse(&nla_buf))?;
                CtNetlinkMessage::New(nlas)
            }
            IPCTNL_MSG_CT_GET => {
                if buf.payload().is_empty() {
                    CtNetlinkMessage::Get(None)
                } else {
                    let nlas =
                        buf.parse_all_nlas(|nla_buf| FlowNla::parse(&nla_buf))?;
                    CtNetlinkMessage::Get(Some(nlas))
                }
            }
            IPCTNL_MSG_CT_DELETE => {
                let nlas =
                    buf.parse_all_nlas(|nla_buf| FlowNla::parse(&nla_buf))?;
                CtNetlinkMessage::Delete(nlas)
            }
            _ => CtNetlinkMessage::Other {
                message_type,
                nlas: buf.default_nlas()?,
            },
        })
    }
}
