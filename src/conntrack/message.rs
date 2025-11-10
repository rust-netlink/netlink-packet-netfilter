// SPDX-License-Identifier: MIT

use crate::{
    buffer::NetfilterBuffer, conntrack::attributes::ConntrackAttribute,
};
use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, Parseable, ParseableParametrized,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum ConntrackMessage {
    New(Vec<ConntrackAttribute>),
    Get(Vec<ConntrackAttribute>),
    Delete(Vec<ConntrackAttribute>),
    Other {
        message_type: u8,
        attributes: Vec<DefaultNla>,
    },
}

const IPCTNL_MSG_CT_NEW: u8 = 0;
const IPCTNL_MSG_CT_GET: u8 = 1;
const IPCTNL_MSG_CT_DELETE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConntrackMessageType {
    New,
    Get,
    Delete,
    Other(u8),
}

impl From<u8> for ConntrackMessageType {
    fn from(value: u8) -> Self {
        match value {
            IPCTNL_MSG_CT_NEW => Self::New,
            IPCTNL_MSG_CT_GET => Self::Get,
            IPCTNL_MSG_CT_DELETE => Self::Delete,
            v => Self::Other(v),
        }
    }
}

impl From<ConntrackMessageType> for u8 {
    fn from(value: ConntrackMessageType) -> Self {
        match value {
            ConntrackMessageType::New => IPCTNL_MSG_CT_NEW,
            ConntrackMessageType::Get => IPCTNL_MSG_CT_GET,
            ConntrackMessageType::Delete => IPCTNL_MSG_CT_DELETE,
            ConntrackMessageType::Other(v) => v,
        }
    }
}

impl ConntrackMessage {
    pub fn message_type(&self) -> ConntrackMessageType {
        match self {
            ConntrackMessage::New(_) => ConntrackMessageType::New,
            ConntrackMessage::Get(_) => ConntrackMessageType::Get,
            ConntrackMessage::Delete(_) => ConntrackMessageType::Delete,
            ConntrackMessage::Other { message_type, .. } => {
                (*message_type).into()
            }
        }
    }
}

impl Emitable for ConntrackMessage {
    fn buffer_len(&self) -> usize {
        match self {
            ConntrackMessage::New(attributes) => {
                attributes.as_slice().buffer_len()
            }
            ConntrackMessage::Get(attributes) => {
                attributes.as_slice().buffer_len()
            }
            ConntrackMessage::Delete(attributes) => {
                attributes.as_slice().buffer_len()
            }
            ConntrackMessage::Other { attributes, .. } => {
                attributes.as_slice().buffer_len()
            }
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            ConntrackMessage::New(attributes) => {
                attributes.as_slice().emit(buffer)
            }
            ConntrackMessage::Get(attributes) => {
                attributes.as_slice().emit(buffer)
            }
            ConntrackMessage::Delete(attributes) => {
                attributes.as_slice().emit(buffer)
            }
            ConntrackMessage::Other { attributes, .. } => {
                attributes.as_slice().emit(buffer)
            }
        };
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NetfilterBuffer<&'a T>, u8> for ConntrackMessage
{
    fn parse_with_param(
        buf: &NetfilterBuffer<&'a T>,
        message_type: u8,
    ) -> Result<Self, DecodeError> {
        Ok(match ConntrackMessageType::from(message_type) {
            ConntrackMessageType::New => {
                let attributes = buf.parse_all_nlas(|nla_buf| {
                    ConntrackAttribute::parse(&nla_buf)
                })?;
                ConntrackMessage::New(attributes)
            }
            ConntrackMessageType::Get => {
                let attributes = buf.parse_all_nlas(|nla_buf| {
                    ConntrackAttribute::parse(&nla_buf)
                })?;
                ConntrackMessage::Get(attributes)
            }
            ConntrackMessageType::Delete => {
                let nlas = buf.parse_all_nlas(|nla_buf| {
                    ConntrackAttribute::parse(&nla_buf)
                })?;
                ConntrackMessage::Delete(nlas)
            }
            ConntrackMessageType::Other(message_type) => {
                ConntrackMessage::Other {
                    message_type,
                    attributes: buf.default_nlas()?,
                }
            }
        })
    }
}
