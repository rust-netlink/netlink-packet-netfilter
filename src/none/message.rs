// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext as _, ParseableParametrized,
};

use crate::nlas::default_nlas;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum ControlMessage {
    BatchBegin,
    BatchEnd,
    Other {
        message_type: u8,
        attributes: Vec<DefaultNla>,
    },
}

// Defined in Linux kernel: include/uapi/linux/netfilter/nfnetlink.h
const NFNL_MSG_BATCH_BEGIN: u8 = 16;
const NFNL_MSG_BATCH_END: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlMessageType {
    BatchBegin,
    BatchEnd,
    Other(u8),
}

impl From<u8> for ControlMessageType {
    fn from(value: u8) -> Self {
        match value {
            NFNL_MSG_BATCH_BEGIN => Self::BatchBegin,
            NFNL_MSG_BATCH_END => Self::BatchEnd,
            v => Self::Other(v),
        }
    }
}

impl From<ControlMessageType> for u8 {
    fn from(value: ControlMessageType) -> Self {
        match value {
            ControlMessageType::BatchBegin => NFNL_MSG_BATCH_BEGIN,
            ControlMessageType::BatchEnd => NFNL_MSG_BATCH_END,
            ControlMessageType::Other(v) => v,
        }
    }
}

impl ControlMessage {
    pub fn message_type(&self) -> ControlMessageType {
        match self {
            Self::BatchBegin => ControlMessageType::BatchBegin,
            Self::BatchEnd => ControlMessageType::BatchEnd,
            Self::Other { message_type, .. } => (*message_type).into(),
        }
    }
}

impl Emitable for ControlMessage {
    fn buffer_len(&self) -> usize {
        match self {
            Self::BatchBegin | Self::BatchEnd => 0,
            Self::Other { attributes, .. } => {
                attributes.as_slice().buffer_len()
            }
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            Self::BatchBegin | Self::BatchEnd => {}
            Self::Other { attributes, .. } => {
                attributes.as_slice().emit(buffer)
            }
        }
    }
}

impl ParseableParametrized<[u8], u8> for ControlMessage {
    fn parse_with_param(
        buf: &[u8],
        message_type: u8,
    ) -> Result<Self, DecodeError> {
        Ok(match ControlMessageType::from(message_type) {
            ControlMessageType::BatchBegin => Self::BatchBegin,
            ControlMessageType::BatchEnd => Self::BatchEnd,
            ControlMessageType::Other(_) => {
                let attributes =
                    default_nlas(buf).context("failed to parse message nla")?;
                Self::Other {
                    message_type,
                    attributes,
                }
            }
        })
    }
}
