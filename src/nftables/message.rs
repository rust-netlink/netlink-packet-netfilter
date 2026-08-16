// SPDX-License-Identifier: MIT

use crate::nftables::{
    chain::ChainMessage, r#gen::GenMessage, rule::RuleMessage, set::SetMessage,
    set_element::SetElementMessage, table::TableMessage,
};
use crate::nlas::default_nlas;

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext as _, Parseable,
    ParseableParametrized,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum NfTablesMessage {
    NewTable(TableMessage),
    GetTable(TableMessage),
    DeleteTable(TableMessage),
    NewChain(ChainMessage),
    GetChain(ChainMessage),
    DeleteChain(ChainMessage),
    NewRule(RuleMessage),
    GetRule(RuleMessage),
    DeleteRule(RuleMessage),
    NewSet(SetMessage),
    GetSet(SetMessage),
    DeleteSet(SetMessage),
    NewSetElement(SetElementMessage),
    GetSetElement(SetElementMessage),
    DeleteSetElement(SetElementMessage),
    NewGen(GenMessage),
    GetGen(GenMessage),
    Trace(Vec<DefaultNla>),
    NewObject(Vec<DefaultNla>),
    GetObject(Vec<DefaultNla>),
    DeleteObject(Vec<DefaultNla>),
    NewFlowTable(Vec<DefaultNla>),
    GetFlowTable(Vec<DefaultNla>),
    DeleteFlowTable(Vec<DefaultNla>),
    Other {
        message_type: u8,
        attributes: Vec<DefaultNla>,
    },
}

// Defined in Linux kernel: include/uapi/linux/netfilter/nf_tables.h
const NFT_MSG_NEWTABLE: u8 = 0;
const NFT_MSG_GETTABLE: u8 = 1;
const NFT_MSG_DELTABLE: u8 = 2;
const NFT_MSG_NEWCHAIN: u8 = 3;
const NFT_MSG_GETCHAIN: u8 = 4;
const NFT_MSG_DELCHAIN: u8 = 5;
const NFT_MSG_NEWRULE: u8 = 6;
const NFT_MSG_GETRULE: u8 = 7;
const NFT_MSG_DELRULE: u8 = 8;
const NFT_MSG_NEWSET: u8 = 9;
const NFT_MSG_GETSET: u8 = 10;
const NFT_MSG_DELSET: u8 = 11;
const NFT_MSG_NEWSETELEM: u8 = 12;
const NFT_MSG_GETSETELEM: u8 = 13;
const NFT_MSG_DELSETELEM: u8 = 14;
const NFT_MSG_NEWGEN: u8 = 15;
const NFT_MSG_GETGEN: u8 = 16;
const NFT_MSG_TRACE: u8 = 17;
const NFT_MSG_NEWOBJ: u8 = 18;
const NFT_MSG_GETOBJ: u8 = 19;
const NFT_MSG_DELOBJ: u8 = 20;
//const NFT_MSG_GETOBJ_RESET: u8 = 21;
const NFT_MSG_NEWFLOWTABLE: u8 = 22;
const NFT_MSG_GETFLOWTABLE: u8 = 23;
const NFT_MSG_DELFLOWTABLE: u8 = 24;
//const NFT_MSG_GETRULE_RESET: u8 = 25;
//const NFT_MSG_DESTROYTABLE: u8 = 26;
//const NFT_MSG_DESTROYCHAIN: u8 = 27;
//const NFT_MSG_DESTROYRULE: u8 = 28;
//const NFT_MSG_DESTROYSET: u8 = 29;
//const NFT_MSG_DESTROYSETELEM: u8 = 30;
//const NFT_MSG_DESTROYOBJ: u8 = 31;
//const NFT_MSG_DESTROYFLOWTABLE: u8 = 32;
//const NFT_MSG_GETSETELEM_RESET: u8 = 33;
//const NFT_MSG_MAX: u8 = 34;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NfTablesMessageType {
    NewTable,
    GetTable,
    DeleteTable,
    NewChain,
    GetChain,
    DeleteChain,
    NewRule,
    GetRule,
    DeleteRule,
    NewSet,
    GetSet,
    DeleteSet,
    NewSetElement,
    GetSetElement,
    DeleteSetElement,
    NewGen,
    GetGen,
    Trace,
    NewObject,
    GetObject,
    DeleteObject,
    NewFlowTable,
    GetFlowTable,
    DeleteFlowTable,
    Other(u8),
}

impl From<u8> for NfTablesMessageType {
    fn from(value: u8) -> Self {
        match value {
            NFT_MSG_NEWTABLE => Self::NewTable,
            NFT_MSG_GETTABLE => Self::GetTable,
            NFT_MSG_DELTABLE => Self::DeleteTable,
            NFT_MSG_NEWCHAIN => Self::NewChain,
            NFT_MSG_GETCHAIN => Self::GetChain,
            NFT_MSG_DELCHAIN => Self::DeleteChain,
            NFT_MSG_NEWRULE => Self::NewRule,
            NFT_MSG_GETRULE => Self::GetRule,
            NFT_MSG_DELRULE => Self::DeleteRule,
            NFT_MSG_NEWSET => Self::NewSet,
            NFT_MSG_GETSET => Self::GetSet,
            NFT_MSG_DELSET => Self::DeleteSet,
            NFT_MSG_NEWSETELEM => Self::NewSetElement,
            NFT_MSG_GETSETELEM => Self::GetSetElement,
            NFT_MSG_DELSETELEM => Self::DeleteSetElement,
            NFT_MSG_NEWGEN => Self::NewGen,
            NFT_MSG_GETGEN => Self::GetGen,
            NFT_MSG_TRACE => Self::Trace,
            NFT_MSG_NEWOBJ => Self::NewObject,
            NFT_MSG_GETOBJ => Self::GetObject,
            NFT_MSG_DELOBJ => Self::DeleteObject,
            NFT_MSG_NEWFLOWTABLE => Self::NewFlowTable,
            NFT_MSG_GETFLOWTABLE => Self::GetFlowTable,
            NFT_MSG_DELFLOWTABLE => Self::DeleteFlowTable,
            v => Self::Other(v),
        }
    }
}

impl From<NfTablesMessageType> for u8 {
    fn from(value: NfTablesMessageType) -> Self {
        match value {
            NfTablesMessageType::NewTable => NFT_MSG_NEWTABLE,
            NfTablesMessageType::GetTable => NFT_MSG_GETTABLE,
            NfTablesMessageType::DeleteTable => NFT_MSG_DELTABLE,
            NfTablesMessageType::NewChain => NFT_MSG_NEWCHAIN,
            NfTablesMessageType::GetChain => NFT_MSG_GETCHAIN,
            NfTablesMessageType::DeleteChain => NFT_MSG_DELCHAIN,
            NfTablesMessageType::NewRule => NFT_MSG_NEWRULE,
            NfTablesMessageType::GetRule => NFT_MSG_GETRULE,
            NfTablesMessageType::DeleteRule => NFT_MSG_DELRULE,
            NfTablesMessageType::NewSet => NFT_MSG_NEWSET,
            NfTablesMessageType::GetSet => NFT_MSG_GETSET,
            NfTablesMessageType::DeleteSet => NFT_MSG_DELSET,
            NfTablesMessageType::NewSetElement => NFT_MSG_NEWSETELEM,
            NfTablesMessageType::GetSetElement => NFT_MSG_GETSETELEM,
            NfTablesMessageType::DeleteSetElement => NFT_MSG_DELSETELEM,
            NfTablesMessageType::NewGen => NFT_MSG_NEWGEN,
            NfTablesMessageType::GetGen => NFT_MSG_GETGEN,
            NfTablesMessageType::Trace => NFT_MSG_TRACE,
            NfTablesMessageType::NewObject => NFT_MSG_NEWOBJ,
            NfTablesMessageType::GetObject => NFT_MSG_GETOBJ,
            NfTablesMessageType::DeleteObject => NFT_MSG_DELOBJ,
            NfTablesMessageType::NewFlowTable => NFT_MSG_NEWFLOWTABLE,
            NfTablesMessageType::GetFlowTable => NFT_MSG_GETFLOWTABLE,
            NfTablesMessageType::DeleteFlowTable => NFT_MSG_DELFLOWTABLE,
            NfTablesMessageType::Other(v) => v,
        }
    }
}

impl NfTablesMessage {
    pub fn message_type(&self) -> NfTablesMessageType {
        match self {
            Self::NewTable(_) => NfTablesMessageType::NewTable,
            Self::GetTable(_) => NfTablesMessageType::GetTable,
            Self::DeleteTable(_) => NfTablesMessageType::DeleteTable,
            Self::NewChain(_) => NfTablesMessageType::NewChain,
            Self::GetChain(_) => NfTablesMessageType::GetChain,
            Self::DeleteChain(_) => NfTablesMessageType::DeleteChain,
            Self::NewRule(_) => NfTablesMessageType::NewRule,
            Self::GetRule(_) => NfTablesMessageType::GetRule,
            Self::DeleteRule(_) => NfTablesMessageType::DeleteRule,
            Self::NewSet(_) => NfTablesMessageType::NewSet,
            Self::GetSet(_) => NfTablesMessageType::GetSet,
            Self::DeleteSet(_) => NfTablesMessageType::DeleteSet,
            Self::NewSetElement(_) => NfTablesMessageType::NewSetElement,
            Self::GetSetElement(_) => NfTablesMessageType::GetSetElement,
            Self::DeleteSetElement(_) => NfTablesMessageType::DeleteSetElement,
            Self::NewGen(_) => NfTablesMessageType::NewGen,
            Self::GetGen(_) => NfTablesMessageType::GetGen,
            Self::Trace(_) => NfTablesMessageType::Trace,
            Self::NewObject(_) => NfTablesMessageType::NewObject,
            Self::GetObject(_) => NfTablesMessageType::GetObject,
            Self::DeleteObject(_) => NfTablesMessageType::DeleteObject,
            Self::NewFlowTable(_) => NfTablesMessageType::NewFlowTable,
            Self::GetFlowTable(_) => NfTablesMessageType::GetFlowTable,
            Self::DeleteFlowTable(_) => NfTablesMessageType::DeleteFlowTable,
            Self::Other { message_type, .. } => (*message_type).into(),
        }
    }
}

impl Emitable for NfTablesMessage {
    fn buffer_len(&self) -> usize {
        match self {
            NfTablesMessage::NewTable(TableMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::GetTable(TableMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::DeleteTable(TableMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::NewChain(ChainMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::GetChain(ChainMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::DeleteChain(ChainMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::NewRule(RuleMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::GetRule(RuleMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::DeleteRule(RuleMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::NewSet(SetMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::GetSet(SetMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::DeleteSet(SetMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::NewSetElement(SetElementMessage {
                attributes,
            }) => attributes.as_slice().buffer_len(),
            NfTablesMessage::GetSetElement(SetElementMessage {
                attributes,
            }) => attributes.as_slice().buffer_len(),
            NfTablesMessage::DeleteSetElement(SetElementMessage {
                attributes,
            }) => attributes.as_slice().buffer_len(),
            NfTablesMessage::NewGen(GenMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::GetGen(GenMessage { attributes }) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::Trace(attributes) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::NewObject(attributes) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::GetObject(attributes) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::DeleteObject(attributes) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::NewFlowTable(attributes) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::GetFlowTable(attributes) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::DeleteFlowTable(attributes) => {
                attributes.as_slice().buffer_len()
            }
            NfTablesMessage::Other { attributes, .. } => {
                attributes.as_slice().buffer_len()
            }
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            NfTablesMessage::NewTable(TableMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::GetTable(TableMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::DeleteTable(TableMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::NewChain(ChainMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::GetChain(ChainMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::DeleteChain(ChainMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::NewRule(RuleMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::GetRule(RuleMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::DeleteRule(RuleMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::NewSet(SetMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::GetSet(SetMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::DeleteSet(SetMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::NewSetElement(SetElementMessage {
                attributes,
            }) => attributes.as_slice().emit(buffer),
            NfTablesMessage::GetSetElement(SetElementMessage {
                attributes,
            }) => attributes.as_slice().emit(buffer),
            NfTablesMessage::DeleteSetElement(SetElementMessage {
                attributes,
            }) => attributes.as_slice().emit(buffer),
            NfTablesMessage::NewGen(GenMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::GetGen(GenMessage { attributes }) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::Trace(attributes) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::NewObject(attributes) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::GetObject(attributes) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::DeleteObject(attributes) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::NewFlowTable(attributes) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::GetFlowTable(attributes) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::DeleteFlowTable(attributes) => {
                attributes.as_slice().emit(buffer)
            }
            NfTablesMessage::Other { attributes, .. } => {
                attributes.as_slice().emit(buffer)
            }
        };
    }
}

impl ParseableParametrized<[u8], u8> for NfTablesMessage {
    fn parse_with_param(
        buf: &[u8],
        message_type: u8,
    ) -> Result<Self, DecodeError> {
        Ok(match NfTablesMessageType::from(message_type) {
            NfTablesMessageType::NewTable => {
                Self::NewTable(TableMessage::parse(buf)?)
            }
            NfTablesMessageType::GetTable => {
                Self::GetTable(TableMessage::parse(buf)?)
            }
            NfTablesMessageType::DeleteTable => {
                Self::DeleteTable(TableMessage::parse(buf)?)
            }

            NfTablesMessageType::NewChain => {
                Self::NewChain(ChainMessage::parse(buf)?)
            }
            NfTablesMessageType::GetChain => {
                Self::GetChain(ChainMessage::parse(buf)?)
            }
            NfTablesMessageType::DeleteChain => {
                Self::DeleteChain(ChainMessage::parse(buf)?)
            }

            NfTablesMessageType::NewRule => {
                Self::NewRule(RuleMessage::parse(buf)?)
            }
            NfTablesMessageType::GetRule => {
                Self::GetRule(RuleMessage::parse(buf)?)
            }
            NfTablesMessageType::DeleteRule => {
                Self::DeleteRule(RuleMessage::parse(buf)?)
            }

            NfTablesMessageType::NewSet => {
                Self::NewSet(SetMessage::parse(buf)?)
            }
            NfTablesMessageType::GetSet => {
                Self::GetSet(SetMessage::parse(buf)?)
            }
            NfTablesMessageType::DeleteSet => {
                Self::DeleteSet(SetMessage::parse(buf)?)
            }

            NfTablesMessageType::NewSetElement => {
                Self::NewSetElement(SetElementMessage::parse(buf)?)
            }
            NfTablesMessageType::GetSetElement => {
                Self::GetSetElement(SetElementMessage::parse(buf)?)
            }
            NfTablesMessageType::DeleteSetElement => {
                Self::DeleteSetElement(SetElementMessage::parse(buf)?)
            }

            NfTablesMessageType::NewGen => {
                Self::NewGen(GenMessage::parse(buf)?)
            }
            NfTablesMessageType::GetGen => {
                Self::GetGen(GenMessage::parse(buf)?)
            }

            NfTablesMessageType::Trace => NfTablesMessage::Trace(
                default_nlas(buf)
                    .context("failed to parse trace message nla")?,
            ),

            NfTablesMessageType::NewObject => NfTablesMessage::NewObject(
                default_nlas(buf)
                    .context("failed to parse object message nla")?,
            ),
            NfTablesMessageType::GetObject => NfTablesMessage::GetObject(
                default_nlas(buf)
                    .context("failed to parse object message nla")?,
            ),
            NfTablesMessageType::DeleteObject => NfTablesMessage::DeleteObject(
                default_nlas(buf)
                    .context("failed to parse trace object message nla")?,
            ),

            NfTablesMessageType::NewFlowTable => NfTablesMessage::NewFlowTable(
                default_nlas(buf)
                    .context("failed to parse trace flow table message nla")?,
            ),
            NfTablesMessageType::GetFlowTable => NfTablesMessage::GetFlowTable(
                default_nlas(buf)
                    .context("failed to parse trace flow table message nla")?,
            ),
            NfTablesMessageType::DeleteFlowTable => {
                NfTablesMessage::DeleteFlowTable(
                    default_nlas(buf).context(
                        "failed to parse trace flow table message nla",
                    )?,
                )
            }

            NfTablesMessageType::Other(message_type) => {
                let attributes =
                    default_nlas(buf).context("failed to parse message nla")?;
                NfTablesMessage::Other {
                    message_type,
                    attributes,
                }
            }
        })
    }
}
