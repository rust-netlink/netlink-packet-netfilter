// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_u32_be, parse_string, parse_u32_be, DecodeError, DefaultNla,
    Emitable, ErrorContext as _, Nla, NlaBuffer, Parseable, NLA_F_NESTED,
};

use crate::nftables::{
    attributes::{list::VecListAttribute, ListAttribute},
    set_element::SetElementAttribute,
};
use netlink_packet_core::{append_bytes, EncodeError};

const NFTA_SET_ELEM_LIST_UNSPEC: u16 = 0;
const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
const NFTA_SET_ELEM_LIST_SET_ID: u16 = 4;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum SetElementList {
    Unspecified,
    /// Table of the set to be changed.
    Table(String),
    /// Name of the set to be changed.
    Set(String),
    Elements(Vec<ListAttribute<SetElementAttribute>>),
    /// Uniquely identifies a set in a transaction.
    SetId(u32),
    Other(DefaultNla),
}

impl Nla for SetElementList {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_SET_ELEM_LIST_UNSPEC,
            Self::Table(_) => NFTA_SET_ELEM_LIST_TABLE,
            Self::Set(_) => NFTA_SET_ELEM_LIST_SET,
            Self::Elements(_) => NFTA_SET_ELEM_LIST_ELEMENTS | NLA_F_NESTED,
            Self::SetId(_) => NFTA_SET_ELEM_LIST_SET_ID,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::Table(string) | Self::Set(string) => {
                append_bytes(out, string.as_bytes());
                out.push(0);
            }
            Self::Elements(elems) => elems.as_slice().emit(out)?,
            Self::SetId(value) => append_u32_be(out, *value),
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Elements(_)) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for SetElementList {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_SET_ELEM_LIST_UNSPEC => Self::Unspecified,
            NFTA_SET_ELEM_LIST_TABLE => Self::Table(
                parse_string(payload)
                    .context("invalid NFTA_SET_ELEM_LIST_TABLE value")?,
            ),
            NFTA_SET_ELEM_LIST_SET => Self::Set(
                parse_string(payload)
                    .context("invalid NFTA_SET_ELEM_LIST_SET value")?,
            ),
            NFTA_SET_ELEM_LIST_ELEMENTS => Self::Elements(
                VecListAttribute::parse(payload)
                    .context("invalid NFTA_SET_ELEM_LIST_ELEMENTS value")?
                    .0,
            ),
            NFTA_SET_ELEM_LIST_SET_ID => Self::SetId(
                parse_u32_be(payload)
                    .context("invalid NFTA_SET_ELEM_LIST_SET_ID value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
