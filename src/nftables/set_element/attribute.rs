// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_u32_be, append_u64_be, parse_string, parse_u32_be, parse_u64_be,
    DecodeError, DefaultNla, Emitable, ErrorContext as _, Nla, NlaBuffer,
    NlasIterator, Parseable, ParseableParametrized as _, NLA_F_NESTED,
};

use crate::nftables::{
    attributes::{
        list::VecListAttribute, DataAttribute, ExpressionAttribute,
        ListAttribute,
    },
    set_element::SetElementFlags,
};
use netlink_packet_core::{append_bytes, EncodeError};

// Defined in Linux kernel: include/uapi/linux/netfilter/nf_tables.h
const NFTA_SET_ELEM_UNSPEC: u16 = 0;
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_DATA: u16 = 2;
const NFTA_SET_ELEM_FLAGS: u16 = 3;
const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
const NFTA_SET_ELEM_EXPIRATION: u16 = 5;
const NFTA_SET_ELEM_USERDATA: u16 = 6;
const NFTA_SET_ELEM_EXPR: u16 = 7;
//const NFTA_SET_ELEM_PAD: u16 = 8;
const NFTA_SET_ELEM_OBJREF: u16 = 9;
const NFTA_SET_ELEM_KEY_END: u16 = 10;
const NFTA_SET_ELEM_EXPRESSIONS: u16 = 11;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum SetElementAttribute {
    Unspecified,
    /// Key value.
    Key(DataAttribute),
    /// Data value of mapping.
    Data(DataAttribute),
    Flags(SetElementFlags),
    /// Timeout value.
    ///
    /// Zero means never times out.
    Timeout(u64),
    Expiration(u64),
    UserData(Vec<u8>),
    Expression(ExpressionAttribute),
    /// Stateful object refrence.
    ObjectRefrence(String),
    // Closing key value
    KeyEnd(Vec<DefaultNla>),
    ListExpressions(Vec<ListAttribute<ExpressionAttribute>>),
    Other(DefaultNla),
}

impl Nla for SetElementAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_SET_ELEM_UNSPEC,
            Self::Key(_) => NFTA_SET_ELEM_KEY | NLA_F_NESTED,
            Self::Data(_) => NFTA_SET_ELEM_DATA | NLA_F_NESTED,
            Self::Flags(_) => NFTA_SET_ELEM_FLAGS,
            Self::Timeout(_) => NFTA_SET_ELEM_TIMEOUT,
            Self::Expiration(_) => NFTA_SET_ELEM_EXPIRATION,
            Self::UserData(_) => NFTA_SET_ELEM_USERDATA,
            Self::Expression(_) => NFTA_SET_ELEM_EXPR | NLA_F_NESTED,
            Self::ObjectRefrence(_) => NFTA_SET_ELEM_OBJREF,
            Self::KeyEnd(_) => NFTA_SET_ELEM_KEY_END | NLA_F_NESTED,
            Self::ListExpressions(_) => {
                NFTA_SET_ELEM_EXPRESSIONS | NLA_F_NESTED
            }
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::Key(data) | Self::Data(data) => data.emit(out)?,
            Self::Flags(bits) => append_u32_be(out, bits.bits()),
            Self::Timeout(value) | Self::Expiration(value) => {
                append_u64_be(out, *value)
            }
            Self::UserData(bytes) => append_bytes(out, bytes.as_slice()),
            Self::Expression(ex) => ex.emit(out)?,
            Self::KeyEnd(attr) => attr.as_slice().emit(out)?,
            Self::ListExpressions(exs) => exs.as_slice().emit(out)?,
            Self::ObjectRefrence(string) => {
                append_bytes(out, string.as_bytes());
                out.push(0);
            }
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }

    fn is_nested(&self) -> bool {
        matches!(
            self,
            Self::Key(_)
                | Self::Data(_)
                | Self::Expression(_)
                | Self::KeyEnd(_)
                | Self::ListExpressions(_)
        ) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for SetElementAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_SET_ELEM_UNSPEC => Self::Unspecified,
            NFTA_SET_ELEM_KEY => Self::Key(
                DataAttribute::parse(&NlaBuffer::new(payload)?)
                    .context("invalid NFTA_SET_ELEM_KEY value")?,
            ),
            NFTA_SET_ELEM_DATA => Self::Data(
                DataAttribute::parse(&NlaBuffer::new(payload)?)
                    .context("invalid NFTA_SET_ELEM_DATA value")?,
            ),
            NFTA_SET_ELEM_FLAGS => {
                Self::Flags(SetElementFlags::from_bits_retain(
                    parse_u32_be(payload)
                        .context("invalid NFTA_SET_ELEM_FLAGS value")?,
                ))
            }
            NFTA_SET_ELEM_TIMEOUT => Self::Timeout(
                parse_u64_be(payload)
                    .context("invalid NFTA_SET_ELEM_TIMEOUT value")?,
            ),
            NFTA_SET_ELEM_EXPIRATION => Self::Expiration(
                parse_u64_be(payload)
                    .context("invalid NFTA_SET_ELEM_EXPIRATION value")?,
            ),
            NFTA_SET_ELEM_USERDATA => Self::UserData(payload.to_vec()),
            NFTA_SET_ELEM_EXPR => Self::Expression(
                ExpressionAttribute::parse_with_param(
                    &NlaBuffer::new(payload)?,
                    None, /* FIXME: Figure out how the legacy behavior
                           * determined the name */
                )
                .context("invalid NFTA_SET_ELEM_EXPR value")?,
            ),
            NFTA_SET_ELEM_OBJREF => Self::ObjectRefrence(
                parse_string(payload)
                    .context("invalid NFTA_SET_ELEM_OBJREF value")?,
            ),
            NFTA_SET_ELEM_KEY_END => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload)? {
                    nlas.push(DefaultNla::parse(&nla)?);
                }
                Self::KeyEnd(nlas)
            }
            NFTA_SET_ELEM_EXPRESSIONS => Self::ListExpressions(
                VecListAttribute::parse(payload)
                    .context("invalid NFTA_SET_ELEM_EXPRESSIONS value")?
                    .0,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
