// SPDX-License-Identifier: MIT

use netlink_packet_core::{append_bytes, EncodeError};
use std::fmt::Debug;

mod bitwise;
mod cmp;
mod immediate;
mod lookup;
mod meta;
mod payload;
mod register;

use crate::nftables::attributes::ListAttribute;

pub use self::{
    bitwise::Bitwise, cmp::Cmp, cmp::Operator, immediate::Immediate,
    lookup::Lookup, meta::Meta, meta::MetaKey, payload::ChecksumFlags,
    payload::ChecksumType, payload::Payload, register::Register,
};

use netlink_packet_core::{
    parse_string, DecodeError, DefaultNla, Emitable, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable, ParseableParametrized, NLA_F_NESTED,
};

const NFTA_EXPR_UNSPEC: u16 = 0;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Expressions {
    Bitwise(Vec<Bitwise>),
    Cmp(Vec<Cmp>),
    Immediate(Vec<Immediate>),
    Lookup(Vec<Lookup>),
    Meta(Vec<Meta>),
    Payload(Vec<Payload>),
    Unknown(Vec<DefaultNla>),
    Other {
        expression_type: String,
        attributes: Vec<DefaultNla>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExpressionAttribute {
    Unspec,
    /// Name of the expression type.
    Name(String),
    /// Type specific data.
    Data(Expressions),
    Other(DefaultNla),
}

impl From<Expressions> for ListAttribute<ExpressionAttribute> {
    fn from(ex: Expressions) -> Self {
        let name = match &ex {
            Expressions::Bitwise(_) => Some("bitwise"),
            Expressions::Cmp(_) => Some("cmp"),
            Expressions::Immediate(_) => Some("immediate"),
            Expressions::Lookup(_) => Some("lookup"),
            Expressions::Meta(_) => Some("meta"),
            Expressions::Payload(_) => Some("payload"),
            Expressions::Unknown(_) => None,
            Expressions::Other {
                ref expression_type,
                ..
            } => Some(expression_type.as_str()),
        };
        if let Some(name) = name {
            ListAttribute::Element(vec![
                ExpressionAttribute::Name(name.to_string()),
                ExpressionAttribute::Data(ex),
            ])
        } else {
            ListAttribute::Element(vec![ExpressionAttribute::Data(ex)])
        }
    }
}

impl Emitable for Expressions {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Bitwise(attrs) => attrs.as_slice().emit(out)?,
            Self::Cmp(attrs) => attrs.as_slice().emit(out)?,
            Self::Immediate(attrs) => attrs.as_slice().emit(out)?,
            Self::Lookup(attrs) => attrs.as_slice().emit(out)?,
            Self::Meta(attrs) => attrs.as_slice().emit(out)?,
            Self::Payload(attrs) => attrs.as_slice().emit(out)?,
            Self::Unknown(attrs) => attrs.as_slice().emit(out)?,
            Self::Other { attributes, .. } => {
                attributes.as_slice().emit(out)?
            }
        }
        Ok(())
    }
}

impl<T: AsRef<[u8]> + ?Sized + Debug> ParseableParametrized<T, Option<String>>
    for Expressions
{
    fn parse_with_param(
        buf: &T,
        name: Option<String>,
    ) -> Result<Self, DecodeError> {
        Ok(match name {
            None => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(buf)? {
                    nlas.push(DefaultNla::parse(&nla)?);
                }

                Self::Unknown(nlas)
            }
            Some(name) => match name.as_str() {
                "bitwise" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf)? {
                        nlas.push(Bitwise::parse(&nla)?);
                    }
                    Self::Bitwise(nlas)
                }
                "cmp" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf)? {
                        nlas.push(Cmp::parse(&nla)?);
                    }
                    Self::Cmp(nlas)
                }
                "immediate" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf)? {
                        nlas.push(Immediate::parse(&nla)?);
                    }
                    Self::Immediate(nlas)
                }
                "lookup" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf)? {
                        nlas.push(Lookup::parse(&nla)?);
                    }
                    Self::Lookup(nlas)
                }
                "meta" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf)? {
                        nlas.push(Meta::parse(&nla)?);
                    }
                    Self::Meta(nlas)
                }
                "payload" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf)? {
                        nlas.push(Payload::parse(&nla)?);
                    }
                    Self::Payload(nlas)
                }
                name => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf)? {
                        nlas.push(DefaultNla::parse(&nla)?);
                    }
                    Self::Other {
                        expression_type: name.to_string(),
                        attributes: nlas,
                    }
                }
            },
        })
    }
}

impl Nla for ExpressionAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspec => NFTA_EXPR_UNSPEC,
            Self::Name(_) => NFTA_EXPR_NAME,
            Self::Data(_) => NFTA_EXPR_DATA | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspec => {}
            Self::Name(string) => {
                append_bytes(out, string.as_bytes());
                out.push(0);
            }
            Self::Data(exps) => exps.emit(out)?,
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Data(_)) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a> ParseableParametrized<NlaBuffer<'a>, Option<String>>
    for ExpressionAttribute
{
    fn parse_with_param(
        buf: &NlaBuffer<'a>,
        name: Option<String>,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_EXPR_UNSPEC => Self::Unspec,
            NFTA_EXPR_NAME => Self::Name(
                parse_string(payload).context("invalid NFTA_EXPR_NAME")?,
            ),
            NFTA_EXPR_DATA => Self::Data(
                Expressions::parse_with_param(payload, name)
                    .context("invalid NFTA_EXPR_DATA")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
