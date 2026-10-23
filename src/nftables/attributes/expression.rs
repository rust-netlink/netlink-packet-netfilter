// SPDX-License-Identifier: MIT

use std::fmt::Debug;

mod bitwise;
mod cmp;
mod ct;
mod immediate;
mod limit;
mod log;
mod lookup;
mod meta;
mod payload;
mod register;
mod rt;

use crate::nftables::attributes::ListAttribute;

pub use self::{
    bitwise::Bitwise, cmp::Cmp, cmp::Operator, ct::Ct, ct::CtDirection,
    ct::CtKey, immediate::Immediate, limit::Limit, limit::LimitFlags,
    limit::LimitType, log::Log, log::LogFlags, log::LogLevel, lookup::Lookup,
    meta::Meta, meta::MetaKey, payload::ChecksumFlags, payload::ChecksumType,
    payload::Payload, register::Register, rt::Rt, rt::RtKey,
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
    Ct(Vec<Ct>),
    Immediate(Vec<Immediate>),
    Limit(Vec<Limit>),
    Log(Vec<Log>),
    Lookup(Vec<Lookup>),
    Meta(Vec<Meta>),
    Payload(Vec<Payload>),
    Rt(Vec<Rt>),
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
            Expressions::Ct(_) => Some("ct"),
            Expressions::Immediate(_) => Some("immediate"),
            Expressions::Limit(_) => Some("limit"),
            Expressions::Log(_) => Some("log"),
            Expressions::Lookup(_) => Some("lookup"),
            Expressions::Meta(_) => Some("meta"),
            Expressions::Payload(_) => Some("payload"),
            Expressions::Rt(_) => Some("rt"),
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
    fn buffer_len(&self) -> usize {
        match self {
            Self::Bitwise(attrs) => attrs.as_slice().buffer_len(),
            Self::Cmp(attrs) => attrs.as_slice().buffer_len(),
            Self::Ct(attrs) => attrs.as_slice().buffer_len(),
            Self::Immediate(attrs) => attrs.as_slice().buffer_len(),
            Self::Limit(attrs) => attrs.as_slice().buffer_len(),
            Self::Log(attrs) => attrs.as_slice().buffer_len(),
            Self::Lookup(attrs) => attrs.as_slice().buffer_len(),
            Self::Meta(attrs) => attrs.as_slice().buffer_len(),
            Self::Payload(attrs) => attrs.as_slice().buffer_len(),
            Self::Rt(attrs) => attrs.as_slice().buffer_len(),
            Self::Unknown(attrs) => attrs.as_slice().buffer_len(),
            Self::Other { attributes, .. } => {
                attributes.as_slice().buffer_len()
            }
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            Self::Bitwise(attrs) => attrs.as_slice().emit(buffer),
            Self::Cmp(attrs) => attrs.as_slice().emit(buffer),
            Self::Ct(attrs) => attrs.as_slice().emit(buffer),
            Self::Immediate(attrs) => attrs.as_slice().emit(buffer),
            Self::Limit(attrs) => attrs.as_slice().emit(buffer),
            Self::Log(attrs) => attrs.as_slice().emit(buffer),
            Self::Lookup(attrs) => attrs.as_slice().emit(buffer),
            Self::Meta(attrs) => attrs.as_slice().emit(buffer),
            Self::Payload(attrs) => attrs.as_slice().emit(buffer),
            Self::Rt(attrs) => attrs.as_slice().emit(buffer),
            Self::Unknown(attrs) => attrs.as_slice().emit(buffer),
            Self::Other { attributes, .. } => {
                attributes.as_slice().emit(buffer)
            }
        }
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
                for nla in NlasIterator::new(buf) {
                    let nla = nla
                        .context(format!("invalid NFTA_EXPR_DATA {:?}", buf))?;
                    nlas.push(DefaultNla::parse(&nla)?);
                }

                Self::Unknown(nlas)
            }
            Some(name) => match name.as_str() {
                "bitwise" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Bitwise::parse(&nla)?);
                    }
                    Self::Bitwise(nlas)
                }
                "cmp" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Cmp::parse(&nla)?);
                    }
                    Self::Cmp(nlas)
                }
                "ct" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Ct::parse(&nla)?);
                    }
                    Self::Ct(nlas)
                }
                "immediate" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Immediate::parse(&nla)?);
                    }
                    Self::Immediate(nlas)
                }
                "limit" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Limit::parse(&nla)?);
                    }
                    Self::Limit(nlas)
                }
                "log" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Log::parse(&nla)?);
                    }
                    Self::Log(nlas)
                }
                "lookup" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Lookup::parse(&nla)?);
                    }
                    Self::Lookup(nlas)
                }
                "meta" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Meta::parse(&nla)?);
                    }
                    Self::Meta(nlas)
                }
                "payload" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Payload::parse(&nla)?);
                    }
                    Self::Payload(nlas)
                }
                "rt" => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
                        nlas.push(Rt::parse(&nla)?);
                    }
                    Self::Rt(nlas)
                }
                name => {
                    let mut nlas = vec![];
                    for nla in NlasIterator::new(buf) {
                        let nla = nla.context(format!(
                            "invalid NFTA_EXPR_DATA {:?}",
                            buf
                        ))?;
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
    fn value_len(&self) -> usize {
        match self {
            Self::Unspec => 0,
            Self::Name(string) => string.len() + 1,
            Self::Data(exps) => exps.buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspec => NFTA_EXPR_UNSPEC,
            Self::Name(_) => NFTA_EXPR_NAME,
            Self::Data(_) => NFTA_EXPR_DATA | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspec => {}
            Self::Name(string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }
            Self::Data(exps) => exps.emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Data(_)) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NlaBuffer<&'a T>, Option<String>>
    for ExpressionAttribute
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
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
