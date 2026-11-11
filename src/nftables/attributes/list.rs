// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable as _, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable, ParseableParametrized, NLA_F_NESTED,
};
use std::fmt::Debug;

use crate::nftables::attributes::ExpressionAttribute;
use netlink_packet_core::EncodeError;

const NFTA_LIST_UNSPEC: u16 = 0;
const NFTA_LIST_ELEM: u16 = 1;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ListAttribute<T = DefaultNla> {
    Unspec,
    /// Element of the list.
    Element(Vec<T>),
    Other(DefaultNla),
}

impl<T: Nla> Nla for ListAttribute<T> {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspec => NFTA_LIST_UNSPEC,
            Self::Element(_) => NFTA_LIST_ELEM | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspec => {}
            Self::Element(elems) => elems.as_slice().emit(out)?,
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
    fn is_nested(&self) -> bool {
        matches!(self, Self::Element(_)) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a, T> Parseable<NlaBuffer<'a>> for ListAttribute<T>
where
    for<'b> T: Parseable<NlaBuffer<'b>>,
{
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_LIST_UNSPEC => Self::Unspec,
            NFTA_LIST_ELEM => {
                let error_msg = "invalid NFTA_LIST_ELEM";
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload)? {
                    let parsed = T::parse(&nla).context(error_msg)?;
                    nlas.push(parsed);
                }
                Self::Element(nlas)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for ListAttribute<ExpressionAttribute> {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_LIST_UNSPEC => Self::Unspec,
            NFTA_LIST_ELEM => {
                let error_msg = "invalid NFTA_LIST_ELEM";
                let mut nlas = vec![];
                let mut name = None;

                for nla in NlasIterator::new(payload)? {
                    let expression_attribute =
                        ExpressionAttribute::parse_with_param(
                            &nla,
                            name.take(),
                        )
                        .context(error_msg)?;
                    if let ExpressionAttribute::Name(parsed_name) =
                        &expression_attribute
                    {
                        name = Some(parsed_name.clone());
                    }

                    nlas.push(expression_attribute);
                }
                Self::Element(nlas)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

pub(crate) struct VecListAttribute<T>(pub(crate) Vec<ListAttribute<T>>);

impl<T, B> Parseable<B> for VecListAttribute<T>
where
    B: AsRef<[u8]> + Debug + ?Sized,
    for<'b> T: Parseable<NlaBuffer<'b>>,
{
    fn parse(buf: &B) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla in NlasIterator::new(buf)? {
            nlas.push(ListAttribute::parse(&nla)?);
        }
        Ok(Self(nlas))
    }
}

impl<T: AsRef<[u8]> + Debug + ?Sized> Parseable<T>
    for VecListAttribute<ExpressionAttribute>
{
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla in NlasIterator::new(buf)? {
            nlas.push(ListAttribute::parse(&nla)?);
        }
        Ok(Self(nlas))
    }
}
