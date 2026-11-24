// SPDX-License-Identifier: MIT

use std::fmt::Debug;

use netlink_packet_core::EncodeError;
use netlink_packet_core::{
    append_u32_be, parse_u32_be, DecodeError, DefaultNla, Emitable as _,
    ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable,
};

const NFTA_SET_DESC_UNSPEC: u16 = 0;
const NFTA_SET_DESC_SIZE: u16 = 1;
const NFTA_SET_DESC_CONCAT: u16 = 2;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum SetDescription {
    Unspec,
    /// Number of elements in the set
    Size(u32),
    /// Concatenation description
    Concat(Vec<DefaultNla>),
    Other(DefaultNla),
}

impl Nla for SetDescription {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspec => NFTA_SET_DESC_UNSPEC,
            Self::Size(_) => NFTA_SET_DESC_SIZE,
            Self::Concat(_) => NFTA_SET_DESC_CONCAT,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspec => {}
            Self::Size(value) => append_u32_be(out, *value),
            Self::Concat(concat) => concat.as_slice().emit(out)?,
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for SetDescription {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_SET_DESC_UNSPEC => Self::Unspec,
            NFTA_SET_DESC_SIZE => Self::Size(
                parse_u32_be(payload).context("invalid NFTA_SET_DESC_SIZE")?,
            ),
            NFTA_SET_DESC_CONCAT => {
                let error_msg = "invalid NFTA_SET_DESC_CONCAT";
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload)? {
                    let nla = &nla;
                    let parsed = DefaultNla::parse(nla).context(error_msg)?;
                    nlas.push(parsed);
                }
                Self::Concat(nlas)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

pub(crate) struct VecSetDescription(pub(crate) Vec<SetDescription>);

impl<T: AsRef<[u8]> + Debug + ?Sized> Parseable<T> for VecSetDescription {
    fn parse(buf: &T) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla in NlasIterator::new(buf)? {
            nlas.push(SetDescription::parse(&nla)?);
        }
        Ok(Self(nlas))
    }
}
