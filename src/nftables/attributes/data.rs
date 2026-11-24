// SPDX-License-Identifier: MIT

use std::fmt::Debug;

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable as _, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable, NLA_F_NESTED,
};

use crate::nftables::attributes::VerdictAttribute;
use netlink_packet_core::{append_bytes, EncodeError};

const NFTA_DATA_UNSPEC: u16 = 0;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum DataAttribute {
    Unspec,
    /// Generic data.
    Value(Vec<u8>),
    Verdict(Vec<VerdictAttribute>),
    Other(DefaultNla),
}

impl Nla for DataAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspec => NFTA_DATA_UNSPEC,
            Self::Value(_) => NFTA_DATA_VALUE,
            Self::Verdict(_) => NFTA_DATA_VERDICT | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspec => {}
            Self::Value(bytes) => append_bytes(out, bytes),
            Self::Verdict(attr) => attr.as_slice().emit(out)?,
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Verdict(_)) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for DataAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_DATA_UNSPEC => Self::Unspec,
            NFTA_DATA_VALUE => Self::Value(payload.to_vec()),
            NFTA_DATA_VERDICT => {
                let error_msg = "invalid NFTA_DATA_VERDICT";
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload)? {
                    let nla = &nla;
                    let parsed =
                        VerdictAttribute::parse(nla).context(error_msg)?;
                    nlas.push(parsed);
                }
                Self::Verdict(nlas)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
