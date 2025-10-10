// SPDX-License-Identifier: MIT

use derive_more::IsVariant;

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    DecodeError, Parseable,
};

use crate::{
    constants::{CTA_TUPLE_ORIG, CTA_TUPLE_REPLY},
    nfconntrack::nlas::ConnectionTuple,
};

#[derive(Clone, Debug, PartialEq, Eq, IsVariant)]
pub enum ConnectionNla {
    TupleOrig(ConnectionTuple),
    TupleReply(ConnectionTuple),
    Other(DefaultNla),
}

impl Nla for ConnectionNla {
    fn value_len(&self) -> usize {
        match self {
            ConnectionNla::TupleOrig(attr) => attr.value_len(),
            ConnectionNla::TupleReply(attr) => attr.value_len(),
            ConnectionNla::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ConnectionNla::TupleOrig(attr) => attr.kind(),
            ConnectionNla::TupleReply(attr) => attr.kind(),
            ConnectionNla::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ConnectionNla::TupleOrig(attr) => attr.emit_value(buffer),
            ConnectionNla::TupleReply(attr) => attr.emit_value(buffer),
            ConnectionNla::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ConnectionNla
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let payload = NlaBuffer::new(buf.value());
        let nla = match buf.kind() {
            CTA_TUPLE_ORIG => {
                ConnectionNla::TupleOrig(ConnectionTuple::parse(&payload)?)
            }
            CTA_TUPLE_REPLY => {
                ConnectionNla::TupleReply(ConnectionTuple::parse(&payload)?)
            }
            _ => ConnectionNla::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
