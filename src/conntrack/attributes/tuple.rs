// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable,
};

use crate::conntrack::attributes::{iptuple::IPTuple, prototuple::ProtoTuple};

const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Tuple {
    Ip(Vec<IPTuple>),
    Proto(Vec<ProtoTuple>),
    Other(DefaultNla),
}

impl Nla for Tuple {
    fn value_len(&self) -> usize {
        match self {
            Tuple::Ip(nlas) => nlas.iter().map(|op| op.buffer_len()).sum(),
            Tuple::Proto(nlas) => nlas.iter().map(|op| op.buffer_len()).sum(),
            Tuple::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Tuple::Ip(_) => CTA_TUPLE_IP,
            Tuple::Proto(_) => CTA_TUPLE_PROTO,
            Tuple::Other(attr) => attr.kind(),
        }
    }
    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Tuple::Ip(nlas) => {
                let mut len = 0;
                for op in nlas {
                    op.emit(&mut buffer[len..]);
                    len += op.buffer_len();
                }
            }
            Tuple::Proto(nlas) => {
                let mut len = 0;
                for op in nlas {
                    op.emit(&mut buffer[len..]);
                    len += op.buffer_len();
                }
            }
            Tuple::Other(attr) => attr.emit_value(buffer),
        }
    }
    fn is_nested(&self) -> bool {
        matches!(self, Tuple::Ip(_) | Tuple::Proto(_))
    }
}
impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for Tuple
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_TUPLE_IP => {
                let mut ip_tuples = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context("invalid CTA_TUPLE_IP value")?;
                    ip_tuples.push(IPTuple::parse(nlas)?);
                }
                Tuple::Ip(ip_tuples)
            }
            CTA_TUPLE_PROTO => {
                let mut proto_tuples = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas =
                        &nlas.context("invalid CTA_TUPLE_PROTO value")?;
                    proto_tuples.push(ProtoTuple::parse(nlas)?);
                }
                Tuple::Proto(proto_tuples)
            }
            _ => Tuple::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
