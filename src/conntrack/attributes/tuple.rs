// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Nla, NlaBuffer, NlasIterator, Parseable,
};

use crate::conntrack::attributes::{iptuple::IPTuple, prototuple::ProtoTuple};
use netlink_packet_core::EncodeError;

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
    fn kind(&self) -> u16 {
        match self {
            Tuple::Ip(_) => CTA_TUPLE_IP,
            Tuple::Proto(_) => CTA_TUPLE_PROTO,
            Tuple::Other(attr) => attr.kind(),
        }
    }
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Tuple::Ip(nlas) => {
                for op in nlas {
                    op.emit(out)?;
                }
            }
            Tuple::Proto(nlas) => {
                for op in nlas {
                    op.emit(out)?;
                }
            }
            Tuple::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
    fn is_nested(&self) -> bool {
        matches!(self, Tuple::Ip(_) | Tuple::Proto(_))
    }
}
impl<'buffer> Parseable<NlaBuffer<'buffer>> for Tuple {
    fn parse(buf: &NlaBuffer<'buffer>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_TUPLE_IP => {
                let mut ip_tuples = Vec::new();
                for nlas in NlasIterator::new(payload)? {
                    let nlas = &nlas;
                    ip_tuples.push(IPTuple::parse(nlas)?);
                }
                Tuple::Ip(ip_tuples)
            }
            CTA_TUPLE_PROTO => {
                let mut proto_tuples = Vec::new();
                for nlas in NlasIterator::new(payload)? {
                    let nlas = &nlas;
                    proto_tuples.push(ProtoTuple::parse(nlas)?);
                }
                Tuple::Proto(proto_tuples)
            }
            _ => Tuple::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
