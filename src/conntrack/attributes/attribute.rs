// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable,
};

use crate::conntrack::attributes::{protoinfo::ProtoInfo, tuple::Tuple};

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_PROTOINFO: u16 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConntrackAttribute {
    CtaTupleOrig(Vec<Tuple>),
    CtaProtoInfo(Vec<ProtoInfo>),
    Other(DefaultNla),
}

impl Nla for ConntrackAttribute {
    fn value_len(&self) -> usize {
        match self {
            ConntrackAttribute::CtaTupleOrig(attr) => {
                attr.iter().map(|op| op.buffer_len()).sum()
            }
            ConntrackAttribute::CtaProtoInfo(attr) => {
                attr.iter().map(|op| op.buffer_len()).sum()
            }
            ConntrackAttribute::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ConntrackAttribute::CtaTupleOrig(_) => CTA_TUPLE_ORIG,
            ConntrackAttribute::CtaProtoInfo(_) => CTA_PROTOINFO,
            ConntrackAttribute::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ConntrackAttribute::CtaTupleOrig(attr) => {
                let mut len = 0;
                for op in attr {
                    op.emit(&mut buffer[len..]);
                    len += op.buffer_len();
                }
            }
            ConntrackAttribute::CtaProtoInfo(attr) => {
                let mut len = 0;
                for op in attr {
                    op.emit(&mut buffer[len..]);
                    len += op.buffer_len();
                }
            }
            ConntrackAttribute::Other(attr) => attr.emit_value(buffer),
        }
    }
    fn is_nested(&self) -> bool {
        matches!(
            self,
            ConntrackAttribute::CtaTupleOrig(_)
                | ConntrackAttribute::CtaProtoInfo(_)
        )
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ConntrackAttribute
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_TUPLE_ORIG => {
                let mut tuples = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context("invalid CTA_TUPLE_ORIG value")?;
                    tuples.push(Tuple::parse(nlas)?);
                }
                ConntrackAttribute::CtaTupleOrig(tuples)
            }
            CTA_PROTOINFO => {
                let mut proto_infos = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context("invalid CTA_PROTOINFO value")?;
                    proto_infos.push(ProtoInfo::parse(nlas)?);
                }
                ConntrackAttribute::CtaProtoInfo(proto_infos)
            }
            _ => ConntrackAttribute::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
