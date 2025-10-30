// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32_be, parse_u32_be, DecodeError, DefaultNla, Emitable, ErrorContext,
    Nla, NlaBuffer, NlasIterator, Parseable,
};

use crate::conntrack::attributes::{
    protoinfo::ProtoInfo, status::Status, tuple::Tuple,
};

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_PROTOINFO: u16 = 4;
const CTA_STATUS: u16 = 3;
const CTA_TIMEOUT: u16 = 7;
const CTA_MARK: u16 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConntrackAttribute {
    CtaTupleOrig(Vec<Tuple>),
    CtaTupleReply(Vec<Tuple>),
    CtaProtoInfo(Vec<ProtoInfo>),
    CtaStatus(Status),
    CtaTimeout(u32),
    CtaMark(u32),
    Other(DefaultNla),
}

impl Nla for ConntrackAttribute {
    fn value_len(&self) -> usize {
        match self {
            ConntrackAttribute::CtaTupleOrig(attr) => {
                attr.iter().map(|op| op.buffer_len()).sum()
            }
            ConntrackAttribute::CtaTupleReply(attr) => {
                attr.iter().map(|op| op.buffer_len()).sum()
            }
            ConntrackAttribute::CtaProtoInfo(attr) => {
                attr.iter().map(|op| op.buffer_len()).sum()
            }
            ConntrackAttribute::CtaStatus(_) => size_of::<u32>(),
            ConntrackAttribute::CtaTimeout(attr) => size_of_val(attr),
            ConntrackAttribute::CtaMark(attr) => size_of_val(attr),
            ConntrackAttribute::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ConntrackAttribute::CtaTupleOrig(_) => CTA_TUPLE_ORIG,
            ConntrackAttribute::CtaTupleReply(_) => CTA_TUPLE_REPLY,
            ConntrackAttribute::CtaProtoInfo(_) => CTA_PROTOINFO,
            ConntrackAttribute::CtaStatus(_) => CTA_STATUS,
            ConntrackAttribute::CtaTimeout(_) => CTA_TIMEOUT,
            ConntrackAttribute::CtaMark(_) => CTA_MARK,
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
            ConntrackAttribute::CtaTupleReply(attr) => {
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
            ConntrackAttribute::CtaStatus(attr) => {
                emit_u32_be(buffer, (*attr).bits()).unwrap()
            }
            ConntrackAttribute::CtaTimeout(attr) => {
                emit_u32_be(buffer, *attr).unwrap()
            }
            ConntrackAttribute::CtaMark(attr) => {
                emit_u32_be(buffer, *attr).unwrap()
            }
            ConntrackAttribute::Other(attr) => attr.emit_value(buffer),
        }
    }
    fn is_nested(&self) -> bool {
        matches!(
            self,
            ConntrackAttribute::CtaTupleOrig(_)
                | ConntrackAttribute::CtaTupleReply(_)
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
            CTA_TUPLE_REPLY => {
                let mut tuples = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas =
                        &nlas.context("invalid CTA_TUPLE_REPLY value")?;

                    tuples.push(Tuple::parse(nlas)?);
                }
                ConntrackAttribute::CtaTupleReply(tuples)
            }
            CTA_PROTOINFO => {
                let mut proto_infos = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context("invalid CTA_PROTOINFO value")?;
                    proto_infos.push(ProtoInfo::parse(nlas)?);
                }
                ConntrackAttribute::CtaProtoInfo(proto_infos)
            }
            CTA_STATUS => {
                ConntrackAttribute::CtaStatus(Status::from_bits_retain(
                    parse_u32_be(payload)
                        .context("invalid CTA_STATUS value")?,
                ))
            }
            CTA_TIMEOUT => ConntrackAttribute::CtaTimeout(
                parse_u32_be(payload).context("invalid CTA_TIMEOUT value")?,
            ),
            CTA_MARK => ConntrackAttribute::CtaMark(
                parse_u32_be(payload).context("invalid CTA_MARK value")?,
            ),
            _ => ConntrackAttribute::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
