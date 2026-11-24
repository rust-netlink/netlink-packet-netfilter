// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_u32_be, parse_u32_be, DecodeError, DefaultNla, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable,
};

use crate::conntrack::attributes::{
    protoinfo::ProtoInfo, status::Status, tuple::Tuple,
};
use netlink_packet_core::EncodeError;

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

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            ConntrackAttribute::CtaTupleOrig(attr) => {
                for op in attr {
                    op.emit(out)?;
                }
            }
            ConntrackAttribute::CtaTupleReply(attr) => {
                for op in attr {
                    op.emit(out)?;
                }
            }
            ConntrackAttribute::CtaProtoInfo(attr) => {
                for op in attr {
                    op.emit(out)?;
                }
            }
            ConntrackAttribute::CtaStatus(attr) => {
                append_u32_be(out, (*attr).bits())
            }
            ConntrackAttribute::CtaTimeout(attr) => append_u32_be(out, *attr),
            ConntrackAttribute::CtaMark(attr) => append_u32_be(out, *attr),
            ConntrackAttribute::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
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

impl<'buffer> Parseable<NlaBuffer<'buffer>> for ConntrackAttribute {
    fn parse(buf: &NlaBuffer<'buffer>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_TUPLE_ORIG => {
                let mut tuples = Vec::new();
                for nlas in NlasIterator::new(payload)? {
                    let nlas = &nlas;
                    tuples.push(Tuple::parse(nlas)?);
                }
                ConntrackAttribute::CtaTupleOrig(tuples)
            }
            CTA_TUPLE_REPLY => {
                let mut tuples = Vec::new();
                for nlas in NlasIterator::new(payload)? {
                    let nlas = &nlas;

                    tuples.push(Tuple::parse(nlas)?);
                }
                ConntrackAttribute::CtaTupleReply(tuples)
            }
            CTA_PROTOINFO => {
                let mut proto_infos = Vec::new();
                for nlas in NlasIterator::new(payload)? {
                    let nlas = &nlas;
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
