// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Nla, NlaBuffer, NlasIterator, Parseable,
};

use crate::conntrack::attributes::protoinfotcp::ProtoInfoTCP;
use netlink_packet_core::EncodeError;

const CTA_PROTOINFO_TCP: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtoInfo {
    TCP(Vec<ProtoInfoTCP>),
    Other(DefaultNla),
}
impl Nla for ProtoInfo {
    fn kind(&self) -> u16 {
        match self {
            ProtoInfo::TCP(_) => CTA_PROTOINFO_TCP,
            ProtoInfo::Other(attr) => attr.kind(),
        }
    }
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            ProtoInfo::TCP(nlas) => {
                for op in nlas {
                    op.emit(out)?;
                }
            }
            ProtoInfo::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
    fn is_nested(&self) -> bool {
        matches!(self, ProtoInfo::TCP(_))
    }
}

impl<'buffer> Parseable<NlaBuffer<'buffer>> for ProtoInfo {
    fn parse(buf: &NlaBuffer<'buffer>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_PROTOINFO_TCP => {
                let mut proto_info_tcps = Vec::new();
                for nlas in NlasIterator::new(payload)? {
                    let nlas = &nlas;
                    proto_info_tcps.push(ProtoInfoTCP::parse(nlas)?);
                }
                ProtoInfo::TCP(proto_info_tcps)
            }
            _ => ProtoInfo::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
