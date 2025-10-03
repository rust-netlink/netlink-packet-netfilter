// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable,
};

use crate::conntrack::attributes::protoinfotcp::ProtoInfoTCP;

const CTA_PROTOINFO_TCP: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtoInfo {
    TCP(Vec<ProtoInfoTCP>),
    Other(DefaultNla),
}
impl Nla for ProtoInfo {
    fn value_len(&self) -> usize {
        match self {
            ProtoInfo::TCP(nlas) => nlas.iter().map(|op| op.buffer_len()).sum(),
            ProtoInfo::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ProtoInfo::TCP(_) => CTA_PROTOINFO_TCP,
            ProtoInfo::Other(attr) => attr.kind(),
        }
    }
    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ProtoInfo::TCP(nlas) => {
                let mut len = 0;
                for op in nlas {
                    op.emit(&mut buffer[len..]);
                    len += op.buffer_len();
                }
            }
            ProtoInfo::Other(attr) => attr.emit_value(buffer),
        }
    }
    fn is_nested(&self) -> bool {
        matches!(self, ProtoInfo::TCP(_))
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ProtoInfo
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_PROTOINFO_TCP => {
                let mut proto_info_tcps = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas =
                        &nlas.context("invailid CTA_PROTOINFO_TCP value")?;
                    proto_info_tcps.push(ProtoInfoTCP::parse(nlas)?);
                }
                ProtoInfo::TCP(proto_info_tcps)
            }
            _ => ProtoInfo::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
