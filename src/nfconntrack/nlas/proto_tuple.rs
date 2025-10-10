// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    DecodeError, Parseable,
};

use crate::nfconntrack::nlas::ProtoMember;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoTuple(Vec<ProtoMember>);

impl ProtoTuple {
    pub fn iter(&self) -> std::slice::Iter<ProtoMember> {
        self.0.iter()
    }
}

impl Nla for ProtoTuple {
    fn value_len(&self) -> usize {
        self.0.iter().map(|c| c.value_len()).sum()
    }

    fn kind(&self) -> u16 {
        todo!()
    }

    fn emit_value(&self, _buffer: &mut [u8]) {
        todo!()
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ProtoTuple
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let nlas = NlasIterator::new(buf.into_inner())
            .map(|nla_buf| ProtoMember::parse(&nla_buf.unwrap()).unwrap())
            .collect();
        Ok(ProtoTuple(nlas))
    }
}
