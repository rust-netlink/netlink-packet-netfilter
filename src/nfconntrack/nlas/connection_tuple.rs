// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    DecodeError, Parseable,
};
use std::convert::TryFrom;
use std::net::IpAddr;

use crate::nfconntrack::nlas::{ConnectionMember, IpMember, ProtoMember};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionTuple(Vec<ConnectionMember>);

impl ConnectionTuple {
    pub fn iter(&self) -> std::slice::Iter<ConnectionMember> {
        self.0.iter()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionProperties {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl TryFrom<ConnectionTuple> for ConnectionProperties {
    type Error = DecodeError;

    fn try_from(cxn_tuple: ConnectionTuple) -> Result<Self, Self::Error> {
        let mut sip: Option<IpAddr> = None;
        let mut dip: Option<IpAddr> = None;
        let mut spt: Option<u16> = None;
        let mut dpt: Option<u16> = None;
        let mut prot: Option<u8> = None;

        for member in cxn_tuple.iter() {
            match member {
                ConnectionMember::IpTuple(ip_tuple) => {
                    for ip_mem in ip_tuple.iter() {
                        match ip_mem {
                            IpMember::Src(addr) => sip = Some(*addr),
                            IpMember::Dst(addr) => dip = Some(*addr),
                        }
                    }
                }
                ConnectionMember::ProtoTuple(proto_tuple) => {
                    for proto_mem in proto_tuple.iter() {
                        match proto_mem {
                            ProtoMember::ProtoNum(p) => prot = Some(*p),
                            ProtoMember::SrcPort(p) => spt = Some(*p),
                            ProtoMember::DstPort(p) => dpt = Some(*p),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        match (sip, dip, spt, dpt, prot) {
            (
                Some(src_ip),
                Some(dst_ip),
                Some(src_port),
                Some(dst_port),
                Some(protocol),
            ) => Ok(ConnectionProperties {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
            }),
            _ => Err("Connection properties incomplete".into()),
        }
    }
}

impl Nla for ConnectionTuple {
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
    for ConnectionTuple
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let nlas = NlasIterator::new(buf.into_inner())
            .map(|nla_buf| ConnectionMember::parse(&nla_buf.unwrap()).unwrap())
            .collect();
        Ok(ConnectionTuple(nlas))
    }
}
