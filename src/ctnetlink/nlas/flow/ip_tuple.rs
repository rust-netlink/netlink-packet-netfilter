// SPDX-License-Identifier: MIT

use std::{convert::TryFrom, net::IpAddr};

use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NLA_F_NESTED, NLA_HEADER_SIZE},
    parsers::parse_ip,
    DecodeError, Parseable,
};

use crate::{
    constants::{
        CTA_IP_V4_DST, CTA_IP_V4_SRC, CTA_IP_V6_DST, CTA_IP_V6_SRC,
        CTA_PROTO_DST_PORT, CTA_PROTO_NUM, CTA_PROTO_SRC_PORT, CTA_TUPLE_IP,
        CTA_TUPLE_PROTO,
    },
    ctnetlink::nlas::ct_attr::{CtAttr, CtAttrBuilder},
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TupleNla {
    Ip(IpTuple),
    Protocol(ProtocolTuple),
}

impl Nla for TupleNla {
    fn value_len(&self) -> usize {
        match self {
            TupleNla::Ip(attr) => attr.value_len(),
            TupleNla::Protocol(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            TupleNla::Ip(attr) => attr.kind(),
            TupleNla::Protocol(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            TupleNla::Ip(attr) => attr.emit_value(buffer),
            TupleNla::Protocol(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for TupleNla
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let attr = CtAttr::parse(buf)?;
        match attr.attr_type {
            CTA_TUPLE_IP => Ok(TupleNla::Ip(IpTuple::try_from(attr)?)),
            CTA_TUPLE_PROTO => {
                Ok(TupleNla::Protocol(ProtocolTuple::try_from(attr)?))
            }
            _ => Err(DecodeError::from("CTA_TUPLE_{IP|PROTO} is expected")),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IpTuple {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
}

impl Nla for IpTuple {
    fn value_len(&self) -> usize {
        let mut l = 0;
        l += match self.src_addr {
            IpAddr::V4(_) => 4 + NLA_HEADER_SIZE,
            IpAddr::V6(_) => 16 + NLA_HEADER_SIZE,
        };
        l += match self.dst_addr {
            IpAddr::V4(_) => 4 + NLA_HEADER_SIZE,
            IpAddr::V6(_) => 16 + NLA_HEADER_SIZE,
        };
        l
    }

    fn kind(&self) -> u16 {
        CTA_TUPLE_IP + NLA_F_NESTED
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        let mut builder = CtAttrBuilder::new(CTA_TUPLE_IP);
        match self.src_addr {
            IpAddr::V4(addr) => {
                let src_ip_attr = CtAttrBuilder::new(CTA_IP_V4_SRC)
                    .value(&addr.octets())
                    .build();
                builder = builder.nested_attr(src_ip_attr);
            }
            IpAddr::V6(addr) => {
                let src_ip_attr = CtAttrBuilder::new(CTA_IP_V6_SRC)
                    .value(&addr.octets())
                    .build();
                builder = builder.nested_attr(src_ip_attr);
            }
        }
        match self.dst_addr {
            IpAddr::V4(addr) => {
                let dst_ip_attr = CtAttrBuilder::new(CTA_IP_V4_DST)
                    .value(&addr.octets())
                    .build();
                builder = builder.nested_attr(dst_ip_attr);
            }
            IpAddr::V6(addr) => {
                let dst_ip_attr = CtAttrBuilder::new(CTA_IP_V6_DST)
                    .value(&addr.octets())
                    .build();
                builder = builder.nested_attr(dst_ip_attr);
            }
        }

        builder.build().emit_value(buffer);
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for IpTuple
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let ip_tuple = CtAttr::parse(buf)?;
        let mut builder = IpTupleBuilder::default();

        if let Some(attrs) = ip_tuple.nested {
            for attr in attrs.iter() {
                match attr.attr_type {
                    CTA_IP_V4_SRC | CTA_IP_V6_SRC => {
                        if let Some(value) = &attr.value {
                            let addr = parse_ip(value)?;
                            builder = builder.src_addr(addr);
                        }
                    }
                    CTA_IP_V4_DST | CTA_IP_V6_DST => {
                        if let Some(value) = &attr.value {
                            let addr = parse_ip(value)?;
                            builder = builder.dst_addr(addr);
                        }
                    }
                    _ => {}
                }
            }
            builder.build()
        } else {
            Err(DecodeError::from("CTA_TUPLE_IP must be nested"))
        }
    }
}

impl TryFrom<CtAttr> for IpTuple {
    type Error = DecodeError;

    fn try_from(attr: CtAttr) -> Result<Self, Self::Error> {
        if attr.attr_type != CTA_TUPLE_IP {
            return Err(DecodeError::from("CTA_TUPLE_IP is expected"));
        }
        let mut builder = IpTupleBuilder::default();

        if let Some(attrs) = attr.nested {
            for attr in attrs.iter() {
                match attr.attr_type {
                    CTA_IP_V4_SRC | CTA_IP_V6_SRC => {
                        if let Some(value) = &attr.value {
                            let addr = parse_ip(value)?;
                            builder = builder.src_addr(addr);
                        }
                    }
                    CTA_IP_V4_DST | CTA_IP_V6_DST => {
                        if let Some(value) = &attr.value {
                            let addr = parse_ip(value)?;
                            builder = builder.dst_addr(addr);
                        }
                    }
                    _ => {}
                }
            }
            builder.build()
        } else {
            Err(DecodeError::from("CTA_TUPLE_IP must be nested"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpTupleBuilder {
    src_addr: Option<IpAddr>,
    dst_addr: Option<IpAddr>,
}

impl IpTupleBuilder {
    pub fn src_addr(mut self, addr: IpAddr) -> Self {
        self.src_addr = Some(addr);
        self
    }

    pub fn dst_addr(mut self, addr: IpAddr) -> Self {
        self.dst_addr = Some(addr);
        self
    }

    pub fn build(&self) -> Result<IpTuple, DecodeError> {
        Ok(IpTuple {
            src_addr: self
                .src_addr
                .ok_or(DecodeError::from("ip_tuple.src_addr is none"))?,
            dst_addr: self
                .dst_addr
                .ok_or(DecodeError::from("ip_tuple.dst_addr is none"))?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProtocolTuple {
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl TryFrom<CtAttr> for ProtocolTuple {
    type Error = DecodeError;

    fn try_from(attr: CtAttr) -> Result<Self, Self::Error> {
        if attr.attr_type != CTA_TUPLE_PROTO {
            return Err(DecodeError::from("CTA_TUPLE_PROTO is expected"));
        }
        let mut builder = ProtocolTupleBuilder::default();

        if let Some(attrs) = attr.nested {
            for attr in attrs.iter() {
                match attr.attr_type {
                    CTA_PROTO_NUM => {
                        if let Some(value) = &attr.value {
                            builder = builder.protocol(value[0]);
                        }
                    }
                    CTA_PROTO_SRC_PORT => {
                        if let Some(value) = &attr.value {
                            builder =
                                builder.src_port(BigEndian::read_u16(value));
                        }
                    }
                    CTA_PROTO_DST_PORT => {
                        if let Some(value) = &attr.value {
                            builder =
                                builder.dst_port(BigEndian::read_u16(value));
                        }
                    }
                    _ => {}
                }
            }
            builder.build()
        } else {
            Err(DecodeError::from("CTA_TUPLE_PROTO must be nested"))
        }
    }
}

impl Nla for ProtocolTuple {
    fn value_len(&self) -> usize {
        24
    }

    fn kind(&self) -> u16 {
        CTA_TUPLE_PROTO + NLA_F_NESTED
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        let mut builder = CtAttrBuilder::new(CTA_TUPLE_PROTO);
        builder = builder.nested_attr(
            CtAttrBuilder::new(CTA_PROTO_NUM)
                .value(vec![self.protocol].as_ref())
                .build(),
        );
        let mut src_port_buf = [0u8; 2];
        BigEndian::write_u16(&mut src_port_buf, self.src_port);
        let mut dst_port_buf = [0u8; 2];
        BigEndian::write_u16(&mut dst_port_buf, self.dst_port);
        builder = builder.nested_attr(
            CtAttrBuilder::new(CTA_PROTO_SRC_PORT)
                .value(&src_port_buf)
                .build(),
        );
        builder = builder.nested_attr(
            CtAttrBuilder::new(CTA_PROTO_DST_PORT)
                .value(&dst_port_buf)
                .build(),
        );

        builder.build().emit_value(buffer);
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ProtocolTuple
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let proto_tuple = CtAttr::parse(buf)?;
        let mut builder = ProtocolTupleBuilder::default();

        if let Some(attrs) = proto_tuple.nested {
            for attr in attrs.iter() {
                match attr.attr_type {
                    CTA_PROTO_NUM => {
                        if let Some(value) = &attr.value {
                            builder = builder.protocol(value[0]);
                        }
                    }
                    CTA_PROTO_SRC_PORT => {
                        if let Some(value) = &attr.value {
                            builder =
                                builder.src_port(BigEndian::read_u16(value));
                        }
                    }
                    CTA_PROTO_DST_PORT => {
                        if let Some(value) = &attr.value {
                            builder =
                                builder.dst_port(BigEndian::read_u16(value));
                        }
                    }
                    _ => {}
                }
            }
            builder.build()
        } else {
            Err(DecodeError::from("CTA_TUPLE_PROTO must be nested"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtocolTupleBuilder {
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: Option<u8>,
}

impl ProtocolTupleBuilder {
    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = Some(port);
        self
    }

    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    pub fn protocol(mut self, proto: u8) -> Self {
        self.protocol = Some(proto);
        self
    }

    pub fn build(&self) -> Result<ProtocolTuple, DecodeError> {
        Ok(ProtocolTuple {
            src_port: self
                .src_port
                .ok_or(DecodeError::from("ip_tuple.src_port is none"))?,
            dst_port: self
                .dst_port
                .ok_or(DecodeError::from("ip_tuple.dst_port is none"))?,
            protocol: self
                .protocol
                .ok_or(DecodeError::from("ip_tuple.protocol is none"))?,
        })
    }
}

#[cfg(test)]
mod tests {

    use std::{net::IpAddr, str::FromStr};

    use netlink_packet_utils::{nla::NlaBuffer, Emitable, Parseable};

    use crate::ctnetlink::nlas::flow::ip_tuple::{IpTuple, ProtocolTuple};

    const DATA: [u8; 48] = [
        20, 0, 1, 128, 8, 0, 1, 0, 1, 2, 3, 4, 8, 0, 2, 0, 1, 2, 3, 4, 28, 0,
        2, 128, 5, 0, 1, 0, 17, 0, 0, 0, 6, 0, 2, 0, 220, 210, 0, 0, 6, 0, 3,
        0, 7, 108, 0, 0,
    ];

    #[test]
    fn test_ip_tuple_parse() {
        let buf = NlaBuffer::new(&DATA);
        let ip_tuple = IpTuple::parse(&buf).unwrap();
        assert_eq!(ip_tuple.src_addr, IpAddr::from_str("1.2.3.4").unwrap());
        assert_eq!(ip_tuple.dst_addr, IpAddr::from_str("1.2.3.4").unwrap());

        let buf = NlaBuffer::new(&DATA[ip_tuple.buffer_len()..]);
        let proto_tuple = ProtocolTuple::parse(&buf).unwrap();
        assert_eq!(proto_tuple.protocol, 17);
        assert_eq!(proto_tuple.src_port, 56530);
        assert_eq!(proto_tuple.dst_port, 1900);
    }

    #[test]
    fn test_ip_tuple_to_vec() {
        let buf = NlaBuffer::new(&DATA);
        let ip_tuple = IpTuple::parse(&buf).unwrap();
        assert_eq!(ip_tuple.src_addr, IpAddr::from_str("1.2.3.4").unwrap());
        assert_eq!(ip_tuple.dst_addr, IpAddr::from_str("1.2.3.4").unwrap());

        let mut attr_data = [0u8; 20];
        ip_tuple.emit(&mut attr_data);
        assert_eq!(attr_data, DATA[..20]);

        let buf = NlaBuffer::new(&DATA[ip_tuple.buffer_len()..]);
        let proto_tuple = ProtocolTuple::parse(&buf).unwrap();
        assert_eq!(proto_tuple.protocol, 17);
        assert_eq!(proto_tuple.src_port, 56530);
        assert_eq!(proto_tuple.dst_port, 1900);

        let mut attr_data = [0u8; 28];
        proto_tuple.emit(&mut attr_data);
        assert_eq!(attr_data, DATA[20..]);
    }
}
