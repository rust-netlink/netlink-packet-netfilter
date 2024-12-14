// SPDX-License-Identifier: MIT

use std::convert::TryFrom;

use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NLA_F_NESTED},
    DecodeError, Emitable, Parseable,
};

use crate::{
    constants::{
        CTA_PROTOINFO_DCCP, CTA_PROTOINFO_SCTP, CTA_PROTOINFO_TCP,
        CTA_PROTOINFO_TCP_FLAGS_ORIGINAL, CTA_PROTOINFO_TCP_FLAGS_REPLY,
        CTA_PROTOINFO_TCP_STATE, CTA_PROTOINFO_TCP_WSCALE_ORIGINAL,
        CTA_PROTOINFO_TCP_WSCALE_REPLY, CTA_PROTOINFO_UNSPEC,
    },
    ctnetlink::nlas::flow::CtAttrBuilder,
};

use super::CtAttr;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ProtocolInfo {
    Tcp(ProtocolInfoTcp),
    Dccp(CtAttr),
    Sctp(CtAttr),
    Other(CtAttr),
}

impl ProtocolInfo {
    pub(super) fn parse_from_bytes(
        buf: &[u8],
    ) -> Result<ProtocolInfo, DecodeError> {
        let b = NlaBuffer::new(buf);
        ProtocolInfo::parse(&b)
    }
}

impl Nla for ProtocolInfo {
    fn value_len(&self) -> usize {
        match self {
            ProtocolInfo::Tcp(info) => info.buffer_len(),
            ProtocolInfo::Dccp(attr) => attr.buffer_len(),
            ProtocolInfo::Sctp(attr) => attr.buffer_len(),
            ProtocolInfo::Other(attr) => attr.buffer_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ProtocolInfo::Tcp(_) => CTA_PROTOINFO_TCP | NLA_F_NESTED,
            ProtocolInfo::Dccp(_) => CTA_PROTOINFO_DCCP | NLA_F_NESTED,
            ProtocolInfo::Sctp(_) => CTA_PROTOINFO_SCTP | NLA_F_NESTED,
            ProtocolInfo::Other(_) => CTA_PROTOINFO_UNSPEC,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ProtocolInfo::Tcp(info) => info.emit(buffer),
            ProtocolInfo::Dccp(attr) => attr.emit(buffer),
            ProtocolInfo::Sctp(attr) => attr.emit(buffer),
            ProtocolInfo::Other(attr) => attr.emit(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ProtocolInfo
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let attr = CtAttr::parse(buf)?;

        match attr.attr_type {
            CTA_PROTOINFO_TCP => {
                Ok(ProtocolInfo::Tcp(ProtocolInfoTcp::try_from(attr)?))
            }
            CTA_PROTOINFO_DCCP => Ok(ProtocolInfo::Dccp(attr)),
            CTA_PROTOINFO_SCTP => Ok(ProtocolInfo::Sctp(attr)),
            _ => Ok(ProtocolInfo::Other(attr)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct ProtocolInfoTcp {
    state: u8,
    wscale_original: u8,
    wscale_reply: u8,
    flgas_original: u16,
    flags_reply: u16,
}

impl Nla for ProtocolInfoTcp {
    fn value_len(&self) -> usize {
        40
    }

    fn kind(&self) -> u16 {
        CTA_PROTOINFO_TCP | NLA_F_NESTED
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        let mut flag_orig = [0u8; 2];
        let mut flag_reply = [0u8; 2];
        NativeEndian::write_u16(&mut flag_orig, self.flgas_original);
        NativeEndian::write_u16(&mut flag_reply, self.flags_reply);

        let info = CtAttrBuilder::new(CTA_PROTOINFO_TCP)
            .nested_attr(
                CtAttrBuilder::new(CTA_PROTOINFO_TCP_STATE)
                    .value(vec![self.state].as_ref())
                    .build(),
            )
            .nested_attr(
                CtAttrBuilder::new(CTA_PROTOINFO_TCP_WSCALE_ORIGINAL)
                    .value(vec![self.wscale_original].as_ref())
                    .build(),
            )
            .nested_attr(
                CtAttrBuilder::new(CTA_PROTOINFO_TCP_WSCALE_REPLY)
                    .value(vec![self.wscale_reply].as_ref())
                    .build(),
            )
            .nested_attr(
                CtAttrBuilder::new(CTA_PROTOINFO_TCP_FLAGS_ORIGINAL)
                    .value(&flag_orig)
                    .build(),
            )
            .nested_attr(
                CtAttrBuilder::new(CTA_PROTOINFO_TCP_FLAGS_REPLY)
                    .value(&flag_reply)
                    .build(),
            )
            .build();
        info.emit_value(buffer);
    }
}

impl TryFrom<CtAttr> for ProtocolInfoTcp {
    type Error = DecodeError;

    fn try_from(attr: CtAttr) -> Result<Self, Self::Error> {
        if let Some(attrs) = attr.nested {
            let mut info = ProtocolInfoTcp::default();
            for attr in attrs.iter() {
                match attr.attr_type {
                    CTA_PROTOINFO_TCP_STATE => {
                        if let Some(v) = &attr.value {
                            if v.len() != 1 {
                                return Err(DecodeError::from(
                                    "invalid CTA_PROTOINFO_TCP_STATE value",
                                ));
                            }
                            info.state = v[0];
                        }
                    }
                    CTA_PROTOINFO_TCP_WSCALE_ORIGINAL => {
                        if let Some(v) = &attr.value {
                            if v.len() != 1 {
                                return Err(DecodeError::from("invalid CTA_PROTOINFO_TCP_WSCALE_ORIGINAL value"));
                            }
                            info.wscale_original = v[0];
                        }
                    }
                    CTA_PROTOINFO_TCP_WSCALE_REPLY => {
                        if let Some(v) = &attr.value {
                            if v.len() != 1 {
                                return Err(DecodeError::from("invalid CTA_PROTOINFO_TCP_WSCALE_REPLY value"));
                            }
                            info.wscale_reply = v[0];
                        }
                    }
                    CTA_PROTOINFO_TCP_FLAGS_ORIGINAL => {
                        if let Some(v) = &attr.value {
                            info.flgas_original = NativeEndian::read_u16(v);
                        }
                    }
                    CTA_PROTOINFO_TCP_FLAGS_REPLY => {
                        if let Some(v) = &attr.value {
                            info.flags_reply = NativeEndian::read_u16(v);
                        }
                    }
                    _ => {}
                }
            }
            Ok(info)
        } else {
            Err(DecodeError::from(
                "CTA_PROTOINFO_TCP must have nested attributes",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use netlink_packet_utils::{
        nla::{NlaBuffer, NLA_HEADER_SIZE},
        Emitable, Parseable,
    };

    use super::ProtocolInfo;
    const DATA: [u8; 44] = [
        44, 0, 1, 128, 5, 0, 1, 0, 3, 0, 0, 0, 5, 0, 2, 0, 7, 0, 0, 0, 5, 0, 3,
        0, 7, 0, 0, 0, 6, 0, 4, 0, 35, 0, 0, 0, 6, 0, 5, 0, 35, 0, 0, 0,
    ];

    #[test]
    fn test_protocol_info_parse() {
        let buf = NlaBuffer::new(&DATA);
        let info = ProtocolInfo::parse(&buf).unwrap();
        if let ProtocolInfo::Tcp(info) = info {
            assert_eq!(info.state, 3);
            assert_eq!(info.wscale_original, 7);
            assert_eq!(info.wscale_reply, 7);
            assert_eq!(info.flgas_original, 35);
            assert_eq!(info.flags_reply, 35);
        } else {
            panic!("invalid protocol info")
        }
    }

    #[test]
    fn test_protocol_info_emit() {
        let buf = NlaBuffer::new(&DATA);
        let info = ProtocolInfo::parse(&buf).unwrap();
        if let ProtocolInfo::Tcp(info) = info {
            assert_eq!(info.state, 3);
            assert_eq!(info.wscale_original, 7);
            assert_eq!(info.wscale_reply, 7);
            assert_eq!(info.flgas_original, 35);
            assert_eq!(info.flags_reply, 35);
        } else {
            panic!("invalid protocol info")
        }

        let mut attr_data = [0u8; 48];
        info.emit(&mut attr_data);
        assert_eq!(attr_data[NLA_HEADER_SIZE..], DATA);
    }
}
