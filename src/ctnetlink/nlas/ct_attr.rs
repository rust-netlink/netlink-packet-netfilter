// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NLA_F_NESTED, NLA_HEADER_SIZE},
    DecodeError, Emitable, Parseable,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConntrackAttribute {
    pub nested: Option<Vec<ConntrackAttribute>>,
    pub attr_type: u16,
    pub length: u16,
    pub value: Option<Vec<u8>>,
}

impl Nla for ConntrackAttribute {
    fn value_len(&self) -> usize {
        (self.length as usize) - NLA_HEADER_SIZE
    }

    fn kind(&self) -> u16 {
        if self.is_nested() {
            self.attr_type | NLA_F_NESTED
        } else {
            self.attr_type
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        if let Some(attrs) = &self.nested {
            let mut attrs_buf = vec![];
            for attr in attrs.iter() {
                let l = if attr.length % 4 != 0 {
                    attr.length + 4 - (attr.length % 4)
                } else {
                    attr.length
                } as usize;
                let mut buf = vec![0u8; l];
                attr.emit(&mut buf);
                attrs_buf.append(&mut buf);
            }
            buffer[..attrs_buf.len()].copy_from_slice(&attrs_buf);
        } else if let Some(value) = &self.value {
            buffer[..value.len()].copy_from_slice(value);
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ConntrackAttribute
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let length = buf.length();
        let is_nested = buf.nested_flag();
        let attr_type = buf.kind();
        let value_l = (length as usize) - NLA_HEADER_SIZE;
        let value = buf.value();
        if is_nested {
            let mut nested_attrs = vec![];
            let mut read = 0;
            while value_l > read {
                let nla_buf = NlaBuffer::new(&value[read..]);
                let attr = Self::parse(&nla_buf)?;
                read += attr.length as usize;
                if attr.length % 4 != 0 {
                    read += 4 - (attr.length as usize % 4);
                }
                nested_attrs.push(attr);
            }
            Ok(ConntrackAttribute {
                nested: Some(nested_attrs),
                length,
                attr_type,
                value: None,
            })
        } else {
            Ok(ConntrackAttribute {
                nested: None,
                attr_type,
                // padding bytes are not included
                length,
                value: Some(value[..value_l].to_vec()),
            })
        }
    }
}

impl ConntrackAttribute {
    pub fn is_nested(&self) -> bool {
        self.nested.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct CtAttrBuilder {
    nested: Option<Vec<ConntrackAttribute>>,
    attr_type: u16,
    value: Option<Vec<u8>>,
    length: u16,
}

impl CtAttrBuilder {
    pub fn new(attr_type: u16) -> CtAttrBuilder {
        CtAttrBuilder {
            nested: None,
            attr_type,
            value: None,
            length: 0,
        }
    }
    pub fn nested_attr(mut self, attr: ConntrackAttribute) -> Self {
        self.length += attr.length;
        if attr.length % 4 != 0 {
            self.length += 4 - (attr.length % 4);
        }
        if let Some(ref mut nested) = self.nested {
            nested.push(attr);
        } else {
            self.nested = Some(vec![attr]);
        }
        self.attr_type |= NLA_F_NESTED;
        self
    }

    pub fn value(mut self, v: &[u8]) -> Self {
        self.length += v.len() as u16;
        self.value = Some(v.to_vec());
        self
    }

    pub fn build(&self) -> ConntrackAttribute {
        ConntrackAttribute {
            nested: self.nested.clone(),
            attr_type: self.attr_type,
            length: self.length + NLA_HEADER_SIZE as u16,
            value: self.value.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use netlink_packet_utils::{nla::NlaBuffer, Emitable, Parseable};

    use crate::ctnetlink::nlas::ct_attr::ConntrackAttribute;
    const DATA: [u8; 48] = [
        20, 0, 1, 128, 8, 0, 1, 0, 1, 2, 3, 4, 8, 0, 2, 0, 1, 2, 3, 4, 28, 0,
        2, 128, 5, 0, 1, 0, 17, 0, 0, 0, 6, 0, 2, 0, 220, 210, 0, 0, 6, 0, 3,
        0, 7, 108, 0, 0,
    ];

    const CTA_IP_V4_SRC: u16 = 1;
    const CTA_IP_V4_DST: u16 = 2;

    const CTA_TUPLE_IP: u16 = 1;
    const CTA_TUPLE_PROTO: u16 = 2;

    const CTA_PROTO_NUM: u16 = 1;
    const CTA_PROTO_SRC_PORT: u16 = 2;
    const CTA_PROTO_DST_PORT: u16 = 3;

    #[test]
    fn test_ct_attr_parse() {
        let buf = NlaBuffer::new(&DATA);
        // first
        let ct_attr = ConntrackAttribute::parse(&buf).unwrap();
        assert_eq!(ct_attr.length, 20);
        assert!(ct_attr.is_nested());
        assert_eq!(ct_attr.attr_type, CTA_TUPLE_IP);

        let nested_attrs = ct_attr.nested.unwrap();
        assert_eq!(nested_attrs.len(), 2);
        assert_eq!(nested_attrs[0].attr_type, CTA_IP_V4_SRC);
        assert_eq!(nested_attrs[0].length, 8);

        assert_eq!(nested_attrs[1].attr_type, CTA_IP_V4_DST);
        assert_eq!(nested_attrs[1].length, 8);

        // second
        let buf = NlaBuffer::new(&DATA[(ct_attr.length as usize)..]);
        let ct_attr = ConntrackAttribute::parse(&buf).unwrap();
        assert_eq!(ct_attr.length, 28);
        assert!(ct_attr.is_nested());
        assert_eq!(ct_attr.attr_type, CTA_TUPLE_PROTO);
        let nested_attr = ct_attr.nested.unwrap();
        assert_eq!(nested_attr.len(), 3);
        assert_eq!(nested_attr[0].attr_type, CTA_PROTO_NUM);
        assert_eq!(nested_attr[1].attr_type, CTA_PROTO_SRC_PORT);
        assert_eq!(nested_attr[2].attr_type, CTA_PROTO_DST_PORT);
    }

    #[test]
    fn test_ct_attr_emit() {
        let buf = NlaBuffer::new(&DATA);
        let ct_attr = ConntrackAttribute::parse(&buf).unwrap();
        assert_eq!(ct_attr.length, 20);
        assert!(ct_attr.is_nested());
        assert_eq!(ct_attr.attr_type, CTA_TUPLE_IP);

        let mut attr_data = [0u8; 20];
        ct_attr.emit(&mut attr_data);
        assert_eq!(attr_data, DATA[..20])
    }
}
