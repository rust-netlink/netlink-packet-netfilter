// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    buffer, fields, getter, setter, DecodeError, Emitable, Parseable,
};

const TCP_FLAGS_LEN: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TCPFlags {
    pub flags: u8,
    pub mask: u8,
}

buffer!(TCPFlagsBuffer(TCP_FLAGS_LEN) {
    flags: (u8, 0),
    mask: (u8, 1),
});

impl<T: AsRef<[u8]>> Parseable<TCPFlagsBuffer<T>> for TCPFlags {
    fn parse(buf: &TCPFlagsBuffer<T>) -> Result<Self, DecodeError> {
        Ok(TCPFlags {
            flags: buf.flags(),
            mask: buf.mask(),
        })
    }
}

impl Emitable for TCPFlags {
    fn buffer_len(&self) -> usize {
        TCP_FLAGS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = TCPFlagsBuffer::new(buffer);
        buffer.set_flags(self.flags);
        buffer.set_mask(self.mask);
    }
}
