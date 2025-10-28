// SPDX-License-Identifier: MIT

use crate::{
    conntrack::ConntrackMessage,
    message::{
        NetfilterHeader, NetfilterMessage, NetfilterMessageInner, Subsystem,
        NETFILTER_HEADER_LEN,
    },
    nflog::ULogMessage,
};
use netlink_packet_core::{
    buffer, fields, DecodeError, DefaultNla, ErrorContext, NlaBuffer,
    NlasIterator, Parseable, ParseableParametrized,
};

buffer!(NetfilterBuffer(NETFILTER_HEADER_LEN) {
    header: (slice, ..NETFILTER_HEADER_LEN),
    payload: (slice, NETFILTER_HEADER_LEN..),
});

impl<'a, T: AsRef<[u8]> + ?Sized> NetfilterBuffer<&'a T> {
    pub fn nlas(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }

    pub fn parse_all_nlas<F, U>(&self, f: F) -> Result<Vec<U>, DecodeError>
    where
        F: Fn(NlaBuffer<&[u8]>) -> Result<U, DecodeError>,
    {
        self.nlas()
            .map(|buf| f(buf?))
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse NLAs")
    }

    pub fn default_nlas(&self) -> Result<Vec<DefaultNla>, DecodeError> {
        self.parse_all_nlas(|buf| DefaultNla::parse(&buf))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NetfilterBuffer<&'a T>, u16> for NetfilterMessage
{
    fn parse_with_param(
        buf: &NetfilterBuffer<&'a T>,
        message_type: u16,
    ) -> Result<Self, DecodeError> {
        let header_buf =
            crate::message::NetfilterHeaderBuffer::new(buf.inner());
        let header = NetfilterHeader::parse(&header_buf)
            .context("failed to parse netfilter header")?;
        let subsys = (message_type >> 8) as u8;
        let message_type = message_type as u8;
        let inner = match Subsystem::from(subsys) {
            Subsystem::ULog => NetfilterMessageInner::ULog(
                ULogMessage::parse_with_param(buf, message_type)
                    .context("failed to parse nflog payload")?,
            ),
            Subsystem::Conntrack => NetfilterMessageInner::Conntrack(
                ConntrackMessage::parse_with_param(buf, message_type)
                    .context("failed to parse conntrack payload")?,
            ),
            subsys_enum @ Subsystem::Other(_) => NetfilterMessageInner::Other {
                subsys: subsys_enum,
                message_type,
                attributes: buf.default_nlas()?,
            },
        };
        Ok(NetfilterMessage::new(header, inner))
    }
}
