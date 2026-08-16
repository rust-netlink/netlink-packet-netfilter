// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, ErrorContext, NlaBuffer, NlasIterator, Parseable,
};

pub(crate) fn parse_all_nlas<F, U>(
    payload: &[u8],
    f: F,
) -> Result<Vec<U>, DecodeError>
where
    F: Fn(NlaBuffer<&[u8]>) -> Result<U, DecodeError>,
{
    NlasIterator::new(payload)
        .map(|buf| f(buf?))
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse NLAs")
}

pub(crate) fn default_nlas(
    payload: &[u8],
) -> Result<Vec<DefaultNla>, DecodeError> {
    parse_all_nlas(payload, |buf| DefaultNla::parse(&buf))
}
