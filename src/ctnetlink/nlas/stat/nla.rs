// SPDX-License-Identifier: MIT

use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    Parseable,
};

use crate::constants::{
    CTA_STATS_CHAIN_TOOLONG, CTA_STATS_CLASH_RESOLVE, CTA_STATS_DELETE,
    CTA_STATS_DELETE_LIST, CTA_STATS_DROP, CTA_STATS_EARLY_DROP,
    CTA_STATS_ERROR, CTA_STATS_FOUND, CTA_STATS_IGNORE, CTA_STATS_INSERT,
    CTA_STATS_INSERT_FAILED, CTA_STATS_INVALID, CTA_STATS_NEW,
    CTA_STATS_SEARCHED, CTA_STATS_SEARCH_RESTART,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StatNla {
    Searched(u32), // no longer used
    Found(u32),
    New(u32), // no longer used
    Invalid(u32),
    Ignore(u32),     // no longer used
    Delete(u32),     // no longer used
    DeleteList(u32), // no longer used
    Insert(u32),
    InsertFailed(u32),
    Drop(u32),
    EarlyDrop(u32),
    Error(u32),
    SearchRestart(u32),
    ClashResolve(u32),
    ChainTooLong(u32),
    Other(DefaultNla),
}

impl Nla for StatNla {
    fn value_len(&self) -> usize {
        match self {
            StatNla::Searched(_) => 4,
            StatNla::Found(_) => 4,
            StatNla::New(_) => 4,
            StatNla::Invalid(_) => 4,
            StatNla::Ignore(_) => 4,
            StatNla::Delete(_) => 4,
            StatNla::DeleteList(_) => 4,
            StatNla::Insert(_) => 4,
            StatNla::InsertFailed(_) => 4,
            StatNla::Drop(_) => 4,
            StatNla::EarlyDrop(_) => 4,
            StatNla::Error(_) => 4,
            StatNla::SearchRestart(_) => 4,
            StatNla::ClashResolve(_) => 4,
            StatNla::ChainTooLong(_) => 4,
            StatNla::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            StatNla::Searched(_) => CTA_STATS_SEARCHED,
            StatNla::Found(_) => CTA_STATS_FOUND,
            StatNla::New(_) => CTA_STATS_NEW,
            StatNla::Invalid(_) => CTA_STATS_INVALID,
            StatNla::Ignore(_) => CTA_STATS_IGNORE,
            StatNla::Delete(_) => CTA_STATS_DELETE,
            StatNla::DeleteList(_) => CTA_STATS_DELETE_LIST,
            StatNla::Insert(_) => CTA_STATS_INSERT,
            StatNla::InsertFailed(_) => CTA_STATS_INSERT_FAILED,
            StatNla::Drop(_) => CTA_STATS_DROP,
            StatNla::EarlyDrop(_) => CTA_STATS_EARLY_DROP,
            StatNla::Error(_) => CTA_STATS_ERROR,
            StatNla::SearchRestart(_) => CTA_STATS_SEARCH_RESTART,
            StatNla::ClashResolve(_) => CTA_STATS_CLASH_RESOLVE,
            StatNla::ChainTooLong(_) => CTA_STATS_CHAIN_TOOLONG,
            StatNla::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            StatNla::Searched(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Found(val) => BigEndian::write_u32(buffer, *val),
            StatNla::New(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Invalid(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Ignore(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Delete(val) => BigEndian::write_u32(buffer, *val),
            StatNla::DeleteList(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Insert(val) => BigEndian::write_u32(buffer, *val),
            StatNla::InsertFailed(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Drop(val) => BigEndian::write_u32(buffer, *val),
            StatNla::EarlyDrop(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Error(val) => BigEndian::write_u32(buffer, *val),
            StatNla::SearchRestart(val) => BigEndian::write_u32(buffer, *val),
            StatNla::ClashResolve(val) => BigEndian::write_u32(buffer, *val),
            StatNla::ChainTooLong(val) => BigEndian::write_u32(buffer, *val),
            StatNla::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for StatNla
{
    fn parse(
        buf: &NlaBuffer<&'buffer T>,
    ) -> Result<Self, netlink_packet_utils::DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_STATS_SEARCHED => {
                StatNla::Searched(BigEndian::read_u32(payload))
            }
            CTA_STATS_FOUND => StatNla::Found(BigEndian::read_u32(payload)),
            CTA_STATS_NEW => StatNla::New(BigEndian::read_u32(payload)),
            CTA_STATS_INVALID => StatNla::Invalid(BigEndian::read_u32(payload)),
            CTA_STATS_IGNORE => StatNla::Ignore(BigEndian::read_u32(payload)),
            CTA_STATS_DELETE => StatNla::Delete(BigEndian::read_u32(payload)),
            CTA_STATS_DELETE_LIST => {
                StatNla::DeleteList(BigEndian::read_u32(payload))
            }
            CTA_STATS_INSERT => StatNla::Insert(BigEndian::read_u32(payload)),
            CTA_STATS_INSERT_FAILED => {
                StatNla::InsertFailed(BigEndian::read_u32(payload))
            }
            CTA_STATS_DROP => StatNla::Drop(BigEndian::read_u32(payload)),
            CTA_STATS_EARLY_DROP => {
                StatNla::EarlyDrop(BigEndian::read_u32(payload))
            }
            CTA_STATS_ERROR => StatNla::Error(BigEndian::read_u32(payload)),
            CTA_STATS_SEARCH_RESTART => {
                StatNla::SearchRestart(BigEndian::read_u32(payload))
            }
            CTA_STATS_CLASH_RESOLVE => {
                StatNla::ClashResolve(BigEndian::read_u32(payload))
            }
            CTA_STATS_CHAIN_TOOLONG => {
                StatNla::ChainTooLong(BigEndian::read_u32(payload))
            }
            _ => StatNla::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
