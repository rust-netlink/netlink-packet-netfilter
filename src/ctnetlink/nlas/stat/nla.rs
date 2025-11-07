// SPDX-License-Identifier: MIT

use byteorder::{BigEndian, ByteOrder};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    Parseable,
};

const CTA_STATS_FOUND: u16 = 2;
const CTA_STATS_INVALID: u16 = 4;
const CTA_STATS_INSERT: u16 = 8;
const CTA_STATS_INSERT_FAILED: u16 = 9;
const CTA_STATS_DROP: u16 = 10;
const CTA_STATS_EARLY_DROP: u16 = 11;
const CTA_STATS_ERROR: u16 = 12;
const CTA_STATS_SEARCH_RESTART: u16 = 13;
const CTA_STATS_CLASH_RESOLVE: u16 = 14;
const CTA_STATS_CHAIN_TOOLONG: u16 = 15;

const CTA_STATS_GLOBAL_ENTRIES: u16 = 1;
const CTA_STATS_GLOBAL_MAX_ENTRIES: u16 = 2;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StatCpuAttribute {
    Found(u32),
    Invalid(u32),
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

impl Nla for StatCpuAttribute {
    fn value_len(&self) -> usize {
        match self {
            StatCpuAttribute::Found(_) => 4,
            StatCpuAttribute::Invalid(_) => 4,
            StatCpuAttribute::Insert(_) => 4,
            StatCpuAttribute::InsertFailed(_) => 4,
            StatCpuAttribute::Drop(_) => 4,
            StatCpuAttribute::EarlyDrop(_) => 4,
            StatCpuAttribute::Error(_) => 4,
            StatCpuAttribute::SearchRestart(_) => 4,
            StatCpuAttribute::ClashResolve(_) => 4,
            StatCpuAttribute::ChainTooLong(_) => 4,
            StatCpuAttribute::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            StatCpuAttribute::Found(_) => CTA_STATS_FOUND,
            StatCpuAttribute::Invalid(_) => CTA_STATS_INVALID,
            StatCpuAttribute::Insert(_) => CTA_STATS_INSERT,
            StatCpuAttribute::InsertFailed(_) => CTA_STATS_INSERT_FAILED,
            StatCpuAttribute::Drop(_) => CTA_STATS_DROP,
            StatCpuAttribute::EarlyDrop(_) => CTA_STATS_EARLY_DROP,
            StatCpuAttribute::Error(_) => CTA_STATS_ERROR,
            StatCpuAttribute::SearchRestart(_) => CTA_STATS_SEARCH_RESTART,
            StatCpuAttribute::ClashResolve(_) => CTA_STATS_CLASH_RESOLVE,
            StatCpuAttribute::ChainTooLong(_) => CTA_STATS_CHAIN_TOOLONG,
            StatCpuAttribute::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            StatCpuAttribute::Found(val) => BigEndian::write_u32(buffer, *val),
            StatCpuAttribute::Invalid(val) => {
                BigEndian::write_u32(buffer, *val)
            }
            StatCpuAttribute::Insert(val) => BigEndian::write_u32(buffer, *val),
            StatCpuAttribute::InsertFailed(val) => {
                BigEndian::write_u32(buffer, *val)
            }
            StatCpuAttribute::Drop(val) => BigEndian::write_u32(buffer, *val),
            StatCpuAttribute::EarlyDrop(val) => {
                BigEndian::write_u32(buffer, *val)
            }
            StatCpuAttribute::Error(val) => BigEndian::write_u32(buffer, *val),
            StatCpuAttribute::SearchRestart(val) => {
                BigEndian::write_u32(buffer, *val)
            }
            StatCpuAttribute::ClashResolve(val) => {
                BigEndian::write_u32(buffer, *val)
            }
            StatCpuAttribute::ChainTooLong(val) => {
                BigEndian::write_u32(buffer, *val)
            }
            StatCpuAttribute::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for StatCpuAttribute
{
    fn parse(
        buf: &NlaBuffer<&'buffer T>,
    ) -> Result<Self, netlink_packet_utils::DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_STATS_FOUND => {
                StatCpuAttribute::Found(BigEndian::read_u32(payload))
            }
            CTA_STATS_INVALID => {
                StatCpuAttribute::Invalid(BigEndian::read_u32(payload))
            }
            CTA_STATS_INSERT => {
                StatCpuAttribute::Insert(BigEndian::read_u32(payload))
            }
            CTA_STATS_INSERT_FAILED => {
                StatCpuAttribute::InsertFailed(BigEndian::read_u32(payload))
            }
            CTA_STATS_DROP => {
                StatCpuAttribute::Drop(BigEndian::read_u32(payload))
            }
            CTA_STATS_EARLY_DROP => {
                StatCpuAttribute::EarlyDrop(BigEndian::read_u32(payload))
            }
            CTA_STATS_ERROR => {
                StatCpuAttribute::Error(BigEndian::read_u32(payload))
            }
            CTA_STATS_SEARCH_RESTART => {
                StatCpuAttribute::SearchRestart(BigEndian::read_u32(payload))
            }
            CTA_STATS_CLASH_RESOLVE => {
                StatCpuAttribute::ClashResolve(BigEndian::read_u32(payload))
            }
            CTA_STATS_CHAIN_TOOLONG => {
                StatCpuAttribute::ChainTooLong(BigEndian::read_u32(payload))
            }
            _ => StatCpuAttribute::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StatGlobalAttribute {
    Entries(u32),
    MaxEntries(u32),
    Other(DefaultNla),
}

impl Nla for StatGlobalAttribute {
    fn value_len(&self) -> usize {
        match self {
            StatGlobalAttribute::Entries(_) => 4,
            StatGlobalAttribute::MaxEntries(_) => 4,
            StatGlobalAttribute::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            StatGlobalAttribute::Entries(_) => CTA_STATS_GLOBAL_ENTRIES,
            StatGlobalAttribute::MaxEntries(_) => CTA_STATS_GLOBAL_MAX_ENTRIES,
            StatGlobalAttribute::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            StatGlobalAttribute::Entries(val) => {
                BigEndian::write_u32(buffer, *val)
            }
            StatGlobalAttribute::MaxEntries(val) => {
                BigEndian::write_u32(buffer, *val)
            }
            StatGlobalAttribute::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for StatGlobalAttribute
{
    fn parse(
        buf: &NlaBuffer<&'buffer T>,
    ) -> Result<Self, netlink_packet_utils::DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_STATS_GLOBAL_ENTRIES => {
                StatGlobalAttribute::Entries(BigEndian::read_u32(payload))
            }
            CTA_STATS_GLOBAL_MAX_ENTRIES => {
                StatGlobalAttribute::MaxEntries(BigEndian::read_u32(payload))
            }
            _ => StatGlobalAttribute::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
