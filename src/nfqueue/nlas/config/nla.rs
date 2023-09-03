// SPDX-License-Identifier: MIT

use byteorder::{BigEndian, ByteOrder};
use derive_more::IsVariant;

use netlink_packet_utils::{
    errors::DecodeError,
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::parse_u32_be,
    Emitable, Parseable,
};

use crate::{
    constants::{
        NFQA_CFG_CMD, //
        NFQA_CFG_FLAGS,
        NFQA_CFG_MASK,
        NFQA_CFG_PARAMS,
        NFQA_CFG_QUEUE_MAXLEN,
    },
    nfqueue::nlas::config::{
        config_cmd::ConfigCmd, //
        config_flags::ConfigFlags,
        config_params::ConfigParams,
    },
};

const U32_BYTES_SIZE: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq, IsVariant)]
pub enum ConfigNla {
    Cmd(ConfigCmd),
    Params(ConfigParams),
    QueueMaxLen(u32),
    Mask(ConfigFlags),
    Flags(ConfigFlags),
    Other(DefaultNla),
}

impl Nla for ConfigNla {
    fn value_len(&self) -> usize {
        match self {
            ConfigNla::Cmd(attr) => attr.buffer_len(),
            ConfigNla::Params(attr) => attr.buffer_len(),
            ConfigNla::QueueMaxLen(_) => U32_BYTES_SIZE,
            ConfigNla::Mask(attr) => attr.buffer_len(),
            ConfigNla::Flags(attr) => attr.buffer_len(),
            ConfigNla::Other(attr) => attr.buffer_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ConfigNla::Cmd(_) => NFQA_CFG_CMD,
            ConfigNla::Params(_) => NFQA_CFG_PARAMS,
            ConfigNla::QueueMaxLen(_) => NFQA_CFG_QUEUE_MAXLEN,
            ConfigNla::Mask(_) => NFQA_CFG_MASK,
            ConfigNla::Flags(_) => NFQA_CFG_FLAGS,
            ConfigNla::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ConfigNla::Cmd(attr) => attr.emit(buffer),
            ConfigNla::Params(attr) => attr.emit(buffer),
            ConfigNla::QueueMaxLen(attr) => BigEndian::write_u32(buffer, *attr),
            ConfigNla::Mask(attr) => attr.emit(buffer),
            ConfigNla::Flags(attr) => attr.emit(buffer),
            ConfigNla::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ConfigNla
{
    fn parse(buffer: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buffer.kind();
        let payload = buffer.value();
        match kind {
            NFQA_CFG_CMD => match ConfigCmd::parse(payload) {
                Ok(payload) => Ok(ConfigNla::Cmd(payload)),
                Err(error) => Err(error),
            },
            NFQA_CFG_PARAMS => match ConfigParams::parse(payload) {
                Ok(payload) => Ok(ConfigNla::Params(payload)),
                Err(error) => Err(error),
            },
            NFQA_CFG_QUEUE_MAXLEN => match parse_u32_be(payload) {
                Ok(payload) => Ok(ConfigNla::QueueMaxLen(payload)),
                Err(error) => Err(error),
            },
            NFQA_CFG_MASK => match ConfigFlags::parse(payload) {
                Ok(payload) => Ok(ConfigNla::Mask(payload)),
                Err(error) => Err(error),
            },
            NFQA_CFG_FLAGS => match ConfigFlags::parse(payload) {
                Ok(payload) => Ok(ConfigNla::Flags(payload)),
                Err(error) => Err(error),
            },
            _ => match DefaultNla::parse(buffer) {
                Ok(attr) => Ok(ConfigNla::Other(attr)),
                Err(error) => Err(error),
            },
        }
    }
}
