// SPDX-License-Identifier: MIT

use derive_more::{From, IsVariant};
use netlink_packet_core::{
    append_u32_be, parse_u16_be, parse_u32_be, parse_u8, DecodeError,
    DefaultNla, ErrorContext, Nla, NlaBuffer, Parseable,
};

use crate::nflog::nlas::config::{ConfigCmd, ConfigFlags, ConfigMode, Timeout};
use netlink_packet_core::EncodeError;

const NFULA_CFG_CMD: u16 = libc::NFULA_CFG_CMD as u16;
const NFULA_CFG_FLAGS: u16 = libc::NFULA_CFG_FLAGS as u16;
const NFULA_CFG_MODE: u16 = libc::NFULA_CFG_MODE as u16;
const NFULA_CFG_NLBUFSIZ: u16 = libc::NFULA_CFG_NLBUFSIZ as u16;
const NFULA_CFG_QTHRESH: u16 = libc::NFULA_CFG_QTHRESH as u16;
const NFULA_CFG_TIMEOUT: u16 = libc::NFULA_CFG_TIMEOUT as u16;

#[derive(Clone, Debug, PartialEq, Eq, From, IsVariant)]
#[non_exhaustive]
pub enum ConfigNla {
    Cmd(ConfigCmd),
    Mode(ConfigMode),
    #[from(ignore)]
    NlBufSiz(u32),
    Timeout(Timeout),
    #[from(ignore)]
    QThresh(u32),
    Flags(ConfigFlags),
    Other(DefaultNla),
}

impl Nla for ConfigNla {
    fn kind(&self) -> u16 {
        match self {
            ConfigNla::Cmd(attr) => attr.kind(),
            ConfigNla::Mode(attr) => attr.kind(),
            ConfigNla::NlBufSiz(_) => NFULA_CFG_NLBUFSIZ,
            ConfigNla::Timeout(attr) => attr.kind(),
            ConfigNla::QThresh(_) => NFULA_CFG_QTHRESH,
            ConfigNla::Flags(attr) => attr.kind(),
            ConfigNla::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            ConfigNla::Cmd(attr) => return attr.emit_value(out),
            ConfigNla::Mode(attr) => return attr.emit_value(out),
            ConfigNla::NlBufSiz(buf_siz) => {
                append_u32_be(out, *buf_siz);
            }
            ConfigNla::Timeout(attr) => return attr.emit_value(out),
            ConfigNla::QThresh(q_thresh) => {
                append_u32_be(out, *q_thresh);
            }
            ConfigNla::Flags(attr) => return attr.emit_value(out),
            ConfigNla::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
}

impl<'buffer> Parseable<NlaBuffer<'buffer>> for ConfigNla {
    fn parse(buf: &NlaBuffer<'buffer>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            NFULA_CFG_CMD => ConfigCmd::from(
                parse_u8(payload).context("invalid NFULA_CFG_CMD value")?,
            )
            .into(),
            NFULA_CFG_MODE => ConfigMode::parse(payload)
                .context("invalid NFULA_CFG_MODE value")?
                .into(),
            NFULA_CFG_NLBUFSIZ => ConfigNla::NlBufSiz(
                parse_u32_be(payload)
                    .context("invalid NFULA_CFG_NLBUFSIZ value")?,
            ),
            NFULA_CFG_TIMEOUT => Timeout::new(
                parse_u32_be(payload)
                    .context("invalid NFULA_CFG_TIMEOUT value")?,
            )
            .into(),
            NFULA_CFG_QTHRESH => ConfigNla::QThresh(
                parse_u32_be(payload)
                    .context("invalid NFULA_CFG_QTHRESH value")?,
            ),
            NFULA_CFG_FLAGS => ConfigFlags::from_bits_preserve(
                parse_u16_be(payload)
                    .context("invalid NFULA_CFG_FLAGS value")?,
            )
            .into(),
            _ => ConfigNla::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
