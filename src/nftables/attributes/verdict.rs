// SPDX-License-Identifier: MIT

use netlink_packet_core::{append_bytes, EncodeError};
use netlink_packet_core::{
    append_u32_be, parse_string, parse_u32_be, DecodeError, DefaultNla,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

const NFT_CONTINUE: u32 = -1 as _;
const NFT_BREAK: u32 = -2 as _;
const NFT_JUMP: u32 = -3 as _;
const NFT_GOTO: u32 = -4 as _;
const NFT_RETURN: u32 = -5 as _;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Verdict {
    /// Continue evaluation of the current rule
    Continue,
    /// Terminate evaluation of the current rule
    Break,
    /// Push the current chain on the jump stack and jump to a chain
    Jump,
    /// Jump to a chain without pushing the current chain on the jump
    Goto,
    /// Return to the topmost chain on the jump stack
    Return,
    Other(u32),
}

impl From<Verdict> for u32 {
    fn from(v: Verdict) -> Self {
        match v {
            Verdict::Continue => NFT_CONTINUE,
            Verdict::Break => NFT_BREAK,
            Verdict::Jump => NFT_JUMP,
            Verdict::Goto => NFT_GOTO,
            Verdict::Return => NFT_RETURN,
            Verdict::Other(code) => code,
        }
    }
}

impl From<u32> for Verdict {
    fn from(code: u32) -> Self {
        match code {
            NFT_CONTINUE => Verdict::Continue,
            NFT_BREAK => Verdict::Break,
            NFT_JUMP => Verdict::Jump,
            NFT_GOTO => Verdict::Goto,
            NFT_RETURN => Verdict::Return,
            _ => Verdict::Other(code),
        }
    }
}

const NFTA_VERDICT_UNSPEC: u16 = 0;
const NFTA_VERDICT_CODE: u16 = 1;
const NFTA_VERDICT_CHAIN: u16 = 2;
const NFTA_VERDICT_CHAIN_ID: u16 = 3;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerdictAttribute {
    Unspecified,
    Code(Verdict),
    Chain(String),
    ChainId(u32),
    Other(DefaultNla),
}

impl Nla for VerdictAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_VERDICT_UNSPEC,
            Self::Code(_) => NFTA_VERDICT_CODE,
            Self::Chain(_) => NFTA_VERDICT_CHAIN,
            Self::ChainId(_) => NFTA_VERDICT_CHAIN_ID,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::Code(code) => append_u32_be(out, (*code).into()),
            Self::Chain(chain) => {
                append_bytes(out, chain.as_bytes());
                out.push(0);
            }
            Self::ChainId(id) => append_u32_be(out, *id),
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for VerdictAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_VERDICT_UNSPEC => Self::Unspecified,
            NFTA_VERDICT_CODE => Self::Code(
                parse_u32_be(payload)
                    .context("invalid NFTA_VERDICT_CODE value")?
                    .into(),
            ),
            NFTA_VERDICT_CHAIN => Self::Chain(
                parse_string(payload)
                    .context("invalid NFTA_VERDICT_CHAIN value")?,
            ),
            NFTA_VERDICT_CHAIN_ID => Self::ChainId(
                parse_u32_be(payload)
                    .context("invalid NFTA_VERDICT_CHAIN_ID value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
