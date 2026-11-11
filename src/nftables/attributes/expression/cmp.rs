// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_u32_be, parse_u32_be, DecodeError, DefaultNla, ErrorContext as _,
    Nla, NlaBuffer, Parseable, NLA_F_NESTED,
};

use crate::nftables::attributes::{expression::Register, DataAttribute};
use netlink_packet_core::EncodeError;

/**
 * enum nft_cmp_ops - nf_tables relational operator
 *
 * @NFT_CMP_EQ: equal
 * @NFT_CMP_NEQ: not equal
 * @NFT_CMP_LT: less than
 * @NFT_CMP_LTE: less than or equal to
 * @NFT_CMP_GT: greater than
 * @NFT_CMP_GTE: greater than or equal to
 */
const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_NEQ: u32 = 1;
const NFT_CMP_LT: u32 = 2;
const NFT_CMP_LTE: u32 = 3;
const NFT_CMP_GT: u32 = 4;
const NFT_CMP_GTE: u32 = 5;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
/// Relational Operator
pub enum Operator {
    Equal,
    NotEqual,
    LessThan,
    LessThanEqual,
    GreaterThan,
    GreatherThanEqual,
    Other(u32),
}

impl From<Operator> for u32 {
    fn from(op: Operator) -> Self {
        match op {
            Operator::Equal => NFT_CMP_EQ,
            Operator::NotEqual => NFT_CMP_NEQ,
            Operator::LessThan => NFT_CMP_LT,
            Operator::LessThanEqual => NFT_CMP_LTE,
            Operator::GreaterThan => NFT_CMP_GT,
            Operator::GreatherThanEqual => NFT_CMP_GTE,
            Operator::Other(op_num) => op_num,
        }
    }
}

impl From<u32> for Operator {
    fn from(op_num: u32) -> Self {
        match op_num {
            NFT_CMP_EQ => Operator::Equal,
            NFT_CMP_NEQ => Operator::NotEqual,
            NFT_CMP_LT => Operator::LessThan,
            NFT_CMP_LTE => Operator::LessThanEqual,
            NFT_CMP_GT => Operator::GreaterThan,
            NFT_CMP_GTE => Operator::GreatherThanEqual,
            op_num => Operator::Other(op_num),
        }
    }
}

const NFTA_CMP_UNSPEC: u16 = 0;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;

#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Cmp {
    Unspecified,
    SourceRegister(Register),
    /// Comparison operation.
    Op(Operator),
    /// Data to compare against.
    Data(DataAttribute),
    Other(DefaultNla),
}

impl Nla for Cmp {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_CMP_UNSPEC,
            Self::SourceRegister(_) => NFTA_CMP_SREG,
            Self::Op(_) => NFTA_CMP_OP,
            Self::Data(_) => NFTA_CMP_DATA | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::SourceRegister(reg) => append_u32_be(out, (*reg).into()),
            Self::Op(value) => append_u32_be(out, (*value).into()),
            Self::Data(data) => data.emit(out)?,
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Data(_)) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for Cmp {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_CMP_UNSPEC => Self::Unspecified,
            NFTA_CMP_SREG => Self::SourceRegister(
                parse_u32_be(payload)
                    .context("invalid NFTA_CMP_SREG value")?
                    .into(),
            ),
            NFTA_CMP_OP => Self::Op(
                parse_u32_be(payload)
                    .context("invalid NFTA_CMP_OP value")?
                    .into(),
            ),
            NFTA_CMP_DATA => Self::Data(
                DataAttribute::parse(&NlaBuffer::new(payload)?)
                    .context(format!("invalid NFTA_CMP_DATA {:?}", payload))?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
