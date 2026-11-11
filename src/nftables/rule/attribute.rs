// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_u32_be, append_u64_be, parse_string, parse_u32_be, parse_u64_be,
    DecodeError, DefaultNla, Emitable as _, ErrorContext as _, Nla, NlaBuffer,
    NlasIterator, Parseable, NLA_F_NESTED,
};

use crate::nftables::attributes::{
    list::VecListAttribute, ExpressionAttribute, ListAttribute,
};
use netlink_packet_core::{append_bytes, EncodeError};

const NFTA_RULE_UNSPEC: u16 = 0;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_HANDLE: u16 = 3;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_RULE_COMPAT: u16 = 5;
const NFTA_RULE_POSITION: u16 = 6;
const NFTA_RULE_USERDATA: u16 = 7;
//const NFTA_RULE_PAD: u16 = 8;
const NFTA_RULE_ID: u16 = 9;
const NFTA_RULE_POSITION_ID: u16 = 10;
const NFTA_RULE_CHAIN_ID: u16 = 11;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum RuleAttribute {
    Unspecified,
    /// Name of the table containing the rule.
    Table(String),
    /// Name of the chain containing the rule.
    Chain(String),
    /// Numeric handle of the rule.
    Handle(u64),
    /// List of expressions in the rule.
    Expressions(Vec<ListAttribute<ExpressionAttribute>>),
    /// Compatibility specifications of the rule.
    Compat(Vec<DefaultNla>),
    /// Numeric handle of the previous rule.
    Position(u64),
    /// Custom user data attached to the rule.
    UserData(Vec<u8>),
    /// Uniquely identifies a rule in a transaction.
    Id(u32),
    /// Transaction unique identifier of the previous rule.
    PositionId(u32),
    /// Add the rule to chain by ID.
    ///
    /// Alternative to [RuleAttribute::Chain].
    ChainId(u32),
    Other(DefaultNla),
}

impl Nla for RuleAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_RULE_UNSPEC,
            Self::Table(_) => NFTA_RULE_TABLE,
            Self::Chain(_) => NFTA_RULE_CHAIN,
            Self::Handle(_) => NFTA_RULE_HANDLE,
            Self::Expressions(_) => NFTA_RULE_EXPRESSIONS | NLA_F_NESTED,
            Self::Compat(_) => NFTA_RULE_COMPAT | NLA_F_NESTED,
            Self::Position(_) => NFTA_RULE_POSITION,
            Self::UserData(_) => NFTA_RULE_USERDATA,
            Self::Id(_) => NFTA_RULE_ID,
            Self::PositionId(_) => NFTA_RULE_POSITION_ID,
            Self::ChainId(_) => NFTA_RULE_CHAIN_ID,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::Table(string) | Self::Chain(string) => {
                append_bytes(out, string.as_bytes());
                out.push(0);
            }
            Self::Handle(value) | Self::Position(value) => {
                append_u64_be(out, *value)
            }
            Self::Expressions(attrs) => attrs.as_slice().emit(out)?,
            Self::Compat(attrs) => attrs.as_slice().emit(out)?,
            Self::UserData(bytes) => append_bytes(out, bytes.as_slice()),
            Self::Id(value)
            | Self::PositionId(value)
            | Self::ChainId(value) => append_u32_be(out, *value),
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::Expressions(_) | Self::Compat(_))
            || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for RuleAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_RULE_UNSPEC => Self::Unspecified,
            NFTA_RULE_TABLE => Self::Table(
                parse_string(payload)
                    .context("invalid NFTA_RULE_TABLE value")?,
            ),
            NFTA_RULE_CHAIN => Self::Chain(
                parse_string(payload)
                    .context("invalid NFTA_RULE_CHAIN value")?,
            ),
            NFTA_RULE_HANDLE => Self::Handle(
                parse_u64_be(payload)
                    .context("invalid NFTA_RULE_HANDLE value")?,
            ),
            NFTA_RULE_EXPRESSIONS => Self::Expressions(
                VecListAttribute::parse(payload)
                    .context("invalid NFTA_RULE_EXPRESSIONS value")?
                    .0,
            ),
            NFTA_RULE_COMPAT => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload)? {
                    nlas.push(DefaultNla::parse(&nla)?);
                }
                Self::Compat(nlas)
            }
            NFTA_RULE_POSITION => Self::Position(
                parse_u64_be(payload)
                    .context("invalid NFTA_RULE_POSITION value")?,
            ),
            NFTA_RULE_USERDATA => Self::UserData(payload.to_vec()),
            NFTA_RULE_ID => Self::Id(
                parse_u32_be(payload).context("invalid NFTA_RULE_ID value")?,
            ),
            NFTA_RULE_POSITION_ID => Self::PositionId(
                parse_u32_be(payload)
                    .context("invalid NFTA_RULE_POSITION_ID value")?,
            ),
            NFTA_RULE_CHAIN_ID => Self::ChainId(
                parse_u32_be(payload)
                    .context("invalid NFTA_RULE_CHAIN_ID value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
