// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_u32_be, append_u64_be, parse_string, parse_u32_be, parse_u64_be,
    DecodeError, DefaultNla, Emitable, ErrorContext as _, Nla, NlaBuffer,
    Parseable, ParseableParametrized, NLA_F_NESTED,
};

use crate::nftables::{
    attributes::{list::VecListAttribute, ExpressionAttribute, ListAttribute},
    set::{description::VecSetDescription, SetDescription, SetFlags},
};
use netlink_packet_core::{append_bytes, EncodeError};

// Defined in Linux kernel: include/uapi/linux/netfilter/nf_tables.h
const NFTA_SET_UNSEPC: u16 = 0;
const NFTA_SET_TABLE: u16 = 1;
const NFTA_SET_NAME: u16 = 2;
const NFTA_SET_FLAGS: u16 = 3;
const NFTA_SET_KEY_TYPE: u16 = 4;
const NFTA_SET_KEY_LEN: u16 = 5;
const NFTA_SET_DATA_TYPE: u16 = 6;
const NFTA_SET_DATA_LEN: u16 = 7;
const NFTA_SET_POLICY: u16 = 8;
const NFTA_SET_DESC: u16 = 9;
const NFTA_SET_ID: u16 = 10;
const NFTA_SET_TIMEOUT: u16 = 11;
const NFTA_SET_GC_INTERVAL: u16 = 12;
const NFTA_SET_USERDATA: u16 = 13;
//const NFTA_SET_PAD: u16 = 14;
const NFTA_SET_OBJ_TYPE: u16 = 15;
const NFTA_SET_HANDLE: u16 = 16;
const NFTA_SET_EXPR: u16 = 17;
const NFTA_SET_EXPRESSIONS: u16 = 18;
const NFTA_SET_TYPE: u16 = 19;
const NFTA_SET_COUNT: u16 = 20;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum SetAttribute {
    Unspecified,
    /// Table Name.
    Table(String),
    /// Name of this set.
    Name(String),
    Flags(SetFlags),
    /// Key data type.
    ///
    /// Informational purpose only.
    KeyType(u32),
    /// Key data length.
    KeyLen(u32),
    /// Mapping data type.
    DataType(u32),
    /// Mapping data length.
    DataLen(u32),
    /// Selection policy.
    Policy(u32),
    /// Set's description.
    Description(Vec<SetDescription>),
    /// Uniquely identifies a set in a transaction.
    Id(u32),
    /// Default timeout value.
    Timeout(u64),
    GarbageCollectionInterval(u32),
    UserData(Vec<u8>),
    /// Stateful object type.
    ObjectType(u32),
    Handle(u64),
    Expression(ExpressionAttribute),
    ListExpressions(Vec<ListAttribute<ExpressionAttribute>>),
    /// Backend type.
    Type(String),
    /// Number of set elements.
    Count(u32),
    Other(DefaultNla),
}

impl Nla for SetAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_SET_UNSEPC,
            Self::Table(_) => NFTA_SET_TABLE,
            Self::Name(_) => NFTA_SET_NAME,
            Self::Flags(_) => NFTA_SET_FLAGS,
            Self::KeyType(_) => NFTA_SET_KEY_TYPE,
            Self::KeyLen(_) => NFTA_SET_KEY_LEN,
            Self::DataType(_) => NFTA_SET_DATA_TYPE,
            Self::DataLen(_) => NFTA_SET_DATA_LEN,
            Self::Policy(_) => NFTA_SET_POLICY,
            Self::Description(_) => NFTA_SET_DESC | NLA_F_NESTED,
            Self::Id(_) => NFTA_SET_ID,
            Self::Timeout(_) => NFTA_SET_TIMEOUT,
            Self::GarbageCollectionInterval(_) => NFTA_SET_GC_INTERVAL,
            Self::UserData(_) => NFTA_SET_USERDATA,
            Self::ObjectType(_) => NFTA_SET_OBJ_TYPE,
            Self::Handle(_) => NFTA_SET_HANDLE,
            Self::Expression(_) => NFTA_SET_EXPR | NLA_F_NESTED,
            Self::ListExpressions(_) => NFTA_SET_EXPRESSIONS | NLA_F_NESTED,
            Self::Type(_) => NFTA_SET_TYPE,
            Self::Count(_) => NFTA_SET_COUNT,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unspecified => {}
            Self::Table(string) | Self::Name(string) | Self::Type(string) => {
                append_bytes(out, string.as_bytes());
                out.push(0);
            }
            Self::UserData(bytes) => append_bytes(out, bytes.as_slice()),
            Self::Flags(bits) => append_u32_be(out, bits.bits()),
            Self::KeyType(value)
            | Self::KeyLen(value)
            | Self::DataType(value)
            | Self::DataLen(value)
            | Self::Policy(value)
            | Self::Id(value)
            | Self::GarbageCollectionInterval(value)
            | Self::ObjectType(value)
            | Self::Count(value) => append_u32_be(out, *value),
            Self::Timeout(value) | Self::Handle(value) => {
                append_u64_be(out, *value)
            }
            Self::Description(desc) => desc.as_slice().emit(out)?,
            Self::Expression(ex) => ex.emit(out)?,
            Self::ListExpressions(exps) => exps.as_slice().emit(out)?,
            Self::Other(attr) => return attr.emit_value(out),
        }
        Ok(())
    }

    fn is_nested(&self) -> bool {
        matches!(
            self,
            Self::Description(_)
                | Self::Expression(_)
                | Self::ListExpressions(_)
        ) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for SetAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_SET_UNSEPC => Self::Unspecified,
            NFTA_SET_TABLE => Self::Table(
                parse_string(payload)
                    .context("invalid NFTA_SET_TABLE value")?,
            ),
            NFTA_SET_NAME => Self::Name(
                parse_string(payload).context("invalid NFTA_SET_NAME value")?,
            ),
            NFTA_SET_FLAGS => Self::Flags(SetFlags::from_bits_retain(
                parse_u32_be(payload)
                    .context("invalid NFTA_SET_FLAGS value")?,
            )),
            NFTA_SET_KEY_TYPE => Self::KeyType(
                parse_u32_be(payload)
                    .context("invalid NFTA_SET_KEY_TYPE value")?,
            ),
            NFTA_SET_KEY_LEN => Self::KeyLen(
                parse_u32_be(payload)
                    .context("invalid NFTA_SET_KEY_LEN value")?,
            ),
            NFTA_SET_DATA_TYPE => Self::DataType(
                parse_u32_be(payload)
                    .context("invalid NFTA_SET_DATA_TYPE value")?,
            ),
            NFTA_SET_DATA_LEN => Self::DataLen(
                parse_u32_be(payload)
                    .context("invalid NFTA_SET_DATA_LEN value")?,
            ),
            NFTA_SET_POLICY => Self::Policy(
                parse_u32_be(payload)
                    .context("invalid NFTA_SET_POLICY value")?,
            ),
            NFTA_SET_DESC => Self::Description(
                VecSetDescription::parse(payload)
                    .context("invalid NFTA_SET_DESC value")?
                    .0,
            ),
            NFTA_SET_ID => Self::Id(
                parse_u32_be(payload).context("invalid NFTA_SET_ID value")?,
            ),
            NFTA_SET_TIMEOUT => Self::Timeout(
                parse_u64_be(payload)
                    .context("invalid NFTA_SET_TIMEOUT value")?,
            ),
            NFTA_SET_GC_INTERVAL => Self::GarbageCollectionInterval(
                parse_u32_be(payload)
                    .context("invalid NFTA_SET_GC_INTERVAL value")?,
            ),
            NFTA_SET_USERDATA => Self::UserData(payload.to_vec()),
            NFTA_SET_OBJ_TYPE => Self::ObjectType(
                parse_u32_be(payload)
                    .context("invalid NFTA_SET_OBJ_TYPE value")?,
            ),
            NFTA_SET_HANDLE => Self::Handle(
                parse_u64_be(payload)
                    .context("invalid NFTA_SET_HANDLE value")?,
            ),
            NFTA_SET_EXPR => Self::Expression(
                ExpressionAttribute::parse_with_param(
                    &NlaBuffer::new(payload)?,
                    None, /* FIXME: Figure out how the legacy behavior
                           * determined the name */
                )
                .context("invalid NFTA_SET_EXPR value")?,
            ),
            NFTA_SET_EXPRESSIONS => Self::ListExpressions(
                VecListAttribute::parse(payload)
                    .context("invalid NFTA_SET_EXPRESSIONS value")?
                    .0,
            ),
            NFTA_SET_TYPE => Self::Type(
                parse_string(payload).context("invalid NFTA_SET_TYPE value")?,
            ),
            NFTA_SET_COUNT => Self::Count(
                parse_u32_be(payload)
                    .context("invalid NFTA_SET_COUNT value")?,
            ),
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
