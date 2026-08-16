// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    emit_u32_be, parse_string, parse_u32_be, DecodeError, DefaultNla, Emitable,
    ErrorContext as _, Nla, NlaBuffer, NlasIterator, Parseable,
    ParseableParametrized, NLA_F_NESTED,
};

const NF_INET_PRE_ROUTING: u32 = 0;
const NF_INET_LOCAL_IN: u32 = 1;
const NF_INET_FORWARD: u32 = 2;
const NF_INET_LOCAL_OUT: u32 = 3;
const NF_INET_POST_ROUTING: u32 = 4;
const NF_INET_INGRESS: u32 = 5;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum InetHookNumber {
    PreRouting,
    LocalIn,
    Forward,
    LocalOut,
    PostRouting,
    Ingress,
    Other(u32),
}

impl From<InetHookNumber> for u32 {
    fn from(inet_nr: InetHookNumber) -> Self {
        match inet_nr {
            InetHookNumber::PreRouting => NF_INET_PRE_ROUTING,
            InetHookNumber::LocalIn => NF_INET_LOCAL_IN,
            InetHookNumber::Forward => NF_INET_FORWARD,
            InetHookNumber::LocalOut => NF_INET_LOCAL_OUT,
            InetHookNumber::PostRouting => NF_INET_POST_ROUTING,
            InetHookNumber::Ingress => NF_INET_INGRESS,
            InetHookNumber::Other(nr) => nr,
        }
    }
}

impl From<u32> for InetHookNumber {
    fn from(value: u32) -> Self {
        match value {
            NF_INET_PRE_ROUTING => InetHookNumber::PreRouting,
            NF_INET_LOCAL_IN => InetHookNumber::LocalIn,
            NF_INET_FORWARD => InetHookNumber::Forward,
            NF_INET_LOCAL_OUT => InetHookNumber::LocalOut,
            NF_INET_POST_ROUTING => InetHookNumber::PostRouting,
            NF_INET_INGRESS => InetHookNumber::Ingress,
            _ => InetHookNumber::Other(value),
        }
    }
}

const NF_NETDEV_INGRESS: u32 = 0;
const NF_NETDEV_EGRESS: u32 = 1;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum DevHookNumber {
    Ingress,
    Egress,
    Other(u32),
}

impl From<DevHookNumber> for u32 {
    fn from(dev_nr: DevHookNumber) -> Self {
        match dev_nr {
            DevHookNumber::Ingress => NF_NETDEV_INGRESS,
            DevHookNumber::Egress => NF_NETDEV_EGRESS,
            DevHookNumber::Other(nr) => nr,
        }
    }
}

impl From<u32> for DevHookNumber {
    fn from(value: u32) -> Self {
        match value {
            NF_NETDEV_INGRESS => DevHookNumber::Ingress,
            NF_NETDEV_EGRESS => DevHookNumber::Egress,
            _ => DevHookNumber::Other(value),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum HookNumber {
    Inet(InetHookNumber),
    Dev(DevHookNumber),
    Other(u32),
}

impl From<InetHookNumber> for HookNumber {
    fn from(inet_nr: InetHookNumber) -> Self {
        Self::Inet(inet_nr)
    }
}

impl From<DevHookNumber> for HookNumber {
    fn from(dev_nr: DevHookNumber) -> Self {
        Self::Dev(dev_nr)
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub(crate) enum HookType {
    #[default]
    Inet,
    Dev,
}

impl From<HookNumber> for u32 {
    fn from(hook_nr: HookNumber) -> Self {
        match hook_nr {
            HookNumber::Inet(inet_nr) => inet_nr.into(),
            HookNumber::Dev(dev_nr) => dev_nr.into(),
            HookNumber::Other(nr) => nr,
        }
    }
}

const NFTA_HOOK_UNSPEC: u16 = 0;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_HOOK_DEV: u16 = 3;
const NFTA_HOOK_DEVS: u16 = 4;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Hook {
    Unspecified,
    Number(HookNumber),
    Priority(u32),
    NetDeviceName(String),
    NetDevices(Vec<DefaultNla>),
    Other(DefaultNla),
}

impl Nla for Hook {
    fn value_len(&self) -> usize {
        match self {
            Self::Unspecified => 0,
            Self::Number(_) | Self::Priority(_) => 4,
            Self::NetDeviceName(string) => string.len() + 1,
            Self::NetDevices(devs) => devs.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Unspecified => NFTA_HOOK_UNSPEC,
            Self::Number(_) => NFTA_HOOK_HOOKNUM,
            Self::Priority(_) => NFTA_HOOK_PRIORITY,
            Self::NetDeviceName(_) => NFTA_HOOK_DEV,
            Self::NetDevices(_) => NFTA_HOOK_DEVS | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Unspecified => {}
            Self::Number(value) => {
                emit_u32_be(buffer, (*value).into()).unwrap()
            }
            Self::Priority(value) => emit_u32_be(buffer, *value).unwrap(),
            Self::NetDeviceName(string) => {
                buffer[..string.len()].copy_from_slice(string.as_bytes());
                buffer[string.len()] = 0;
            }
            Self::NetDevices(attrs) => attrs.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn is_nested(&self) -> bool {
        matches!(self, Self::NetDevices(_)) || (self.kind() & NLA_F_NESTED) != 0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NlaBuffer<&'a T>, HookType> for Hook
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        hook_type: HookType,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFTA_HOOK_UNSPEC => Self::Unspecified,
            NFTA_HOOK_HOOKNUM => {
                let nr = parse_u32_be(payload)
                    .context("invalid NFTA_HOOK_HOOKNUM value")?;

                match hook_type {
                    HookType::Inet => Self::Number(HookNumber::Inet(nr.into())),
                    HookType::Dev => Self::Number(HookNumber::Dev(nr.into())),
                }
            }
            NFTA_HOOK_PRIORITY => Self::Priority(
                parse_u32_be(payload)
                    .context("invalid NFTA_HOOK_PRIORITY value")?,
            ),
            NFTA_HOOK_DEV => Self::NetDeviceName(
                parse_string(payload).context("invalid NFTA_HOOK_DEV value")?,
            ),
            NFTA_HOOK_DEVS => {
                let mut nlas = vec![];
                for nla in NlasIterator::new(payload) {
                    let nla = nla.context(format!(
                        "invalid NFTA_HOOK_DEVS payload {:?}",
                        payload
                    ))?;
                    nlas.push(DefaultNla::parse(&nla)?);
                }
                Self::NetDevices(nlas)
            }
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}
