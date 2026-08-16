// SPDX-License-Identifier: MIT

mod message;
pub use message::{ULogMessage, ULogMessageType};
pub mod nlas;

use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST,
};

use crate::{
    message::ProtoFamily, nflog::nlas::config::ConfigNla, NetfilterHeader,
    NetfilterMessage,
};

const NFNETLINK_V0: u8 = libc::NFNETLINK_V0 as u8;

pub fn config_request(
    family: ProtoFamily,
    group_num: u16,
    nlas: Vec<ConfigNla>,
) -> NetlinkMessage<NetfilterMessage> {
    let mut hdr = NetlinkHeader::default();
    hdr.flags = NLM_F_REQUEST | NLM_F_ACK;
    let mut message = NetlinkMessage::new(
        hdr,
        NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(family, NFNETLINK_V0, group_num),
            ULogMessage::Config(nlas),
        )),
    );
    message.finalize();
    message
}
