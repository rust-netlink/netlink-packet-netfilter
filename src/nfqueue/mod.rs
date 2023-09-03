// SPDX-License-Identifier: MIT

mod message;
pub use message::NfQueueMessage;
pub mod nlas;

use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST,
};

use crate::{
    constants::NFNETLINK_V0,
    nfqueue::nlas::{config::ConfigNla, verdict::VerdictNla},
    NetfilterHeader, NetfilterMessage,
};

pub fn config_request(
    family: u8,
    group_num: u16,
    nlas: Vec<ConfigNla>,
) -> NetlinkMessage<NetfilterMessage> {
    let mut hdr = NetlinkHeader::default();
    hdr.flags = NLM_F_REQUEST | NLM_F_ACK;
    let mut message = NetlinkMessage::new(
        hdr,
        NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(family, NFNETLINK_V0, group_num),
            NfQueueMessage::Config(nlas),
        )),
    );
    message.finalize();
    message
}

pub fn verdict_message(
    family: u8,
    queue_num: u16,
    nla: VerdictNla,
) -> NetlinkMessage<NetfilterMessage> {
    let mut hdr = NetlinkHeader::default();
    hdr.flags = NLM_F_REQUEST;
    let mut message = NetlinkMessage::new(
        hdr,
        NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(family, NFNETLINK_V0, queue_num),
            NfQueueMessage::Verdict(vec![nla]),
        )),
    );
    message.finalize();
    message
}
