// SPDX-License-Identifier: MIT

use std::num::NonZero;

use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_netfilter::{
    constants::{AF_INET, NFNETLINK_V0},
    ctnetlink::{
        message::CtNetlinkMessage,
        nlas::flow::{ip_tuple::TupleNla, nla::FlowNla},
    },
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner,
};
use netlink_sys::{protocols::NETLINK_NETFILTER, Socket};

fn main() {
    let mut receive_buffer = vec![0; 4096];

    let mut socket = Socket::new(NETLINK_NETFILTER).unwrap();
    socket.bind_auto().unwrap();

    // List all conntrack entries
    let packet = list_request(AF_INET, 0);
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    println!(">>> {:?}", packet);
    socket.send(&buf[..], 0).unwrap();

    // pick one ip_tuple from the result of list
    let mut orig: Option<Vec<TupleNla>> = None;

    let mut done = false;
    loop {
        let size = socket.recv(&mut &mut receive_buffer[..], 0).unwrap();
        let bytes = &receive_buffer[..size];
        let mut read = 0;
        let mut msg_count = 0;
        while bytes.len() > read {
            let rx_packet =
                <NetlinkMessage<NetfilterMessage>>::deserialize(&bytes[read..])
                    .unwrap();
            if let NetlinkPayload::Done(_) = rx_packet.payload {
                done = true;
                break;
            }
            read += rx_packet.buffer_len();
            msg_count += 1;
            println!(
                "<<< counter={} packet_len={}\n{:?}",
                msg_count,
                rx_packet.buffer_len(),
                rx_packet
            );

            if let NetlinkPayload::InnerMessage(ct) = rx_packet.payload {
                if let NetfilterMessageInner::CtNetlink(
                    CtNetlinkMessage::New(nlas),
                ) = ct.inner
                {
                    for nla in nlas.iter() {
                        if let FlowNla::Orig(attrs) = nla {
                            orig = Some(attrs.clone())
                        }
                    }
                }
            } else if let NetlinkPayload::Error(e) = rx_packet.payload {
                println!("{}", e);
                assert_eq!(e.code, None);
            }
        }
        if done {
            break;
        }
    }

    // Get a specific conntrack entry
    let orig = orig.unwrap();
    let packet = get_request(AF_INET, 0, orig.clone());
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    println!(">>> {:?}", packet);
    socket.send(&buf[..], 0).unwrap();

    let size = socket.recv(&mut &mut receive_buffer[..], 0).unwrap();
    let bytes = &receive_buffer[..size];
    let rx_packet =
        <NetlinkMessage<NetfilterMessage>>::deserialize(bytes).unwrap();
    println!("<<< packet_len={}\n{:?}", rx_packet.buffer_len(), rx_packet);

    // Delete one entry
    let packet = delete_request(AF_INET, 0, orig.clone());
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    println!(">>> {:?}", packet);
    socket.send(&buf[..], 0).unwrap();

    // Confirm the etntry is deleted
    let packet = get_request(AF_INET, 0, orig.clone());
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    println!(">>> {:?}", packet);
    socket.send(&buf[..], 0).unwrap();

    let size = socket.recv(&mut &mut receive_buffer[..], 0).unwrap();
    let bytes = &receive_buffer[..size];
    let rx_packet =
        <NetlinkMessage<NetfilterMessage>>::deserialize(bytes).unwrap();
    println!("<<< packet_len={}\n{:?}", rx_packet.buffer_len(), rx_packet);
    if let NetlinkPayload::Error(e) = rx_packet.payload {
        if let Some(code) = e.code {
            if NonZero::new(-2).unwrap().ne(&code) {
                panic!("found the other error");
            }
        }
    } else {
        panic!("NetlinkPayload::Error is expected");
    }

    println!(">>> An entry is deleted correctly")
}

fn list_request(family: u8, res_id: u16) -> NetlinkMessage<NetfilterMessage> {
    let mut hdr = NetlinkHeader::default();
    hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut message = NetlinkMessage::new(
        hdr,
        NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(family, NFNETLINK_V0, res_id),
            CtNetlinkMessage::Get(None),
        )),
    );
    message.finalize();
    message
}

fn get_request(
    family: u8,
    res_id: u16,
    tuple: Vec<TupleNla>,
) -> NetlinkMessage<NetfilterMessage> {
    let mut hdr = NetlinkHeader::default();
    hdr.flags = NLM_F_REQUEST;
    let mut message = NetlinkMessage::new(
        hdr,
        NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(family, NFNETLINK_V0, res_id),
            CtNetlinkMessage::Get(Some(vec![FlowNla::Orig(tuple)])),
        )),
    );
    message.finalize();
    message
}

fn delete_request(
    family: u8,
    res_id: u16,
    tuple: Vec<TupleNla>,
) -> NetlinkMessage<NetfilterMessage> {
    let mut hdr = NetlinkHeader::default();
    hdr.flags = NLM_F_REQUEST;
    let mut message = NetlinkMessage::new(
        hdr,
        NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(family, NFNETLINK_V0, res_id),
            CtNetlinkMessage::Delete(vec![FlowNla::Orig(tuple)]),
        )),
    );
    message.finalize();
    message
}
