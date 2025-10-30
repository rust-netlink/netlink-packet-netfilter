// SPDX-License-Identifier: MIT

// To run this example:
//   1) create a iptables/nft rules that send packet with group 1, for example:
//      sudo iptables -A INPUT -j NFLOG --nflog-group 1
//   2) build the example: cargo build --example nflog
//   3) run it as root: sudo ../target/debug/examples/nflog

use std::time::Duration;

use netlink_packet_core::{parse_ip, NetlinkMessage, NetlinkPayload};
use netlink_packet_netfilter::{
    nflog::{
        config_request,
        nlas::{
            config::{ConfigCmd, ConfigFlags, ConfigMode, Timeout},
            packet::PacketNla,
        },
        ULogMessage,
    },
    NetfilterMessage, NetfilterMessageInner, ProtoFamily,
};
use netlink_sys::{constants::NETLINK_NETFILTER, Socket};

fn get_packet_nlas(message: &NetlinkMessage<NetfilterMessage>) -> &[PacketNla] {
    if let NetlinkPayload::InnerMessage(NetfilterMessage {
        inner: NetfilterMessageInner::ULog(ULogMessage::Packet(nlas)),
        ..
    }) = &message.payload
    {
        nlas
    } else {
        &[]
    }
}

fn main() {
    let mut receive_buffer = vec![0; 4096];

    // First, we bind the socket
    let mut socket = Socket::new(NETLINK_NETFILTER).unwrap();
    socket.bind_auto().unwrap();

    // Then we issue the PfBind command
    let packet =
        config_request(ProtoFamily::IPv4, 0, vec![ConfigCmd::PfBind.into()]);
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    println!(">>> {:?}", packet);
    socket.send(&buf[..], 0).unwrap();

    // And check there is no error
    let size = socket.recv(&mut &mut receive_buffer[..], 0).unwrap();
    let bytes = &receive_buffer[..size];
    let rx_packet =
        <NetlinkMessage<NetfilterMessage>>::deserialize(bytes).unwrap();
    println!("<<< {:?}", rx_packet);
    assert!(matches!(rx_packet.payload, NetlinkPayload::Error(_)));
    if let NetlinkPayload::Error(e) = rx_packet.payload {
        assert_eq!(e.code, None);
    }

    // After that we issue a Bind command, to start receiving packets. We can
    // also set various parameters at the same time
    let timeout: Timeout = Duration::from_millis(100).into();
    let packet = config_request(
        ProtoFamily::IPv4,
        1,
        vec![
            ConfigCmd::Bind.into(),
            ConfigFlags::SEQ_GLOBAL.into(),
            ConfigMode::PACKET_MAX.into(),
            timeout.into(),
        ],
    );
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    println!(">>> {:?}", packet);
    socket.send(&buf[..], 0).unwrap();

    let size = socket.recv(&mut &mut receive_buffer[..], 0).unwrap();
    let bytes = &receive_buffer[..size];
    let rx_packet =
        <NetlinkMessage<NetfilterMessage>>::deserialize(bytes).unwrap();
    println!("<<< {:?}", rx_packet);
    assert!(matches!(rx_packet.payload, NetlinkPayload::Error(_)));
    if let NetlinkPayload::Error(e) = rx_packet.payload {
        assert_eq!(e.code, None);
    }

    // And now we can receive the packets
    loop {
        match socket.recv(&mut &mut receive_buffer[..], 0) {
            Ok(size) => {
                let mut offset = 0;
                loop {
                    let bytes = &receive_buffer[offset..];

                    let rx_packet =
                        <NetlinkMessage<NetfilterMessage>>::deserialize(bytes)
                            .unwrap();

                    for nla in get_packet_nlas(&rx_packet) {
                        if let PacketNla::Payload(payload) = nla {
                            let src = parse_ip(&payload[12..16]).unwrap();
                            let dst = parse_ip(&payload[16..20]).unwrap();
                            println!("Packet from {} to {}", src, dst);
                            break;
                        }
                    }

                    offset += rx_packet.header.length as usize;
                    if offset == size || rx_packet.header.length == 0 {
                        break;
                    }
                }
            }
            Err(e) => {
                println!("error while receiving packets: {:?}", e);
                break;
            }
        }
    }
}
