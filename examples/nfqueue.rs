// SPDX-License-Identifier: MIT

// To run this example:
//   1) create a iptables/nft rules that send packet with nfqueue 0, for example:
//          sudo iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
//   2) build the example:
//          cargo build --example nfqueue
//   3) run it as root:
//          sudo ./target/debug/examples/nfqueue

use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_netfilter::{
    constants::*,
    nfqueue::{
        config_request,
        nlas::{
            config::{
                ConfigCmd, ConfigCmdType, ConfigFlags, ConfigNla, ConfigParams,
                CopyMode,
            },
            packet::PacketNla,
            verdict::{VerdictHdr, VerdictNla, VerdictType},
        },
        verdict_message, NfQueueMessage,
    },
    NetfilterMessage, NetfilterMessageInner,
};

use netlink_sys::{constants::NETLINK_NETFILTER, Socket};

fn get_packet_nlas(message: &NetlinkMessage<NetfilterMessage>) -> &[PacketNla] {
    if let NetlinkPayload::InnerMessage(NetfilterMessage {
        inner: NetfilterMessageInner::NfQueue(NfQueueMessage::Packet(nlas)),
        ..
    }) = &message.payload
    {
        nlas
    } else {
        &[]
    }
}

fn main() {
    const QUEUE_NUM: u16 = 0;

    // First, we bind the socket
    let mut socket = Socket::new(NETLINK_NETFILTER).unwrap();
    socket.bind_auto().unwrap();

    // Then we issue the PfUnbind command
    let packet = config_request(
        AF_INET,
        0,
        vec![ConfigNla::Cmd(ConfigCmd::new(
            ConfigCmdType::PfUnbind,
            AF_INET as u16,
        ))],
    );
    let mut tx_buffer = vec![0; packet.header.length as usize];
    packet.serialize(&mut tx_buffer[..]);
    println!(">>> {:?}", packet);
    socket.send(&tx_buffer[..], 0).unwrap();

    let mut rx_buffer = vec![0; 8196];

    // And check there is no error
    let rx_size = socket.recv(&mut &mut rx_buffer[..], 0).unwrap();
    let rx_bytes = &rx_buffer[..rx_size];
    let rx_packet =
        <NetlinkMessage<NetfilterMessage>>::deserialize(rx_bytes).unwrap();
    println!("<<< {:?}", rx_packet);
    assert!(matches!(rx_packet.payload, NetlinkPayload::Error(_)));
    if let NetlinkPayload::Error(e) = rx_packet.payload {
        assert_eq!(e.code, None);
    }

    // Then we issue the PfBind command
    let packet = config_request(
        AF_INET,
        0,
        vec![ConfigNla::Cmd(ConfigCmd::new(
            ConfigCmdType::PfBind,
            AF_INET as u16,
        ))],
    );
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    println!(">>> {:?}", packet);
    socket.send(&buf[..], 0).unwrap();

    // And check there is no error
    let rx_size = socket.recv(&mut &mut rx_buffer[..], 0).unwrap();
    let rx_bytes = &rx_buffer[..rx_size];
    let rx_packet =
        <NetlinkMessage<NetfilterMessage>>::deserialize(rx_bytes).unwrap();
    println!("<<< {:?}", rx_packet);
    assert!(matches!(rx_packet.payload, NetlinkPayload::Error(_)));
    if let NetlinkPayload::Error(e) = rx_packet.payload {
        assert_eq!(e.code, None);
    }

    // After that we issue a Bind command, to start receiving packets. We can
    // also set various parameters at the same time
    let packet = config_request(
        AF_INET,
        QUEUE_NUM,
        vec![
            ConfigNla::Cmd(ConfigCmd::new(ConfigCmdType::Bind, AF_INET as u16)),
            ConfigNla::Params(ConfigParams::new(0xFFFF, CopyMode::Packet)),
            ConfigNla::Mask(
                ConfigFlags::FAIL_OPEN
                    | ConfigFlags::CONNTRACK
                    | ConfigFlags::GSO
                    | ConfigFlags::UID_GID
                    | ConfigFlags::SECCTX,
            ),
            ConfigNla::Flags(
                ConfigFlags::FAIL_OPEN
                    | ConfigFlags::CONNTRACK
                    | ConfigFlags::GSO
                    | ConfigFlags::UID_GID
                    | ConfigFlags::SECCTX,
            ),
        ],
    );

    let mut buffer = vec![0; packet.header.length as usize];
    packet.serialize(&mut buffer[..]);
    println!(">>> {:?}", packet);
    socket.send(&buffer[..], 0).unwrap();

    let rx_size = socket.recv(&mut &mut rx_buffer[..], 0).unwrap();
    let rx_bytes = &rx_buffer[..rx_size];
    let rx_packet =
        <NetlinkMessage<NetfilterMessage>>::deserialize(rx_bytes).unwrap();
    println!("<<< {:?}", rx_packet);
    assert!(matches!(rx_packet.payload, NetlinkPayload::Error(_)));
    if let NetlinkPayload::Error(e) = rx_packet.payload {
        assert_eq!(e.code, None);
    }

    // And now we can receive the packets
    loop {
        println!("Waiting for messages");
        match socket.recv(&mut &mut rx_buffer[..], 0) {
            Ok(rx_size) => {
                let rx_bytes = &rx_buffer[..rx_size];
                let rx_packet =
                    <NetlinkMessage<NetfilterMessage>>::deserialize(&rx_bytes)
                        .unwrap();
                assert_eq!(rx_packet.header.length as usize, rx_size);
                println!("<<< {:?}", rx_packet);

                if let NetlinkPayload::Error(e) = rx_packet.payload {
                    assert_eq!(e.code, None);
                    continue;
                }

                for nla in get_packet_nlas(&rx_packet) {
                    if let PacketNla::PacketHdr(hdr) = nla {
                        println!("packet_id: {}", hdr.packet_id);
                        let verdict_hdr =
                            VerdictHdr::new(VerdictType::Accept, hdr.packet_id);
                        let verdict_nla = VerdictNla::Verdict(verdict_hdr);
                        let verdict_msg =
                            verdict_message(AF_INET, QUEUE_NUM, verdict_nla);
                        let mut tx_buffer =
                            vec![0; verdict_msg.header.length as usize];
                        verdict_msg.serialize(&mut tx_buffer[..]);
                        println!(">>> {:?}", verdict_msg);
                        socket.send(&tx_buffer[..], 0).unwrap();
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
