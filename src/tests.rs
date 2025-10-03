// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use libc::NFNL_SUBSYS_CTNETLINK;
use netlink_packet_core::{Emitable, ParseableParametrized};

use crate::{
    buffer::NetfilterBuffer,
    conntrack::{
        ConntrackAttribute, ConntrackMessage, IPTuple, ProtoInfo, ProtoInfoTCP,
        ProtoTuple, Protocol, TCPFlags, Tuple,
    },
    constants::{AF_INET, AF_INET6, AF_UNSPEC, IPCTNL_MSG_CT_GET},
    NetfilterHeader, NetfilterMessage,
};

// wireshark capture of nlmon against command (netlink message header removed):
// conntrack -L
#[test]
fn test_dump_conntrack() {
    let raw: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];

    let expected: NetfilterMessage = NetfilterMessage::new(
        NetfilterHeader::new(AF_UNSPEC, 0, 0),
        ConntrackMessage::Get(vec![]),
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);

    // Check if the serialization was correct
    assert_eq!(buffer, raw);

    let message_type =
        ((NFNL_SUBSYS_CTNETLINK as u16) << 8) | (IPCTNL_MSG_CT_GET as u16);
    // Check if the deserialization was correct
    assert_eq!(
        NetfilterMessage::parse_with_param(
            &NetfilterBuffer::new(&raw),
            message_type
        )
        .unwrap(),
        expected
    );
}

// wireshark capture of nlmon against command (netlink message header removed):
// conntrack -G -p tcp -s 10.57.97.124 -d 148.113.20.105 --sport 39600 --dport
// 443
#[test]
fn test_get_conntrack_tcp_ipv4() {
    let raw: Vec<u8> = vec![
        0x02, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01, 0x80, 0x14, 0x00, 0x01, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x0a, 0x39, 0x61, 0x7c, 0x08, 0x00, 0x02, 0x00,
        0x94, 0x71, 0x14, 0x69, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x9a, 0xb0, 0x00, 0x00,
        0x06, 0x00, 0x03, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x18, 0x00, 0x04, 0x80,
        0x14, 0x00, 0x01, 0x80, 0x06, 0x00, 0x04, 0x00, 0x0a, 0x0a, 0x00, 0x00,
        0x06, 0x00, 0x05, 0x00, 0x0a, 0x0a, 0x00, 0x00,
    ];

    let src_addr =
        IPTuple::SourceAddress(IpAddr::V4("10.57.97.124".parse().unwrap()));
    let dst_addr = IPTuple::DestinationAddress(IpAddr::V4(
        "148.113.20.105".parse().unwrap(),
    ));

    let proto_num = ProtoTuple::Protocol(Protocol::Tcp);
    let src_port = ProtoTuple::SourcePort(39600);
    let dst_port = ProtoTuple::DestinationPort(443);

    let ip_tuple = Tuple::Ip(vec![src_addr, dst_addr]);
    let proto_tuple = Tuple::Proto(vec![proto_num, src_port, dst_port]);

    let proto_info = ProtoInfo::TCP(vec![
        ProtoInfoTCP::OriginalFlags(TCPFlags {
            flags: 10,
            mask: 10,
        }),
        ProtoInfoTCP::ReplyFlags(TCPFlags {
            flags: 10,
            mask: 10,
        }),
    ]);

    let attributes = vec![
        ConntrackAttribute::CtaTupleOrig(vec![ip_tuple, proto_tuple]),
        ConntrackAttribute::CtaProtoInfo(vec![proto_info]),
    ];

    let expected: NetfilterMessage = NetfilterMessage::new(
        NetfilterHeader::new(AF_INET, 0, 0),
        ConntrackMessage::Get(attributes),
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);

    // Check if the serialization was correct
    assert_eq!(buffer, raw);

    let message_type =
        ((NFNL_SUBSYS_CTNETLINK as u16) << 8) | (IPCTNL_MSG_CT_GET as u16);
    // Check if the deserialization was correct
    assert_eq!(
        NetfilterMessage::parse_with_param(
            &NetfilterBuffer::new(&raw),
            message_type
        )
        .unwrap(),
        expected
    );
}

// wireshark capture of nlmon against command (netlink message header removed):
// conntrack -G -p udp -s 2409:40c4:e8:6bc3:d1d8:1087:4fa2:68a3 --sport 58456 -d
// 2404:6800:4009:81d::200e --dport 443
#[test]
fn test_get_conntrack_udp_ipv6() {
    let raw: Vec<u8> = vec![
        0x0a, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x01, 0x80, 0x2c, 0x00, 0x01, 0x80,
        0x14, 0x00, 0x03, 0x00, 0x24, 0x09, 0x40, 0xc4, 0x00, 0xe8, 0x6b, 0xc3,
        0xd1, 0xd8, 0x10, 0x87, 0x4f, 0xa2, 0x68, 0xa3, 0x14, 0x00, 0x04, 0x00,
        0x24, 0x04, 0x68, 0x00, 0x40, 0x09, 0x08, 0x1d, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x20, 0x0e, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00,
        0x11, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0xe4, 0x58, 0x00, 0x00,
        0x06, 0x00, 0x03, 0x00, 0x01, 0xbb, 0x00, 0x00,
    ];

    let src_addr = IPTuple::SourceAddress(IpAddr::V6(
        "2409:40c4:e8:6bc3:d1d8:1087:4fa2:68a3".parse().unwrap(),
    ));
    let dst_addr = IPTuple::DestinationAddress(IpAddr::V6(
        "2404:6800:4009:81d::200e".parse().unwrap(),
    ));

    let proto_num = ProtoTuple::Protocol(Protocol::Udp);
    let src_port = ProtoTuple::SourcePort(58456);
    let dst_port = ProtoTuple::DestinationPort(443);

    let ip_tuple = Tuple::Ip(vec![src_addr, dst_addr]);
    let proto_tuple = Tuple::Proto(vec![proto_num, src_port, dst_port]);

    let attributes = vec![ConntrackAttribute::CtaTupleOrig(vec![
        ip_tuple,
        proto_tuple,
    ])];

    let expected: NetfilterMessage = NetfilterMessage::new(
        NetfilterHeader::new(AF_INET6, 0, 0),
        ConntrackMessage::Get(attributes),
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);

    // Check if the serialization was correct
    assert_eq!(buffer, raw);

    let message_type =
        ((NFNL_SUBSYS_CTNETLINK as u16) << 8) | (IPCTNL_MSG_CT_GET as u16);
    // Check if the deserialization was correct
    assert_eq!(
        NetfilterMessage::parse_with_param(
            &NetfilterBuffer::new(&raw),
            message_type
        )
        .unwrap(),
        expected
    );
}
