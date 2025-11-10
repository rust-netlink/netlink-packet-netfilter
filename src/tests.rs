// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use netlink_packet_core::{Emitable, ParseableParametrized};

use crate::{
    buffer::NetfilterBuffer,
    conntrack::{
        ConntrackAttribute, ConntrackMessage, ConntrackMessageType, IPTuple,
        ProtoInfo, ProtoInfoTCP, ProtoTuple, Protocol, Status, TCPFlags, Tuple,
    },
    message::{ProtoFamily, Subsystem},
    NetfilterHeader, NetfilterMessage,
};

// wireshark capture of nlmon against command (netlink message header removed):
// conntrack -L
#[test]
fn test_dump_conntrack() {
    let raw: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];

    let expected: NetfilterMessage = NetfilterMessage::new(
        NetfilterHeader::new(ProtoFamily::Unspec, 0, 0),
        ConntrackMessage::Get(vec![]),
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);

    // Check if the serialization was correct
    assert_eq!(buffer, raw);

    let message_type = ((u8::from(Subsystem::Conntrack) as u16) << 8)
        | (u8::from(ConntrackMessageType::Get) as u16);
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
        NetfilterHeader::new(ProtoFamily::IPv4, 0, 0),
        ConntrackMessage::Get(attributes),
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);

    // Check if the serialization was correct
    assert_eq!(buffer, raw);

    let message_type = ((u8::from(Subsystem::Conntrack) as u16) << 8)
        | (u8::from(ConntrackMessageType::Get) as u16);
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
        NetfilterHeader::new(ProtoFamily::IPv6, 0, 0),
        ConntrackMessage::Get(attributes),
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);

    // Check if the serialization was correct
    assert_eq!(buffer, raw);

    let message_type = ((u8::from(Subsystem::Conntrack) as u16) << 8)
        | (u8::from(ConntrackMessageType::Get) as u16);
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
// conntrack -D -f ipv4 -p tcp --src 10.255.160.124 --sport 39640 --dst
// 140.82.113.26 --dport 443 NOTE: For filtered deletions, conntrack-tools
// issues a dump request to retrieve all conntrack entries, filters them in
// userspace, and then sends delete requests for the matching entries with the
// required attributes.
#[test]
fn test_delete_conntrack_tcp_ipv4() {
    let raw: Vec<u8> = vec![
        0x02, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01, 0x80, 0x14, 0x00, 0x01, 0x80,
        0x08, 0x00, 0x01, 0x00, 0x0a, 0xff, 0xa0, 0x7c, 0x08, 0x00, 0x02, 0x00,
        0x8c, 0x52, 0x71, 0x1a, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x9a, 0xd8, 0x00, 0x00,
        0x06, 0x00, 0x03, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x34, 0x00, 0x02, 0x80,
        0x14, 0x00, 0x01, 0x80, 0x08, 0x00, 0x01, 0x00, 0x8c, 0x52, 0x71, 0x1a,
        0x08, 0x00, 0x02, 0x00, 0x0a, 0xff, 0xa0, 0x7c, 0x1c, 0x00, 0x02, 0x80,
        0x05, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00,
        0x01, 0xbb, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x9a, 0xd8, 0x00, 0x00,
        0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x8e, 0x08, 0x00, 0x07, 0x00,
        0x00, 0x06, 0x97, 0x77, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x04, 0x80, 0x2c, 0x00, 0x01, 0x80, 0x05, 0x00, 0x01, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x05, 0x00, 0x23, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x00, 0x00,
    ];

    let orig_src_addr =
        IPTuple::SourceAddress(IpAddr::V4("10.255.160.124".parse().unwrap()));
    let orig_dst_addr = IPTuple::DestinationAddress(IpAddr::V4(
        "140.82.113.26".parse().unwrap(),
    ));

    let orig_proto_num = ProtoTuple::Protocol(Protocol::Tcp);
    let orig_src_port = ProtoTuple::SourcePort(39640);
    let orig_dst_port = ProtoTuple::DestinationPort(443);

    let orig_ip_tuple = Tuple::Ip(vec![orig_src_addr, orig_dst_addr]);
    let orig_proto_tuple =
        Tuple::Proto(vec![orig_proto_num, orig_src_port, orig_dst_port]);

    let reply_src_addr =
        IPTuple::SourceAddress(IpAddr::V4("140.82.113.26".parse().unwrap()));
    let reply_dst_addr = IPTuple::DestinationAddress(IpAddr::V4(
        "10.255.160.124".parse().unwrap(),
    ));

    let reply_proto_num = ProtoTuple::Protocol(Protocol::Tcp);
    let reply_src_port = ProtoTuple::SourcePort(443);
    let reply_dst_port = ProtoTuple::DestinationPort(39640);

    let reply_ip_tuple = Tuple::Ip(vec![reply_src_addr, reply_dst_addr]);
    let reply_proto_tuple =
        Tuple::Proto(vec![reply_proto_num, reply_src_port, reply_dst_port]);

    let status = Status::DstNatDone
        | Status::SrcNatDone
        | Status::Confirmed
        | Status::Assured
        | Status::SeenReply;

    let timeout = 431991;
    let mark = 0;

    let proto_info = vec![ProtoInfo::TCP(vec![
        ProtoInfoTCP::State(3),
        ProtoInfoTCP::OriginalFlags(TCPFlags { flags: 35, mask: 0 }),
        ProtoInfoTCP::ReplyFlags(TCPFlags { flags: 35, mask: 0 }),
        ProtoInfoTCP::OriginalWindowScale(10),
        ProtoInfoTCP::ReplyWindowScale(10),
    ])];

    let attributes = vec![
        ConntrackAttribute::CtaTupleOrig(vec![orig_ip_tuple, orig_proto_tuple]),
        ConntrackAttribute::CtaTupleReply(vec![
            reply_ip_tuple,
            reply_proto_tuple,
        ]),
        ConntrackAttribute::CtaStatus(status),
        ConntrackAttribute::CtaTimeout(timeout),
        ConntrackAttribute::CtaMark(mark),
        ConntrackAttribute::CtaProtoInfo(proto_info),
    ];

    let expected: NetfilterMessage = NetfilterMessage::new(
        NetfilterHeader::new(ProtoFamily::IPv4, 0, 0),
        ConntrackMessage::Delete(attributes),
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);

    // Check if the serialization was correct
    assert_eq!(buffer, raw);

    let message_type = ((u8::from(Subsystem::Conntrack) as u16) << 8)
        | (u8::from(ConntrackMessageType::Delete) as u16);
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
// conntrack -D -f ipv6 -p udp --src 2409:40c4:2c:433d:8a2b:74e7:61f9:d824
// --sport 36289 --dst 2404:6800:4007:839::200a --dport 443 NOTE: For filtered
// deletions, conntrack-tools issues a dump request to retrieve all conntrack
// entries, filters them in userspace, and then sends delete requests for the
// matching entries with the required attributes.
#[test]
fn test_delete_conntrack_udp_ipv6() {
    let raw: Vec<u8> = vec![
        0x0a, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x01, 0x80, 0x2c, 0x00, 0x01, 0x80,
        0x14, 0x00, 0x03, 0x00, 0x24, 0x09, 0x40, 0xc4, 0x00, 0x2c, 0x43, 0x3d,
        0x8a, 0x2b, 0x74, 0xe7, 0x61, 0xf9, 0xd8, 0x24, 0x14, 0x00, 0x04, 0x00,
        0x24, 0x04, 0x68, 0x00, 0x40, 0x07, 0x08, 0x39, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x20, 0x0a, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00,
        0x11, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x8d, 0xc1, 0x00, 0x00,
        0x06, 0x00, 0x03, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x4c, 0x00, 0x02, 0x80,
        0x2c, 0x00, 0x01, 0x80, 0x14, 0x00, 0x03, 0x00, 0x24, 0x04, 0x68, 0x00,
        0x40, 0x07, 0x08, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0a,
        0x14, 0x00, 0x04, 0x00, 0x24, 0x09, 0x40, 0xc4, 0x00, 0x2c, 0x43, 0x3d,
        0x8a, 0x2b, 0x74, 0xe7, 0x61, 0xf9, 0xd8, 0x24, 0x1c, 0x00, 0x02, 0x80,
        0x05, 0x00, 0x01, 0x00, 0x11, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00,
        0x01, 0xbb, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x8d, 0xc1, 0x00, 0x00,
        0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x8e, 0x08, 0x00, 0x07, 0x00,
        0x00, 0x00, 0x00, 0x73, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let orig_src_addr = IPTuple::SourceAddress(IpAddr::V6(
        "2409:40c4:2c:433d:8a2b:74e7:61f9:d824".parse().unwrap(),
    ));
    let orig_dst_addr = IPTuple::DestinationAddress(IpAddr::V6(
        "2404:6800:4007:839::200a".parse().unwrap(),
    ));

    let orig_proto_num = ProtoTuple::Protocol(Protocol::Udp);
    let orig_src_port = ProtoTuple::SourcePort(36289);
    let orig_dst_port = ProtoTuple::DestinationPort(443);

    let orig_ip_tuple = Tuple::Ip(vec![orig_src_addr, orig_dst_addr]);
    let orig_proto_tuple =
        Tuple::Proto(vec![orig_proto_num, orig_src_port, orig_dst_port]);

    let reply_src_addr = IPTuple::SourceAddress(IpAddr::V6(
        "2404:6800:4007:839::200a".parse().unwrap(),
    ));
    let reply_dst_addr = IPTuple::DestinationAddress(IpAddr::V6(
        "2409:40c4:2c:433d:8a2b:74e7:61f9:d824".parse().unwrap(),
    ));

    let reply_proto_num = ProtoTuple::Protocol(Protocol::Udp);
    let reply_src_port = ProtoTuple::SourcePort(443);
    let reply_dst_port = ProtoTuple::DestinationPort(36289);

    let reply_ip_tuple = Tuple::Ip(vec![reply_src_addr, reply_dst_addr]);
    let reply_proto_tuple =
        Tuple::Proto(vec![reply_proto_num, reply_src_port, reply_dst_port]);

    let status = Status::DstNatDone
        | Status::SrcNatDone
        | Status::Confirmed
        | Status::Assured
        | Status::SeenReply;

    let timeout = 115;
    let mark = 0;

    let attributes = vec![
        ConntrackAttribute::CtaTupleOrig(vec![orig_ip_tuple, orig_proto_tuple]),
        ConntrackAttribute::CtaTupleReply(vec![
            reply_ip_tuple,
            reply_proto_tuple,
        ]),
        ConntrackAttribute::CtaStatus(status),
        ConntrackAttribute::CtaTimeout(timeout),
        ConntrackAttribute::CtaMark(mark),
    ];

    let expected: NetfilterMessage = NetfilterMessage::new(
        NetfilterHeader::new(ProtoFamily::IPv6, 0, 0),
        ConntrackMessage::Delete(attributes),
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);

    // Check if the serialization was correct
    assert_eq!(buffer, raw);

    let message_type = ((u8::from(Subsystem::Conntrack) as u16) << 8)
        | (u8::from(ConntrackMessageType::Delete) as u16);
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
//  conntrack -I -p tcp --src 192.168.1.100 --dst 10.0.0.1 --sport 12345 --dport
// 80 --state SYN_SENT --timeout 60
#[test]
fn test_new_conntrack() {
    let raw: Vec<u8> = vec![
        0x02, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01, 0x80, 0x14, 0x00, 0x01, 0x80,
        0x08, 0x00, 0x01, 0x00, 0xc0, 0xa8, 0x01, 0x64, 0x08, 0x00, 0x02, 0x00,
        0x0a, 0x00, 0x00, 0x01, 0x1c, 0x00, 0x02, 0x80, 0x05, 0x00, 0x01, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x30, 0x39, 0x00, 0x00,
        0x06, 0x00, 0x03, 0x00, 0x00, 0x50, 0x00, 0x00, 0x34, 0x00, 0x02, 0x80,
        0x14, 0x00, 0x01, 0x80, 0x08, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x01,
        0x08, 0x00, 0x02, 0x00, 0xc0, 0xa8, 0x01, 0x64, 0x1c, 0x00, 0x02, 0x80,
        0x05, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00,
        0x00, 0x50, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x30, 0x39, 0x00, 0x00,
        0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x20, 0x00, 0x04, 0x80,
        0x1c, 0x00, 0x01, 0x80, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x04, 0x00, 0x0a, 0x0a, 0x00, 0x00, 0x06, 0x00, 0x05, 0x00,
        0x0a, 0x0a, 0x00, 0x00,
    ];

    let orig_src_addr =
        IPTuple::SourceAddress(IpAddr::V4("192.168.1.100".parse().unwrap()));
    let orig_dst_addr =
        IPTuple::DestinationAddress(IpAddr::V4("10.0.0.1".parse().unwrap()));

    let orig_proto_num = ProtoTuple::Protocol(Protocol::Tcp);
    let orig_src_port = ProtoTuple::SourcePort(12345);
    let orig_dst_port = ProtoTuple::DestinationPort(80);

    let orig_ip_tuple = Tuple::Ip(vec![orig_src_addr, orig_dst_addr]);
    let orig_proto_tuple =
        Tuple::Proto(vec![orig_proto_num, orig_src_port, orig_dst_port]);

    let reply_src_addr =
        IPTuple::SourceAddress(IpAddr::V4("10.0.0.1".parse().unwrap()));
    let reply_dst_addr = IPTuple::DestinationAddress(IpAddr::V4(
        "192.168.1.100".parse().unwrap(),
    ));

    let reply_proto_num = ProtoTuple::Protocol(Protocol::Tcp);
    let reply_src_port = ProtoTuple::SourcePort(80);
    let reply_dst_port = ProtoTuple::DestinationPort(12345);

    let reply_ip_tuple = Tuple::Ip(vec![reply_src_addr, reply_dst_addr]);
    let reply_proto_tuple =
        Tuple::Proto(vec![reply_proto_num, reply_src_port, reply_dst_port]);

    let timeout = 60;

    let proto_info = ProtoInfo::TCP(vec![
        ProtoInfoTCP::State(1),
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
        ConntrackAttribute::CtaTupleOrig(vec![orig_ip_tuple, orig_proto_tuple]),
        ConntrackAttribute::CtaTupleReply(vec![
            reply_ip_tuple,
            reply_proto_tuple,
        ]),
        ConntrackAttribute::CtaTimeout(timeout),
        ConntrackAttribute::CtaProtoInfo(vec![proto_info]),
    ];

    let expected: NetfilterMessage = NetfilterMessage::new(
        NetfilterHeader::new(ProtoFamily::IPv4, 0, 0),
        ConntrackMessage::New(attributes),
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);

    // Check if the serialization was correct
    assert_eq!(buffer, raw);

    let message_type = ((u8::from(Subsystem::Conntrack) as u16) << 8)
        | (u8::from(ConntrackMessageType::New) as u16);
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
