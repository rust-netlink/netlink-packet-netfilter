// SPDX-License-Identifier: MIT

// To run this example:
//   1) build the example: cargo build --example nfconntrack
//   2) run it as root: sudo ../target/debug/examples/nfconntrack
//   3) Perform network activity from your host, which would result in conntrack updates:
//      curl http://example.com

use reyzell_netlink_packet_netfilter::{
    constants::{NFNLGRP_CONNTRACK_NEW, NFNLGRP_CONNTRACK_DESTROY},
    nfconntrack::{
        nlas::{ConnectionProperties, ConnectionTuple},
        ConnectionNla, NfConntrackMessage,
    },
    NetfilterMessage, NetfilterMessageInner,
};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_sys::{constants::NETLINK_NETFILTER, Socket};

use std::convert::TryFrom;

fn print_connection_tuple(tuple: ConnectionTuple) {
    match ConnectionProperties::try_from(tuple) {
        Ok(cxn) => {
            print!("{:?} ", cxn)
        }
        Err(e) => {
            print!("[error] {:?} ", e)
        }
    }
}

fn print_connection_nla(nlas: Vec<ConnectionNla>) {
    for nla in nlas {
        match nla {
            ConnectionNla::TupleOrig(tuple) => {
                print!("[orig] ");
                print_connection_tuple(tuple);
            }
            ConnectionNla::TupleReply(tuple) => {
                print!("[reply] ");
                print_connection_tuple(tuple);
            }
            _ => {}
        }
    }
}

fn main() {
    let mut receive_buffer = vec![0; 4096];

    let mut socket = Socket::new(NETLINK_NETFILTER).unwrap();
    socket.bind_auto().unwrap();
    socket.add_membership(NFNLGRP_CONNTRACK_NEW as u32).unwrap();
    socket.add_membership(NFNLGRP_CONNTRACK_DESTROY as u32).unwrap();

    loop {
        match socket.recv(&mut &mut receive_buffer[..], 0) {
            Ok(_size) => {
                let bytes = &receive_buffer[..];
                let msg =
                    <NetlinkMessage<NetfilterMessage>>::deserialize(bytes)
                        .unwrap();
                if let NetlinkPayload::<NetfilterMessage>::InnerMessage(imsg) =
                    msg.payload
                {
                    if let NetfilterMessageInner::NfConntrack(ct) = imsg.inner {
                        match ct {
                            NfConntrackMessage::ConnectionNew(nlas) => {
                                print!("[new] ");
                                print_connection_nla(nlas);
                                println!();
                            }
                            NfConntrackMessage::ConnectionDelete(nlas) => {
                                print!("[delete] ");
                                print_connection_nla(nlas);
                                println!();
                            }
                            _ => {}
                        }
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
