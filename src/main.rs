#![feature(try_from)]
extern crate random_integer;

use dhclient::pcap::*;
use dhclient::sniffer::*;
use random_integer::*;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::ffi::*;
use std::io;
use std::mem::*;
use std::net::*;
use std::net::*;
use std::ptr;
use std::slice;
use std::thread;

#[derive(Debug)]
struct DhcpOption {
    code: u8,
    length: u8,
    data: Vec<u8>,
}

struct OptionsIterator<'a> {
    slice: &'a [u8],
    offset: usize,
}

impl Iterator for OptionsIterator<'_> {
    type Item = DhcpOption;

    fn next(&mut self) -> Option<Self::Item> {
        let slice = &self.slice[self.offset..];
        let code = slice.get(0)?;

        if *code == 255 {
            return None;
        }

        let length = slice.get(1)?;
        let data = slice.get(2..2 + *length as usize)?;

        self.offset = self.offset + 2 + *length as usize;

        Some(DhcpOption {
            code: *code,
            length: *length,
            data: data.into(),
        })
    }
}

#[repr(C)]
struct DhcpMessage {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: u32,
    yiaddr: u32,
    siaddr: u32,
    giaddr: u32,
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    cookie: u32,
}

#[no_mangle]
pub unsafe extern "C" fn packet_handler(
    args: *mut u8,
    header: *const pcap_pkthdr,
    packet: *const u8,
) {
    println!("capture");
    return ();

    let header = *header;
    let packet = std::slice::from_raw_parts(packet, header.len as usize);

    println!("capture {:?}", header);
    println!("packet {:?}", packet);

    let message_size = size_of::<DhcpMessage>();
    let message_slice = &packet[42..message_size];
    let message: DhcpMessage = std::ptr::read(message_slice.as_ptr() as *const _);

    let options_slice = &packet[42 + message_size..];
    let opt_iter = OptionsIterator {
        slice: options_slice,
        offset: 0,
    };

    let options: HashMap<_, _> = opt_iter.map(|option| (option.code, option)).collect();

    println!("{:?}", Ipv4Addr::from(message.yiaddr.to_be()));
    println!("{:x}", message.xid);
    println!("{:?}", options);
}

fn main() -> Result<(), Box<Error>> {

    let mac: String = "e8:03:9a:ce:61:27".split(':').collect();
    let mac = u64::from_str_radix(&mac, 16).unwrap();
    let xid = random_u32(0, u32::max_value());

    let mut message = unsafe { zeroed::<DhcpMessage>() };

    message.op = 0x01;
    message.htype = 0x01;
    message.hlen = 0x06;
    message.xid = xid;

    let oct = &mac as *const _ as *mut u8;
    let mut t = unsafe { *(oct as *const [u8; 6]) };
    t.reverse();

    &mut message.chaddr[0..6].clone_from_slice(&t);

    let mut options: Vec<u8> = Vec::new();

    let cookie: u32 = 0x63_82_53_63;
    message.cookie = cookie.to_be();

    let option_53: u32 = 0x35_01_01;
    let oct = &option_53 as *const _ as *mut u8;
    let mut t = unsafe { *(oct as *const [u8; 3]) };
    t.reverse();

    options.extend_from_slice(&t);

    let message_ptr = &message as *const _ as *mut u8;
    let message_size = size_of::<DhcpMessage>();

    let msg_slice = unsafe { slice::from_raw_parts(message_ptr as *const u8, message_size) };

    let mut msg_vec = msg_slice.to_vec();
    msg_vec.append(&mut options);
    msg_vec.push(0xff);

    println!("{:?}", msg_vec);

    let socket = UdpSocket::bind("0.0.0.0:68").unwrap();
    socket.set_broadcast(true).unwrap();
    socket.send_to(&msg_vec, "255.255.255.255:67").unwrap();

    let iface = lookupdev()?;
    let mut sniffer = Sniffer::new(iface);

    Ok(())

}
