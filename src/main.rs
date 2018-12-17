#![feature(try_from)]
extern crate random_integer;

use dhclient::pcap::*;
use dhclient::sniffer::*;
use dhclient::sniffer::Config as SnifferConfig;
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

impl From<&[u8]> for DhcpMessage {
    fn from(value: &[u8]) -> Self {
        unsafe {
            std::ptr::read(value.as_ptr() as *const _)
        }
    }
}

impl DhcpMessage {
    fn as_slice(&self) -> &[u8] {
        unsafe {
            let message_ptr = self as *const _ as *mut u8;
            slice::from_raw_parts(message_ptr as *const u8, size_of::<DhcpMessage>()) 
        }
    }
}

fn main() -> Result<(), Box<Error>> {

    let mac: String = "e8:03:9a:ce:61:27".split(':').collect();
    let mac = u64::from_str_radix(&mac, 16)?;
    let xid = random_u32(0, u32::max_value());

    let mut message = unsafe { zeroed::<DhcpMessage>() };

    message.op = 0x01;
    message.htype = 0x01;
    message.hlen = 0x06;
    message.xid = xid.to_be();

    let oct = &mac as *const _ as *mut u8;
    let mut t = unsafe { *(oct as *const [u8; 6]) };
    t.reverse();

    &mut message.chaddr[0..6].clone_from_slice(&t);

    let mut options: Vec<u8> = Vec::new();

    let cookie: u32 = 0x63_82_53_63;
    message.cookie = cookie.to_be();

    let mut option_53: u32 = 0x35_01_01;
    let option_53 = option_53.to_be_bytes();
    options.extend_from_slice(&option_53[1..]);

    let msg_slice = message.as_slice();
    let mut msg_vec = msg_slice.to_vec();
    msg_vec.append(&mut options);
    msg_vec.push(0xff);

    println!("{:?}", msg_vec);

    let socket = UdpSocket::bind("0.0.0.0:68")?;
    socket.set_broadcast(true)?;
    socket.send_to(&msg_vec, "255.255.255.255:67")?;

    let iface = lookupdev()?;
    println!("{:x}", xid);
    println!("{:?}", iface);
    let filter_str = format!("udp dst port 68 and ether[46:4] = 0x{:x}", xid);
    let mut sniffer = Sniffer::new(iface)?;
    sniffer.set_timeout(20000)?
        .set_promisc(true)?
        .set_snaplen(BUFSIZ as i32)?
        .activate()?
        .set_filter(filter_str)?;

    let (_, data) = sniffer.read_next().ok_or("not captured")?;
    let message_size = size_of::<DhcpMessage>();
    let message_slice = &data[42..message_size];
    let mut message: DhcpMessage = message_slice.into();
    let options_slice = &data[42 + message_size..];
    let opt_iter = OptionsIterator {
        slice: options_slice,
        offset: 0,
    };

    let options: HashMap<_, _> = opt_iter
        .map(|option| (option.code, option))
        .collect();

    let yiaddr = message.yiaddr;
    let siaddr = message.siaddr;

    println!("{:?}", Ipv4Addr::from(message.yiaddr.to_be()));
    println!("{:?}", Ipv4Addr::from(message.siaddr.to_be()));

    message.op = 0x01;
    message.yiaddr = 0x0;

    let mut options: Vec<u8> = Vec::new();

    let option_53: u32 = 0x35_01_03;
    let option_53 = option_53.to_be_bytes();
    options.extend_from_slice(&option_53[1..]);

    let option_50: u64 = 0x05_04_00_00_00_00 + yiaddr as u64;
    let option_50 = option_50.to_be_bytes();
    options.extend_from_slice(&option_50[2..]);

    let option_54: u64 = 0x45_04_00_00_00_00 + siaddr as u64;
    let option_54 = option_54.to_be_bytes();
    options.extend_from_slice(&option_54[2..]);

    let msg_sclie = message.as_slice();
    let mut msg_vec = msg_slice.to_vec();
    msg_vec.append(&mut options);
    msg_vec.push(0xff);

    socket.send_to(&msg_vec, "255.255.255.255:67")?;

    println!("exit");

    Ok(())

}
