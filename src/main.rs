#![feature(try_from)]
extern crate random_integer;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate libjail;
extern crate libc;

use dhclient::pcap::*;
use dhclient::sniffer::*;
use dhclient::sniffer::Config as SnifferConfig;
use random_integer::*;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::ffi::*;
use std::io;
use std::io::Read;
use std::mem::*;
use std::net::*;
use std::net::*;
use std::ptr;
use std::slice;
use std::thread;
use serde_json::Value as JsonValue;
use serde_derive::*;

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
#[derive(Clone, Copy)]
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

#[repr(C)]
#[derive(Clone, Copy)]
struct EthFrame {
    destination: [u8; 6],
    source: [u8; 6],
    ip_type: [u8; 2],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    jid: Option<i32>,
    iface: Option<String>,
    timeout: Option<i32>,
    trys: Option<i32>,
    hwaddr: Option<String>,
}

fn main() -> Result<(), Box<Error>> {

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let config: Config = serde_json::from_str(&input)?;

    println!("{:?}", config);

    unsafe {

        let if_ptr = std::ptr::null::<pcap_if_t>();
        let if_ptr_ptr = &if_ptr as *const *const pcap_if_t as *mut *mut pcap_if_t;


        let error: Vec<u8> = vec![0; PCAP_ERRBUF_SIZE as usize];
        let result = pcap_findalldevs(if_ptr_ptr, error.as_ptr() as *mut _);

        let iface = *if_ptr;
        let if_name = CStr::from_ptr(iface.name);
        let if_addr = *iface.addresses;
        let if_sockaddr = *(if_addr.addr as *mut libc::sockaddr_dl);
        let data_ptr = &if_sockaddr.sdl_data as *const _ as *mut [u8; 46];
        let data = *data_ptr;


        let mac: &mut [u8; 8] = &mut [0; 8];
        &mut mac[2..8].clone_from_slice(&data[4..10]);
        let mac = u64::from_be_bytes(*mac);


        println!("{:x?}", mac);
        println!("{:x?}", &data[4..10]);

        println!("{:?}", iface);
        println!("{:?}", if_name);
        println!("{:?}", if_addr);
        println!("{:?} {:?}", if_sockaddr.sdl_family, libc::AF_LINK);
        let if_slice_ptr = &if_sockaddr as *const _ as *mut u8;
        let if_slice = slice::from_raw_parts(if_slice_ptr as *const _, size_of::<libc::sockaddr_dl>());
        println!("{:?}", if_slice);


    
    };

    panic!();
    let iface = if let Some(iface) = config.iface {
        iface 
    } else { 
        lookupdev()?
    };

    if let Some(jid) = config.jid { libjail::attach(jid)?; }

    let mac: String = "e8:03:9a:ce:61:27".split(':').collect();
    let mac = u64::from_str_radix(&mac, 16)?;
    let xid = random_u32(0, u32::max_value());
    let iface = lookupdev()?;
    let filter_str = format!("udp dst port 68 and ether[46:4] = 0x{:x}", xid);
    let timeout = 1000;
    let trys = 10;

    let mut dhcp_discover = unsafe { zeroed::<DhcpMessage>() };

    dhcp_discover.op = 0x01;
    dhcp_discover.htype = 0x01;
    dhcp_discover.hlen = 0x06;
    dhcp_discover.xid = xid.to_be();

    let mac_slice = &(mac.to_be_bytes())[2..];
    &mut dhcp_discover.chaddr[0..6].clone_from_slice(mac_slice);

    let cookie: u32 = 0x63_82_53_63;
    dhcp_discover.cookie = cookie.to_be();

    let mut options: Vec<u8> = Vec::new();

    let mut option_53: u32 = 0x35_01_01;
    let option_53 = option_53.to_be_bytes();
    options.extend_from_slice(&option_53[1..]);

    let msg_slice = dhcp_discover.as_slice();
    let mut msg_vec = msg_slice.to_vec();
    msg_vec.append(&mut options);
    msg_vec.push(0xff);

    let socket = UdpSocket::bind("0.0.0.0:68")?;
    socket.set_broadcast(true)?;
    println!("{:x}", xid);
    println!("{:?}", iface);

    let mut sniffer = Sniffer::new(iface.to_owned())?;
    sniffer.set_timeout(timeout)?
        .set_promisc(true)?
        .set_snaplen(BUFSIZ as i32)?
        .activate()?
        .set_filter(filter_str.to_owned())?;

    println!("send dhcp discover");
    socket.send_to(&msg_vec, "255.255.255.255:67")?;

    let mut result = None;
    for _ in 0..trys {

        match sniffer.read_next() {
            option @ Some(_) => {
                result = option;
                break;
            },
            _ => {}
        }

    }

    let (_, data) = result.ok_or("not captured dhcp offer")?;
    let message_size = size_of::<DhcpMessage>();
    let message_slice = &data[42..message_size];
    let mut dhcp_offer: DhcpMessage = message_slice.into();
    let options_slice = &data[42 + message_size..];
    let opt_iter = OptionsIterator {
        slice: options_slice,
        offset: 0,
    };

    let options: HashMap<_, _> = opt_iter
        .map(|option| (option.code, option))
        .collect();

    let yiaddr = dhcp_offer.yiaddr.to_be();
    let siaddr = dhcp_offer.siaddr.to_be();

    println!("{:?}", Ipv4Addr::from(yiaddr));
    println!("{:?}", Ipv4Addr::from(siaddr));

    let mut dhcp_request = dhcp_offer.clone();

    dhcp_request.op = 0x01;
    dhcp_request.yiaddr = 0x0;
    dhcp_request.siaddr = 0x0;

    let mut options: Vec<u8> = Vec::new();

    let option_53: u32 = 0x35_01_03;
    let option_53 = option_53.to_be_bytes();
    options.extend_from_slice(&option_53[1..]);

    let option_50: u64 = 0x32_04_00_00_00_00 + yiaddr as u64;
    let option_50 = option_50.to_be_bytes();
    options.extend_from_slice(&option_50[2..]);

    let option_54: u64 = 0x36_04_00_00_00_00 + siaddr as u64;
    let option_54 = option_54.to_be_bytes();
    options.extend_from_slice(&option_54[2..]);

    let msg_sclie = dhcp_request.as_slice();
    let mut msg_vec = msg_slice.to_vec();
    msg_vec.append(&mut options);
    msg_vec.push(0xff);

    println!("{:?}", &msg_vec);

    let mut sniffer = Sniffer::new(iface.to_owned())?;
    sniffer.set_timeout(timeout)?
        .set_promisc(true)?
        .set_snaplen(BUFSIZ as i32)?
        .activate()?
        .set_filter(filter_str.to_owned())?;

    println!("send dhcp request");
    socket.send_to(&msg_vec, "255.255.255.255:67")?;

    let mut result = None;
    for _ in 0..trys {

        match sniffer.read_next() {
            option @ Some(_) => {
                result = option;
                break;
            },
            _ => {}
        }

    }

    let (_, data) = result.ok_or("not captured dhcp ack")?;
    let message_size = size_of::<DhcpMessage>();
    let message_slice = &data[42..message_size];
    let mut dhcp_ack: DhcpMessage = message_slice.into();
    let options_slice = &data[42 + message_size..];
    let opt_iter = OptionsIterator {
        slice: options_slice,
        offset: 0,
    };

    let options: HashMap<_, _> = opt_iter
        .map(|option| (option.code, option))
        .collect();

    println!("{:?}", options);
    println!("exit");

    Ok(())

}
