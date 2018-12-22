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
use serde_json::json;
use serde_derive::*;

const HW_BROADCAST: u64 = 0xff_ff_ff_ff_ff_ff;
const PROTO_UDP: u8 = 17;

#[derive(Debug)]
struct DhcpOption {
    code: u8,
    length: u8,
    data: Vec<u8>,
}

impl DhcpOption {

    fn to_json(&self) -> (String, JsonValue) {

        let option = self;

        match option.code {
            1 => {
                let mut octets: [u8;4] = [0;4];
                octets.copy_from_slice(&option.data[0..4]);
                let netmask: Ipv4Addr = octets.into();
                let netmask = format!("{}", netmask);
                ("netmask".into(), netmask.into())
            },
            15 => {
                let mut data = option.data.clone();
                data.push(0);
                let domain = unsafe { CStr::from_ptr(data.as_ptr() as _) };
                let domain = domain.to_str().unwrap();
                ("domain".into(), domain.into())
            },
            6 => {
                let mut octets: [u8;4] = [0;4];
                octets.copy_from_slice(&option.data[0..4]);
                let nameserver: Ipv4Addr = octets.into();
                let nameserver = format!("{}", nameserver);
                ("nameserver".into(), nameserver.into())
            },
            3 => {
                let mut octets: [u8;4] = [0;4];
                octets.copy_from_slice(&option.data[0..4]);
                let router: Ipv4Addr = octets.into();
                let router = format!("{}", router);
                ("router".into(), router.into())
            },
            28 => {
                let mut octets: [u8;4] = [0;4];
                octets.copy_from_slice(&option.data[0..4]);
                let broadcast: Ipv4Addr = octets.into();
                let broadcast = format!("{}", broadcast);
                ("broadcast".into(), broadcast.into())
            },
            _ => ("".into(), JsonValue::Null)
        }

    }

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

trait AsSliceU16 {
    fn as_slice_u16(&self) -> &[u16];
}

impl AsSliceU16 for Vec<u8> {
    fn as_slice_u16(&self) -> &[u16] {
        unsafe {
            let vec_ptr = self.as_ptr() as *const u16;
            slice::from_raw_parts(vec_ptr, self.len() / 2)
        }
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
#[derive(Clone, Debug)]
struct EthFrame {
    destination: [u8; 6],
    source: [u8; 6],
    ip_type: [u8; 2],
}

impl EthFrame {

    fn new() -> Self {
        let mut eth_frame: EthFrame = unsafe { zeroed() };
        eth_frame.ip_type = [0x08,0];
        eth_frame
    }

    fn as_slice(&self) -> &[u8] {
        unsafe {
            let message_ptr = self as *const _ as *mut u8;
            slice::from_raw_parts(message_ptr as *const u8, size_of::<EthFrame>()) 
        }
    }

    fn set_source(&mut self, hwaddr: u64) -> &mut Self {

        let hwaddr_bytes: [u8;8] = hwaddr.to_be_bytes();
        let mut source: [u8;6] = [0;6];

        source.copy_from_slice(&hwaddr_bytes[2..]);
        self.source = source;

        self

    }

    fn set_destination(&mut self, hwaddr: u64) -> &mut Self {

        let hwaddr_bytes: [u8;8] = hwaddr.to_be_bytes();
        let mut destination: [u8;6] = [0;6];

        destination.copy_from_slice(&hwaddr_bytes[2..]);
        self.destination = destination;

        self

    }
}

#[repr(C)]
#[derive(Clone, Debug)]
struct IpHeader {
    ver: u8,
    dscp: u8,
    length: u16,
    ident: u16,
    ffo: u16,
    ttl: u8,
    proto: u8,
    checksum: u16,
    source: u32,
    destination: u32,
}

impl IpHeader {

    fn new() -> Self {
        let mut ip4_header: IpHeader = unsafe { zeroed() };
        ip4_header.ver = 0x45;
        ip4_header.ttl = 64;
        ip4_header
    }

    fn set_ttl(&mut self, ttl: u8) -> &mut Self {
        self.ttl = ttl;
        self
    }

    fn set_proto(&mut self, proto: u8) -> &mut Self {
        self.proto = proto;
        self
    }

    fn set_source(&mut self, ip: Ipv4Addr) -> &mut Self {
        let ip_u32: u32 = ip.into(); 
        self.source = ip_u32.to_be();
        self
    }

    fn set_destination(&mut self, ip: Ipv4Addr) -> &mut Self {
        let ip_u32: u32 = ip.into(); 
        self.destination = ip_u32.to_be();
        self
    }

    fn set_length(&mut self, length: u16) -> &mut Self {
        self.length = length.to_be();
        self
    }

    fn as_slice(&self) -> &[u8] {
        unsafe {
            let message_ptr = self.as_ptr() as *const u8;
            slice::from_raw_parts(message_ptr, size_of::<IpHeader>()) 
        }
    }

    fn as_ptr(&self) -> *const Self {
        self as *const _
    }

    fn as_slice_u16(&self) -> &[u16] {
        unsafe {
            let message_ptr = self.as_ptr() as *const u16;
            slice::from_raw_parts(message_ptr, size_of::<IpHeader>() / 2)
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

impl UdpHeader {

    fn new() -> Self {
        let mut udp_header: UdpHeader = unsafe { zeroed() };
        udp_header
    }

    fn set_src_port(&mut self, port: u16) -> &mut Self {
        self.src_port = port.to_be();
        self
    }

    fn set_dst_port(&mut self, port: u16) -> &mut Self {
        self.dst_port = port.to_be();
        self
    }

    fn set_length(&mut self, length: u16) -> &mut Self {
        self.length = length.to_be();
        self
    }

    fn as_ptr(&self) -> *const Self {
        self as *const _
    }

    fn as_slice_u16(&self) -> &[u16] {
        unsafe {
            let message_ptr = self.as_ptr() as *const u16;
            slice::from_raw_parts(message_ptr, size_of::<UdpHeader>() / 2)
        }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe {
            let message_ptr = self.as_ptr() as *const u8;
            slice::from_raw_parts(message_ptr, size_of::<UdpHeader>()) 
        }
    }
}

#[derive(Debug, Clone)]
struct UdpPacketBuilder {
    eth_frame: EthFrame,
    ip_header: IpHeader,
    udp_header: UdpHeader,
    payload: Option<Vec<u8>>,
}

impl UdpPacketBuilder {

    fn new(headers: (EthFrame, IpHeader, UdpHeader)) -> Self {

        let (eth_frame, ip_header, udp_header) = headers;

        UdpPacketBuilder {
            eth_frame,
            ip_header,
            udp_header,
            payload: None,
        }

    }

    fn set_payload(&mut self, value: Vec<u8>) -> &mut Self {
        self.payload = Some(value);
        self
    }

    fn build_to_vec(&mut self) -> Vec<u8> {

        let eth_frame = &self.eth_frame;
        let mut ip_header = &mut self.ip_header;
        let mut udp_header = &mut self.udp_header;

        let mut payload_len = 0;
        if let Some(payload) = &self.payload {
            payload_len = payload.len();
        }

        ip_header.length = (payload_len + size_of::<UdpHeader>() + size_of::<IpHeader>()) as _;
        ip_header.length = ip_header.length.to_be();

        ip_header.checksum = 0;
        ip_header.checksum = checksum(ip_header.as_slice_u16());

        udp_header.length = (payload_len + size_of::<UdpHeader>()) as _;
        udp_header.length = udp_header.length.to_be();

        let mut result: Vec<u8> = Vec::new();
        result.extend_from_slice(eth_frame.as_slice());
        result.extend_from_slice(ip_header.as_slice());
        result.extend_from_slice(udp_header.as_slice());

        if let Some(payload) = &self.payload {
            result.extend_from_slice(&payload[..]);
        }

        result
    }
}


#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    iface: Option<String>,
    hwaddr: Option<String>,
    timeout: Option<i32>,
    trys: Option<i32>,
    jid: Option<i32>,
}

fn checksum(data: &[u16]) -> u16 {

    let mut total: u32 = 0; 

    for hex in data.iter() {

        total += *hex as u32;
        let overflow = total >> 16;
        total = total & u16::max_value() as u32;
        total += overflow;

    }

    let total = total as u16;
    total ^ u16::max_value()

}

fn main() -> Result<(), Box<Error>> {

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let config: Config = serde_json::from_str(&input)?;

    if let Some(jid) = config.jid { libjail::attach(jid)?; }

    let iface = if let Some(iface) = config.iface { iface }
    else { lookupdev()? };

    let hwaddr = if let Some(hwaddr) = config.hwaddr {

        let hwaddr: String = hwaddr.split(':').collect();
        u64::from_str_radix(&hwaddr, 16)?

    } else { get_hwaddr(iface.clone())? };

    let xid = random_u32(0, u32::max_value());
    let timeout = config.timeout.unwrap_or(1000);
    let trys = config.trys.unwrap_or(10);
    let filter_str = format!("udp dst port 68 and ether[46:4] = 0x{:x}", xid);

    let mut dhcp_discover = unsafe { zeroed::<DhcpMessage>() };

    dhcp_discover.op = 0x01;
    dhcp_discover.htype = 0x01;
    dhcp_discover.hlen = 0x06;
    dhcp_discover.xid = xid.to_be();

    let hwaddr_slice = &(hwaddr.to_be_bytes())[2..];
    &mut dhcp_discover.chaddr[0..6].clone_from_slice(hwaddr_slice);

    dhcp_discover.cookie = 0x63_82_53_63_u32.to_be();

    let mut options: Vec<u8> = Vec::new();
    let mut option_53: u32 = 0x35_01_01;
    let option_53 = option_53.to_be_bytes();
    options.extend_from_slice(&option_53[1..]);

    let msg_slice = dhcp_discover.as_slice();
    let mut msg_vec = msg_slice.to_vec();
    msg_vec.append(&mut options);
    msg_vec.push(0xff);

    let mut eth_frame = EthFrame::new();
    let mut ip4_header = IpHeader::new();
    let mut udp_header = UdpHeader::new();

    eth_frame.set_source(hwaddr)
        .set_destination(HW_BROADCAST);

    ip4_header.set_proto(PROTO_UDP)
        .set_destination(Ipv4Addr::UNSPECIFIED)
        .set_destination(Ipv4Addr::BROADCAST);

    udp_header.set_src_port(68)
        .set_dst_port(67);

    let header = (eth_frame, ip4_header, udp_header);
    let mut builder = UdpPacketBuilder::new(header);
    builder.set_payload(msg_vec);

    let eth_msg = builder.build_to_vec();

    let mut out_sniffer = Sniffer::new(iface.to_owned())?;
    out_sniffer.activate()?;

    let mut in_sniffer = Sniffer::new(iface.to_owned())?;
    in_sniffer.set_timeout(timeout)?
        .set_promisc(true)?
        .set_snaplen(BUFSIZ as i32)?
        .activate()?
        .set_filter(filter_str.to_owned())?;

    out_sniffer.inject(&eth_msg[..])?;

    let mut result = None;
    for _ in 0..trys {

        match in_sniffer.read_next() {
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
    let offer_option_54 = options.get(&54)
        .ok_or("option 54 not found in offer")?;

    let mut dhcp_request = dhcp_offer.clone();

    let server_ip_ptr = offer_option_54.data.as_ptr() as *mut u32;

    dhcp_request.op = 0x01;
    dhcp_request.yiaddr = 0x0;
    dhcp_request.siaddr = 0x0;
    dhcp_request.siaddr = unsafe { *server_ip_ptr };

    let mut options: Vec<u8> = Vec::new();

    let option_53: u32 = 0x35_01_03;
    let option_53 = option_53.to_be_bytes();
    options.extend_from_slice(&option_53[1..]);

    let option_50: u64 = 0x32_04_00_00_00_00 + yiaddr as u64;
    let option_50 = option_50.to_be_bytes();
    options.extend_from_slice(&option_50[2..]);

    let option_54: u64 = 0x36_04_00_00_00_00 + siaddr as u64;
    let mut option_54 = option_54.to_be_bytes();
    &option_54[4..].copy_from_slice(&offer_option_54.data[..]);
    options.extend_from_slice(&option_54[2..]);

    let msg_sclie = dhcp_request.as_slice();
    let mut msg_vec = msg_slice.to_vec();
    msg_vec.append(&mut options);
    msg_vec.push(0xff);

    let mut out_sniffer = Sniffer::new(iface.to_owned())?;
    out_sniffer.activate()?;

    builder.set_payload(msg_vec);
    let eth_msg = builder.build_to_vec();

    let mut sniffer = Sniffer::new(iface.to_owned())?;
    sniffer.set_timeout(timeout)?
        .set_promisc(true)?
        .set_snaplen(BUFSIZ as i32)?
        .activate()?
        .set_filter(filter_str.to_owned())?;

    out_sniffer.inject(&eth_msg[..])?;

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
    let mut options: HashMap<_, _> = opt_iter
        .map(|option| option.to_json())
        .collect();

    options.remove("".into());

    let ip4: Ipv4Addr = dhcp_ack.yiaddr.to_be().into();

    let json = json!({
        "ip": ip4,
        "iface": iface,
        "options": options,
    });

    println!("{:#}", json);

    Ok(())

}
