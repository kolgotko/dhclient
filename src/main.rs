#![feature(try_from)]
extern crate dhclient;

use std::mem::*;
use std::net::*;
use std::net::*;
use std::ffi::*;
use std::ptr;
use std::thread;
use std::collections::HashMap;
use dhclient::pcap::*;
use std::io;
use std::error::Error;
use std::convert::{ TryFrom, TryInto };


#[no_mangle]
pub unsafe extern "C" fn read_packet_handler(args: *mut u8, header: *const pcap_pkthdr, packet: *const u8) {

    let mut buf = transmute::<*mut u8, &mut Vec<u8>>(args);
    let header = *header;
    let packet = std::slice::from_raw_parts(packet, header.len as usize);
    buf.extend_from_slice(packet);

}

#[no_mangle]
pub unsafe extern "C" fn dispatch_handler(args: *mut u8, header: *const pcap_pkthdr, packet: *const u8) {

    let mut callback = transmute::<*mut u8, &mut fn(pcap_pkthdr, &[u8])>(args);
    let header = *header;
    let packet = std::slice::from_raw_parts(packet, header.len as usize);

    callback(header, packet);

}

#[derive(Debug)]
struct Iface(CString);

impl TryFrom<CString> for Iface {
    type Error = NulError;

    fn try_from(value: CString) -> Result<Self, Self::Error> {
        Ok(Iface(value))
    }
}

impl TryFrom<&CStr> for Iface {
    type Error = NulError;

    fn try_from(value: &CStr) -> Result<Self, Self::Error> {
        Ok(Iface(value.into()))
    }
}

impl TryFrom<String> for Iface {
    type Error = NulError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Iface(CString::new(value)?))
    }
}

impl TryFrom<&str> for Iface {
    type Error = NulError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Iface(CString::new(value)?))
    }
}

#[derive(Debug)]
struct Pcap {
    iface: CString,
    handle: *mut pcap_t,
}

impl Pcap {

    fn new<T>(iface: T) -> Result<Self, Box<dyn Error>>
        where T: TryInto<Iface, Error=NulError> {
        unsafe {

            let iface = iface.try_into()?.0;

            let error: Vec<u8> = vec![0; PCAP_ERRBUF_SIZE as usize];
            let handle = pcap_open_live(
                iface.as_ptr(),
                BUFSIZ as i32,
                1,
                1000,
                error.as_ptr() as *mut _
                );

            if handle as usize == 0 {

               Err("pcal_open_live error")?

            } else {

                Ok(Pcap {
                    iface: iface,
                    handle: handle,
                })

            }

        }
    }

    fn set_timeout(&mut self, ms: i32) -> Result<(), Box<dyn Error>> {

        let result = unsafe { pcap_set_timeout(self.handle, ms) };

        if result == 0 { Ok(()) }
        else { Err("pcap_set_timeout error")? }

    }

    fn set_promisc(&mut self, value: bool) -> Result<(), Box<dyn Error>> {

        let result = unsafe { pcap_set_promisc(self.handle, value.into()) };

        if result == 0 { Ok(()) }
        else { Err("pcap_set_promisc error")? }

    }

    fn set_filter(&mut self, filter: impl Into<String>) -> Result<(), Box<Error>> {

        unsafe {
            let filter: String = filter.into();

            let dhcp_program: bpf_program = uninitialized();
            let dhcp_program_ptr: *mut bpf_program = &dhcp_program as *const _ as *mut _;
            let dhcp_filter = CString::new(filter)?;

            let net: bpf_u_int32 = uninitialized();
            let mask: bpf_u_int32 = uninitialized();
            let net_ptr = &net as *const _ as *mut _;
            let mask_ptr = &mask as *const _ as *mut _;

            let error: Vec<u8> = vec![0; PCAP_ERRBUF_SIZE as usize];
            let result = pcap_lookupnet(self.iface.as_ptr(), net_ptr, mask_ptr, error.as_ptr() as *mut _);
            let result = pcap_compile(self.handle, dhcp_program_ptr, dhcp_filter.as_ptr(), 0, net);
            let result = pcap_setfilter(self.handle, dhcp_program_ptr);
        }

        Ok(())

    }

    fn read_packet(&self, mut buf: &mut Vec<u8>) -> Result<i32, Box<dyn Error>> {

        let buf_ptr = buf as *const _  as *mut _;
        println!("{:?}", buf_ptr);

        let captured = unsafe {
            pcap_dispatch(self.handle, 1, Some(read_packet_handler), buf_ptr) 
        };

        match captured {
            -1 => Err("pcap_dispatch error")?,
            -2 => Err("pcap_dispatch break")?,
            count @ _ => Ok(count),
        }

    }

    fn dispatch(&self, count: i32, callback: fn(pcap_pkthdr, &[u8])) -> Result<i32, Box<dyn Error>> {

        let callback_ptr = &callback as *const _  as *mut _;

        let captured = unsafe {
            pcap_dispatch(self.handle, count, Some(dispatch_handler), callback_ptr) 
        };

        match captured {
            -1 => Err("pcap_dispatch error")?,
            -2 => Err("pcap_dispatch break")?,
            count @ _ => Ok(count),
        }

    }

}


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

        if *code == 255 { return None; }

        let length = slice.get(1)?;
        let data = slice.get(2..2 + *length as usize)?;

        self.offset = self.offset + 2 + *length as usize;

        Some(DhcpOption {
            code: *code,
            length: *length,
            data: data.into()
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
    chaddr: [u8;16],
    sname: [u8;64],
    file: [u8;128],
    cookie: u32,
}

fn lookupdev() -> Result<Iface, Box<Error>> {

    let error: Vec<u8> = vec![0; PCAP_ERRBUF_SIZE as usize];
    let dev_ptr = unsafe { pcap_lookupdev(error.as_ptr() as *mut _) };
    let dev = unsafe { CStr::from_ptr(dev_ptr) };
    Ok(dev.try_into()?)

}

#[no_mangle]
pub unsafe extern "C" fn packet_handler(args: *mut u8, header: *const pcap_pkthdr, packet: *const u8) {

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
    let opt_iter = OptionsIterator { slice: options_slice, offset: 0 };

    let options: HashMap<_, _> = opt_iter.map(|option| (option.code, option)).collect();

    println!("{:?}", Ipv4Addr::from(message.yiaddr.to_be()));
    println!("{:x}", message.xid);
    println!("{:?}", options);

}

fn main() {

    let mut message = unsafe { zeroed::<DhcpMessage>() };

    message.op = 0x01;
    message.htype = 0x01;
    message.hlen = 0x06;
    message.xid = 0x6666;

    let mac: String = "e8:03:9a:ce:61:27".split(':').collect();
    let mac = u64::from_str_radix(&mac, 16).unwrap();

    let oct = &mac as *const _ as *mut u8;
    let mut t = unsafe { *(oct as *const [u8;6]) };
    t.reverse();

    &mut message.chaddr[0..6].clone_from_slice(&t);

    let mut options: Vec<u8> = Vec::new();

    let cookie: u32 = 0x63_82_53_63;
    message.cookie = cookie.to_be();

    let option_53: u32 = 0x35_01_01;
    let oct = &option_53 as *const _ as *mut u8;
    let mut t = unsafe { *(oct as *const [u8;3]) };
    t.reverse();

    options.extend_from_slice(&t);

    let message_ptr = &message as *const _ as *mut u8;
    let message_size = size_of::<DhcpMessage>();

    let msg_slice = unsafe {
        std::slice::from_raw_parts(message_ptr as *const u8, message_size) 
    };

    let mut msg_vec = msg_slice.to_vec();
    msg_vec.append(&mut options);
    msg_vec.push(0xff);

    println!("{:?}", msg_vec);

    let socket = UdpSocket::bind("0.0.0.0:68").unwrap();
    socket.set_broadcast(true).unwrap();
    socket.send_to(&msg_vec, "255.255.255.255:67").unwrap();

}
