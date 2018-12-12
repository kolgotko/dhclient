extern crate libc;
extern crate dhclient;

use std::mem::*;
use std::net::*;
use std::net::*;
use std::ptr;
use std::thread;


#[repr(C)]
struct Message {
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

use dhclient::pcap::*;
use std::ffi::*;

#[no_mangle]
pub unsafe extern "C" fn packet_handler(args: *mut u8, header: *const pcap_pkthdr, packet: *const u8) {

    let header = *header;
    println!("capture {:?}", header);

}

fn main() {


    unsafe {

        let dev = CString::new("alc0").unwrap();
        let error: Vec<u8> = vec![0; PCAP_ERRBUF_SIZE as usize];

        // pcap_lookupdev(error.as_ptr() as *mut _);
        let handle = pcap_open_live(dev.as_ptr(), BUFSIZ as i32, 1, 1000, error.as_ptr() as *mut _);

        // let header = uninitialized::<pcap_pkthdr>();
        // let packet = pcap_next(handle, &header as *const _ as *mut _);
        // pcap_close(handle);

        pcap_loop(handle, 10, Some(packet_handler), ptr::null_mut() as *mut _);

        // println!("{:?}", header);
        // println!("{:?}", handle);

    }
    panic!();

    let mut message = unsafe { zeroed::<Message>() };

    message.op = 0x01;
    message.htype = 0x01;
    message.hlen = 0x06;
    message.xid = 0x6666;

    let mac: u64 = 0xe8_03_9a_ce_61_27;
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

    println!("{:?}", options);

    let message_ptr = &message as *const _ as *mut u8;
    let message_size = size_of::<Message>();

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

    let mut buffer: Vec<u8> = vec![0;256];
    let (count, addr) = socket.recv_from(&mut buffer).unwrap();

    let recv_slice = &buffer[0..message_size];

    let recv_message: Message = unsafe {
        std::ptr::read(recv_slice.as_ptr() as *const _) 
    };


    println!("{:?}", buffer);
    println!("{:?}", Ipv4Addr::from(recv_message.yiaddr.to_be()));
    println!("{:x}", recv_message.xid);


}
