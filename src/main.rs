use std::mem::*;
use std::net::*;

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
    options: [u8; 340],
}

fn main() {

    let mut message = unsafe { zeroed::<Message>() };

    message.op = 0x01;
    message.htype = 0x01;
    message.hlen = 0x06;
    message.xid = 0x6666;

    let mac: u64 = 0xe8_03_9a_ce_61_26;
    let oct = &mac as *const _ as *mut u8;
    let mut t = unsafe { *(oct as *const [u8;6]) };
    t.reverse();

    &mut message.chaddr[0..6].clone_from_slice(&t);
    println!("{:?}", message.chaddr);

    let message_ptr = &message as *const _ as *mut u8;
    let size_message = size_of::<Message>();

    let sl = unsafe {
        std::slice::from_raw_parts(message_ptr as *const u8, size_message) 
    };

    println!("{:?}", sl);

    let socket = UdpSocket::bind("0.0.0.0:68").unwrap();
    socket.send_to(sl, "255.255.255.255:67").unwrap();

}
