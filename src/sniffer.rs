use crate::pcap::*;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::ffi::*;
use std::mem::*;
use std::slice;
use std::fmt;
use std::str::Utf8Error;
use std::ops::{ Deref, DerefMut };

#[no_mangle]
pub unsafe extern "C" fn read_packet_handler(
    args: *mut u8,
    header: *const pcap_pkthdr,
    packet: *const u8,
) {
    let buf = transmute::<*mut u8, &mut Vec<u8>>(args);
    let header = *header;
    let packet = slice::from_raw_parts(packet, header.len as usize);
    buf.extend_from_slice(packet);
}

#[no_mangle]
pub unsafe extern "C" fn dispatch_handler(
    args: *mut u8,
    header: *const pcap_pkthdr,
    packet: *const u8,
) {
    let callback = transmute::<*mut u8, &mut fn(pcap_pkthdr, &[u8])>(args);
    let header = *header;
    let packet = slice::from_raw_parts(packet, header.len as usize);

    callback(header, packet);
}

#[derive(Debug)]
pub enum SnifferError {
    NulError(NulError),
    OpenLiveError(String),
    FromBytesWithNulError(FromBytesWithNulError),
    Utf8Error(Utf8Error),
}

impl fmt::Display for SnifferError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnifferError::NulError(error) => error.fmt(f),
            SnifferError::OpenLiveError(value) => value.fmt(f),
            SnifferError::FromBytesWithNulError(error) => error.fmt(f),
            SnifferError::Utf8Error(error) => error.fmt(f),
        }
    }
}

impl Error for SnifferError {}

impl From<NulError> for SnifferError {
    fn from(value: NulError) -> Self {
        SnifferError::NulError(value)
    }
}

impl From<Utf8Error> for SnifferError {
    fn from(value: Utf8Error) -> Self {
        SnifferError::Utf8Error(value)
    }
}

impl From<FromBytesWithNulError> for SnifferError {
    fn from(value: FromBytesWithNulError) -> Self {
        SnifferError::FromBytesWithNulError(value)
    }
}

#[derive(Debug)]
pub struct Iface(CString);

impl Deref for Iface {
    type Target = CString;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Iface {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TryFrom<CString> for Iface {
    type Error = SnifferError;

    fn try_from(value: CString) -> Result<Self, Self::Error> {
        Ok(Iface(value))
    }
}

impl TryFrom<&CStr> for Iface {
    type Error = SnifferError;

    fn try_from(value: &CStr) -> Result<Self, Self::Error> {
        Ok(Iface(value.into()))
    }
}

impl TryFrom<String> for Iface {
    type Error = SnifferError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Iface(CString::new(value)?))
    }
}

impl TryFrom<&str> for Iface {
    type Error = SnifferError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Iface(CString::new(value)?))
    }
}

#[derive(Debug)]
pub struct Sniffer {
    iface: CString,
    handle: *mut pcap_t,
}

impl Sniffer {
    pub fn new<T>(iface: T) -> Result<Self, SnifferError>
    where
        T: TryInto<Iface, Error = SnifferError>,
    {
        unsafe {
            let iface = iface.try_into()?.0;

            let error: Vec<u8> = vec![0; PCAP_ERRBUF_SIZE as usize];
            let handle = pcap_open_live(
                iface.as_ptr(),
                BUFSIZ as i32,
                1,
                1000,
                error.as_ptr() as *mut _,
            );

            if handle as usize == 0 {
                let cstr_error = CStr::from_bytes_with_nul(&error)?;
                let string_error = cstr_error.to_str()?.to_string();
                Err(SnifferError::OpenLiveError(string_error))
            } else {
                Ok(Sniffer {
                    iface: iface,
                    handle: handle,
                })
            }
        }
    }

    pub fn set_timeout(&mut self, ms: i32) -> Result<(), Box<dyn Error>> {
        let result = unsafe { pcap_set_timeout(self.handle, ms) };

        if result == 0 {
            Ok(())
        } else {
            Err("pcap_set_timeout error")?
        }
    }

    pub fn set_promisc(&mut self, value: bool) -> Result<(), Box<dyn Error>> {
        let result = unsafe { pcap_set_promisc(self.handle, value.into()) };

        if result == 0 {
            Ok(())
        } else {
            Err("pcap_set_promisc error")?
        }
    }

    pub fn set_filter(&mut self, filter: impl Into<String>) -> Result<(), Box<Error>> {
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
            let _result = pcap_lookupnet(
                self.iface.as_ptr(),
                net_ptr,
                mask_ptr,
                error.as_ptr() as *mut _,
            );
            let _result = pcap_compile(self.handle, dhcp_program_ptr, dhcp_filter.as_ptr(), 0, net);
            let _result = pcap_setfilter(self.handle, dhcp_program_ptr);
        }

        Ok(())
    }

    pub fn read_packet(&self, buf: &mut Vec<u8>) -> Result<i32, Box<dyn Error>> {
        let buf_ptr = buf as *const _ as *mut _;
        println!("{:?}", buf_ptr);

        let captured = unsafe { pcap_dispatch(self.handle, 1, Some(read_packet_handler), buf_ptr) };

        match captured {
            -1 => Err("pcap_dispatch error")?,
            -2 => Err("pcap_dispatch break")?,
            count @ _ => Ok(count),
        }
    }

    pub fn dispatch(
        &self,
        count: i32,
        callback: fn(pcap_pkthdr, &[u8]),
    ) -> Result<i32, Box<dyn Error>> {
        let callback_ptr = &callback as *const _ as *mut _;

        let captured =
            unsafe { pcap_dispatch(self.handle, count, Some(dispatch_handler), callback_ptr) };

        match captured {
            -1 => Err("pcap_dispatch error")?,
            -2 => Err("pcap_dispatch break")?,
            count @ _ => Ok(count),
        }
    }
}

impl Drop for Sniffer {
    fn drop(&mut self) {
        unsafe { pcap_close(self.handle) }
    }
}

pub fn lookupdev() -> Result<String, SnifferError> {
    let error: Vec<u8> = vec![0; PCAP_ERRBUF_SIZE as usize];
    let dev_ptr = unsafe { pcap_lookupdev(error.as_ptr() as *mut _) };
    let cstr_dev = unsafe { CStr::from_ptr(dev_ptr) };
    Ok(cstr_dev.to_str()?.to_string())
}
