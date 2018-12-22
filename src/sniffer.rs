use crate::pcap::*;
use crate::libc;
pub use crate::pcap::BUFSIZ;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::ffi::*;
use std::mem::*;
use std::slice;
use std::fmt;
use std::str::Utf8Error;
use std::ops::{Deref, DerefMut};
use std::default::Default;
use std::io;
use std::ptr;

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
    CreateError(String),
    FromBytesWithNulError(FromBytesWithNulError),
    Utf8Error(Utf8Error),
    SetFilterError(String),
    SetTimeoutError(String),
    SetSnaplenError(String),
    SetPromiscError(String),
    CompileRuleError(String),
    LookupNetError(String),
    DispatchError(String),
    ActivateError(String),
    InjectError(String),
    IfaceNotFound(String),
    LoopTerminated,
}

impl fmt::Display for SnifferError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnifferError::NulError(value) => value.fmt(f),
            SnifferError::CreateError(value) => value.fmt(f),
            SnifferError::FromBytesWithNulError(value) => value.fmt(f),
            SnifferError::Utf8Error(value) => value.fmt(f),
            SnifferError::SetFilterError(value) => value.fmt(f),
            SnifferError::SetTimeoutError(value) => value.fmt(f),
            SnifferError::SetSnaplenError(value) => value.fmt(f),
            SnifferError::SetPromiscError(value) => value.fmt(f),
            SnifferError::CompileRuleError(value) => value.fmt(f),
            SnifferError::LookupNetError(value) => value.fmt(f),
            SnifferError::DispatchError(value) => value.fmt(f),
            SnifferError::ActivateError(value) => value.fmt(f),
            SnifferError::InjectError(value) => value.fmt(f),
            SnifferError::IfaceNotFound(value) => value.fmt(f),
            SnifferError::LoopTerminated => write!(f, "loop terminated"),
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
pub struct Config {
    pub promisc: bool,
    pub timeout: i32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            promisc: true,
            timeout: 1000,
        }
    }
}

pub trait DeviceIter {
    fn iter(&self) -> DeviceIterator;
}

pub struct DeviceIterator {
    iface_next: *mut pcap_if_t,
}

impl Iterator for DeviceIterator {
    type Item = pcap_if_t;

    fn next(&mut self) -> Option<Self::Item> {

        if self.iface_next as usize != 0 {

            unsafe {
                let iface = *self.iface_next;
                self.iface_next = iface.next;
                Some(iface)
            }

        } else { None }

    }

}

impl DeviceIter for pcap_if_t {

    fn iter(&self) -> DeviceIterator {

        DeviceIterator { iface_next: self.next }

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
        let iface = iface.try_into()?.0;
        let error: Vec<u8> = vec![0; PCAP_ERRBUF_SIZE as usize];
        let handle = unsafe {
            pcap_create(iface.as_ptr(), error.as_ptr() as *mut _)
        };

        if handle as usize == 0 {
            let cstr_error = unsafe { CStr::from_ptr(error.as_ptr() as _) };
            let string_error = cstr_error.to_str()?.to_string();
            Err(SnifferError::CreateError(string_error))
        } else {
            Ok(Sniffer {
                iface: iface,
                handle: handle,
            })
        }
    }

    pub fn set_timeout(&mut self, ms: i32) -> Result<&mut Self, SnifferError> {

        let result = unsafe { pcap_set_timeout(self.handle, ms) };

        if result != 0 {
            let error = self.get_error()?;
            Err(SnifferError::SetTimeoutError(error))
        } else {
            Ok(self)
        }

    }

    pub fn set_snaplen(&mut self, value: i32) -> Result<&mut Self, SnifferError> {

        let result = unsafe { pcap_set_snaplen(self.handle, value) };

        if result != 0 {
            let error = self.get_error()?;
            Err(SnifferError::SetSnaplenError(error))
        } else {
            Ok(self)
        }

    }

    pub fn set_promisc(&mut self, value: bool) -> Result<&mut Self, SnifferError> {

        let result = unsafe { pcap_set_promisc(self.handle, value.into()) };

        if result != 0 {
            let error = self.get_error()?;
            Err(SnifferError::SetPromiscError(error))
        } else {
            Ok(self)
        }

    }

    pub fn set_filter(&mut self, filter: impl Into<String>) -> Result<&mut Self, SnifferError> {
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
            let result = pcap_lookupnet(
                self.iface.as_ptr(),
                net_ptr,
                mask_ptr,
                error.as_ptr() as *mut _,
            );

            if result == -1 {
                let cstr_error = CStr::from_ptr(error.as_ptr() as _);
                let string_error = cstr_error.to_str()?.to_string();
                return Err(SnifferError::LookupNetError(string_error));
            }

            let result = pcap_compile(self.handle, dhcp_program_ptr, dhcp_filter.as_ptr(), 0, net);
            if result == -1 {
                let error = SnifferError::CompileRuleError(self.get_error()?);
                return Err(error);
            }

            let result = pcap_setfilter(self.handle, dhcp_program_ptr);
            if result == -1 {
                let error = SnifferError::SetFilterError(self.get_error()?);
                return Err(error);
            }
        }

        Ok(self)
    }

    pub fn activate(&mut self) -> Result<&mut Self, SnifferError> {

        let result = unsafe { pcap_activate(self.handle) };

        if result != 0 {
            let error = self.get_error()?;
            Err(SnifferError::ActivateError(error))
        } else {
            Ok(self)
        }

    }

    pub fn inject(&mut self, buffer: &[u8]) -> Result<i32, SnifferError> {

        let buffer_ptr = buffer.as_ptr() as *const _;
        let count = unsafe { pcap_inject(self.handle, buffer_ptr, buffer.len()) };

        if count == -1 {
            let error = self.get_error()?;
            Err(SnifferError::InjectError(error))
        } else {
            Ok(count)
        }

    }

    pub fn read_next(&self) -> Option<(pcap_pkthdr, &[u8])> {

        let header_ptr = std::ptr::null::<pcap_pkthdr>();
        let data_ptr = std::ptr::null::<u8>();
        let header_ptr_ptr = &header_ptr as *const *const pcap_pkthdr as *mut *mut pcap_pkthdr;
        let data_ptr_ptr = &data_ptr as *const *const u8 as *mut *const u8;

        let result = unsafe { pcap_next_ex(self.handle, header_ptr_ptr, data_ptr_ptr) };

        if result == 1 {
            let header: pcap_pkthdr = unsafe { ptr::read(header_ptr) };
            let data = unsafe { slice::from_raw_parts(data_ptr, header.len as usize) };
            Some((header, data))
        } else {
            None
        }

    }

    pub fn dispatch(
        &self,
        count: i32,
        callback: fn(pcap_pkthdr, &[u8]),
    ) -> Result<i32, SnifferError> {
        let callback_ptr = &callback as *const _ as *mut _;

        let captured =
            unsafe { pcap_dispatch(self.handle, count, Some(dispatch_handler), callback_ptr) };

        match captured {
            -1 => {
                let error = self.get_error()?;
                Err(SnifferError::DispatchError(error))
            },
            -2 => Err(SnifferError::LoopTerminated),
            count @ _ => Ok(count),
        }
    }

    fn get_error(&self) -> Result<String, Utf8Error> {

        let error_ptr = unsafe { pcap_geterr(self.handle) };
        let cstr_error = unsafe { CStr::from_ptr(error_ptr) };
        Ok(cstr_error.to_str()?.to_string())

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

pub type Net = bpf_u_int32;
pub type Mask = bpf_u_int32;

pub fn lookupnet<I>(iface: I) -> Result<(Net, Mask), SnifferError>
    where I: TryInto<Iface, Error = SnifferError> {

    let iface = iface.try_into()?.0;

    let net: Net = unsafe { uninitialized() };
    let mask: Mask = unsafe { uninitialized() };
    let net_ptr = &net as *const _ as *mut _;
    let mask_ptr = &mask as *const _ as *mut _;

    let error: Vec<u8> = vec![0; PCAP_ERRBUF_SIZE as usize];
    let result = unsafe {
        pcap_lookupnet(iface.as_ptr(), net_ptr, mask_ptr, error.as_ptr() as *mut _)
    };

    if result == -1 {
        let cstr_error = unsafe { CStr::from_ptr(error.as_ptr() as _) };
        let string_error = cstr_error.to_str()?.to_string();
        Err(SnifferError::LookupNetError(string_error))
    } else {
        Ok((net, mask))
    }

}

pub fn get_hwaddr<I>(iface: I) -> Result<u64, SnifferError>
    where I: TryInto<Iface, Error = SnifferError> {

        unsafe {

            let iface_name = iface.try_into()?.0;

            let if_ptr = std::ptr::null::<pcap_if_t>();
            let if_ptr_ptr = &if_ptr as *const *const pcap_if_t as *mut *mut pcap_if_t;

            let error: Vec<u8> = vec![0; PCAP_ERRBUF_SIZE as usize];
            let result = pcap_findalldevs(if_ptr_ptr, error.as_ptr() as *mut _);

            let mut device_iterator = DeviceIterator { iface_next: if_ptr as *mut _ };

            let iface = device_iterator.find(|iface| {

                if iface.addresses as usize == 0 { return false; }

                let if_name: CString = CStr::from_ptr(iface.name).into();
                let if_addr = *iface.addresses;
                let if_sockaddr_dl = *(if_addr.addr as *mut libc::sockaddr_dl);

                let family_condition = if_sockaddr_dl.sdl_family == libc::AF_LINK as _;
                let iface_condition = if_name == iface_name;

                if iface_condition && family_condition { true }
                else { false }

            });

            pcap_freealldevs(if_ptr as _);
            let iface = iface.ok_or_else(|| {
                let error_msg = format!("interface {:?} not found", iface_name);
                SnifferError::IfaceNotFound(error_msg.into())
            })?;

            let if_addr = *iface.addresses;
            let if_sockaddr_dl = *(if_addr.addr as *mut libc::sockaddr_dl);

            let data_ptr = &if_sockaddr_dl.sdl_data as *const _ as *mut [u8; 46];
            let data = *data_ptr;
            let sdl_nlen = if_sockaddr_dl.sdl_nlen as usize;

            let hwaddr: &mut [u8; 8] = &mut [0; 8];
            &mut hwaddr[2..8].clone_from_slice(&data[sdl_nlen..sdl_nlen + 6]);
            let hwaddr = u64::from_be_bytes(*hwaddr);

            Ok(hwaddr)

        }

    }
