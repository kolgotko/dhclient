use crate::pcap::*;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::ffi::*;
use std::mem::*;
use std::slice;
use std::fmt;
use std::str::Utf8Error;
use std::ops::{Deref, DerefMut};
use std::default::Default;

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
    SetFilterError(String),
    CompileRuleError(String),
    LookupNetError(String),
    DispatchError(String),
    LoopTerminated,
}

impl fmt::Display for SnifferError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnifferError::NulError(error) => error.fmt(f),
            SnifferError::OpenLiveError(value) => value.fmt(f),
            SnifferError::FromBytesWithNulError(error) => error.fmt(f),
            SnifferError::Utf8Error(error) => error.fmt(f),
            SnifferError::SetFilterError(error) => error.fmt(f),
            SnifferError::CompileRuleError(error) => error.fmt(f),
            SnifferError::LookupNetError(value) => value.fmt(f),
            SnifferError::DispatchError(value) => value.fmt(f),
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

#[derive(Debug)]
pub struct Sniffer {
    iface: CString,
    config: Config,
    handle: *mut pcap_t,
}

impl Sniffer {
    pub fn new<T>(iface: T, config: Config) -> Result<Self, SnifferError>
    where
        T: TryInto<Iface, Error = SnifferError>,
    {
        unsafe {
            let iface = iface.try_into()?.0;

            let error: Vec<u8> = vec![0; PCAP_ERRBUF_SIZE as usize];
            let handle = pcap_open_live(
                iface.as_ptr(),
                BUFSIZ as i32,
                config.promisc.into(),
                config.timeout,
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
                    config: config,
                })
            }
        }
    }

    pub fn set_filter(&mut self, filter: impl Into<String>) -> Result<(), SnifferError> {
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
                let cstr_error = CStr::from_bytes_with_nul(&error)?;
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

        Ok(())
    }

    pub fn read_packet(&self, buf: &mut Vec<u8>) -> Result<i32, SnifferError> {

        let buf_ptr = buf as *const _ as *mut _;
        let captured = unsafe { pcap_dispatch(self.handle, 1, Some(read_packet_handler), buf_ptr) };

        match captured {
            -1 => {
                let error = self.get_error()?;
                Err(SnifferError::DispatchError(error))
            },
            -2 => Err(SnifferError::LoopTerminated),
            count @ _ => Ok(count),
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
