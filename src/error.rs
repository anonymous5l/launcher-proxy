use std::fmt::Formatter;
use windows::Win32::Foundation::WIN32_ERROR;

#[derive(Debug)]
#[allow(dead_code)]
pub enum Error {
    InvalidSize,
    InvalidFormat,
    OutOfMemory,
    ProcNotFound,
    DLLInitFailed,
    SystemError(WIN32_ERROR),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
