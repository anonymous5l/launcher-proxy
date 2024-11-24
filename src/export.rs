use crate::loader::{get_header_dictionary, Module};
use std::ffi::{c_char, CStr};
use std::mem;
use windows::Win32::Foundation::FARPROC;
use windows::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_EXPORT;
use windows::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;

impl Module {
    pub(crate) unsafe fn load_export(&mut self) -> Option<()> {
        let code_base = self.code_base;

        let directory = get_header_dictionary(self, IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize);
        if directory.Size == 0 {
            return None;
        }

        let exports =
            &*(code_base.add(directory.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY);
        if exports.NumberOfNames == 0 || exports.NumberOfFunctions == 0 {
            return None;
        }

        let mut name_base = code_base.add(exports.AddressOfNames as usize) as *mut usize;
        let mut ordinal_base = code_base.add(exports.AddressOfNameOrdinals as usize) as *mut u16;

        for _ in 0..exports.NumberOfNames {
            let name = String::from_utf8_lossy(
                CStr::from_ptr(code_base.add(*name_base) as *const c_char).to_bytes(),
            )
            .to_string();
            let index = *ordinal_base;

            println!("{} {}", name, index);

            self.exports.insert(
                name,
                *(code_base.add(exports.AddressOfFunctions as usize) as *const usize)
                    .add(index as usize),
            );

            ordinal_base = ordinal_base.add(1);
            name_base = name_base.add(1);
        }

        None
    }

    pub fn get_proc_address(&self, name: &str) -> FARPROC {
        if let Some(proc_addr) = self.exports.get(name) {
            return unsafe { mem::transmute(self.code_base.add(*proc_addr)) };
        }
        None
    }

    pub unsafe fn entry_point(&self) -> i32 {
        if self.is_dll || self.exe_entry.is_none() || !self.is_relocated {
            return -1;
        }

        if let Some(entry) = self.exe_entry {
            return entry();
        }

        -1
    }
}
