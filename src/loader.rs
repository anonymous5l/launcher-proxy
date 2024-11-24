use cfg_if::cfg_if;
use std::collections::HashMap;
#[cfg(target_pointer_width = "64")]
use std::collections::LinkedList;
use std::ffi::c_void;
use std::mem::offset_of;
use std::{mem, ptr};
use windows::Win32;
use windows::Win32::Foundation::{
    FreeLibrary, GetLastError, ERROR_SUCCESS, ERROR_UNKNOWN_EXCEPTION, FARPROC, HINSTANCE,
    WIN32_ERROR,
};

#[cfg(target_pointer_width = "32")]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
#[cfg(target_pointer_width = "64")]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;

use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_FILE_DLL, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_NOT_CACHED, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    IMAGE_SECTION_CHARACTERISTICS, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    IsBadReadPtr, VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_DECOMMIT, MEM_RELEASE,
    MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_NOACCESS, PAGE_NOCACHE, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY,
};
use windows::Win32::System::SystemInformation::{
    GetNativeSystemInfo, IMAGE_FILE_MACHINE, SYSTEM_INFO,
};
use windows::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER,
    IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE,
    IMAGE_REL_BASED_HIGHLOW, PIMAGE_TLS_CALLBACK,
};
use windows_core::PCSTR;

use crate::error::Error;
use crate::error::Result;

const IMAGE_DOS_HEADER_SIZE: usize = size_of::<IMAGE_DOS_HEADER>();
const IMAGE_IMPORT_DESCRIPTOR_SIZE: usize = size_of::<IMAGE_IMPORT_DESCRIPTOR>();

const IMAGE_NT_HEADER_SIZE: usize = size_of::<ImageNtHeaders>();
const IMAGE_SIZE_OF_BASE_RELOCATION: usize = size_of::<IMAGE_BASE_RELOCATION>();

cfg_if! {
    if #[cfg(target_pointer_width = "64")] {
        type ImageNtHeaders = IMAGE_NT_HEADERS64;

        use std::ops::{Deref, DerefMut};
        use windows::Win32::System::SystemServices::{
            IMAGE_REL_BASED_DIR64, IMAGE_ORDINAL_FLAG64, IMAGE_TLS_DIRECTORY64,
        };
        use crate::loader::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;

        pub(crate) struct PointerList(LinkedList<*const c_void>);

        impl Deref for PointerList {
            type Target = LinkedList<*const c_void>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for PointerList {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl Drop for PointerList {
            fn drop(&mut self) {
                while let Some(ptr) = self.pop_front() {
                    if !ptr.is_null() {
                        unsafe {
                            let _ = VirtualFree(ptr as *mut c_void, 0, MEM_RELEASE);
                        }
                    }
                }
            }
        }

        #[inline]
        fn check_file_machine(i: IMAGE_FILE_MACHINE) -> bool {
            if i == IMAGE_FILE_MACHINE_AMD64 {
                true
            } else {
                false
            }
        }
    } else {
        type ImageNtHeaders = IMAGE_NT_HEADERS32;

        use crate::loader::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_I386;
        use windows::Win32::System::SystemServices::{
            IMAGE_ORDINAL_FLAG32, IMAGE_TLS_DIRECTORY32,
        };

        #[inline]
        fn check_file_machine(i: IMAGE_FILE_MACHINE) -> bool {
            if i == IMAGE_FILE_MACHINE_I386 {
                true
            } else {
                false
            }
        }
    }
}

type DllEntryFunc = Option<
    unsafe extern "system" fn(
        hinstDLL: HINSTANCE,
        fdw_reason: u32,
        lp_reserved: *mut c_void,
    ) -> bool,
>;

type ExeEntryFunc = Option<unsafe extern "system" fn() -> i32>;

const PROTECTION_FLAGS: [[[PAGE_PROTECTION_FLAGS; 2]; 2]; 2] = [
    [
        [PAGE_NOACCESS, PAGE_WRITECOPY],
        [PAGE_READONLY, PAGE_READWRITE],
    ],
    [
        [PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY],
        [PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE],
    ],
];

#[inline]
pub(crate) unsafe fn image_first_section(
    nt_header: *const ImageNtHeaders,
) -> *const IMAGE_SECTION_HEADER {
    nt_header
        .byte_add(offset_of!(ImageNtHeaders, OptionalHeader))
        .byte_add((&*nt_header).FileHeader.SizeOfOptionalHeader as usize)
        as *const IMAGE_SECTION_HEADER
}

#[inline]
fn align_value_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

#[inline]
fn align_value_down(value: usize, alignment: usize) -> usize {
    value & !(alignment - 1)
}

#[inline]
pub(crate) fn align_address_down(address: *const c_void, alignment: usize) -> *const c_void {
    align_value_down(address as usize, alignment) as *const c_void
}

#[inline]
pub(crate) fn get_real_section_size(module: &Module, section: &IMAGE_SECTION_HEADER) -> usize {
    if section.SizeOfRawData == 0 {
        if (section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
            == IMAGE_SCN_CNT_INITIALIZED_DATA
        {
            return module.headers.OptionalHeader.SizeOfInitializedData as usize;
        } else if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            == IMAGE_SCN_CNT_UNINITIALIZED_DATA
        {
            return module.headers.OptionalHeader.SizeOfUninitializedData as usize;
        }
    }
    section.SizeOfRawData as usize
}

#[inline]
pub(crate) fn get_header_dictionary(module: &Module, index: usize) -> IMAGE_DATA_DIRECTORY {
    module.headers.OptionalHeader.DataDirectory[index]
}

#[inline]
pub(crate) fn image_snap_by_ordinal(ordinal: usize) -> bool {
    cfg_if! {
        if #[cfg(target_pointer_width = "64")] {
            ((ordinal as u64) & IMAGE_ORDINAL_FLAG64) != 0
        } else {
            ((ordinal as u32) & IMAGE_ORDINAL_FLAG32) != 0
        }
    }
}

#[inline]
pub(crate) fn image_ordinal(ordinal: usize) -> usize {
    ordinal & 0xffff
}

pub unsafe fn copy_sections(
    data: *mut u8,
    data_size: usize,
    old_header: &ImageNtHeaders,
    module: &mut Module,
) -> Result<()> {
    let code_base = module.code_base;
    let mut section = &mut *image_first_section(module.headers).cast_mut();

    for _ in 0..module.headers.FileHeader.NumberOfSections {
        if section.SizeOfRawData == 0 {
            let section_size = old_header.OptionalHeader.SectionAlignment;
            if section_size > 0 {
                let mut dst = VirtualAlloc(
                    Some(code_base.add(section.VirtualAddress as usize)),
                    section_size as usize,
                    MEM_COMMIT,
                    PAGE_READWRITE,
                );
                if dst.is_null() {
                    return Err(Error::OutOfMemory);
                }

                dst = code_base.add(section.VirtualAddress as usize) as *mut c_void;
                section.Misc.PhysicalAddress = (dst as usize & 0xffffffff) as u32;
                ptr::write_bytes(dst, 0, section_size as usize);
            }
        } else {
            if data_size < (section.PointerToRawData + section.SizeOfRawData) as usize {
                return Err(Error::InvalidSize);
            }

            let mut dst = VirtualAlloc(
                Some(code_base.add(section.VirtualAddress as usize)),
                section.SizeOfRawData as usize,
                MEM_COMMIT,
                PAGE_READWRITE,
            );
            if dst.is_null() {
                return Err(Error::OutOfMemory);
            }

            dst = code_base.add(section.VirtualAddress as usize) as *mut c_void;
            ptr::copy_nonoverlapping(
                data.add(section.PointerToRawData as usize),
                dst as *mut u8,
                section.SizeOfRawData as usize,
            );
            section.Misc.PhysicalAddress = (dst as usize & 0xffffffff) as u32;
        }

        section = &mut *(section as *mut IMAGE_SECTION_HEADER).add(1);
    }
    Ok(())
}

unsafe fn perform_base_relocation(module: &mut Module, delta: isize) -> bool {
    let code_base = module.code_base;

    let directory = get_header_dictionary(module, IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize);
    if directory.Size == 0 {
        return delta == 0;
    }

    let mut relocation =
        &mut *(code_base.add(directory.VirtualAddress as usize) as *mut IMAGE_BASE_RELOCATION);

    while relocation.VirtualAddress > 0 {
        let dst = code_base.add(directory.VirtualAddress as usize) as *mut usize;

        let mut rel_info = &mut *(relocation as *mut IMAGE_BASE_RELOCATION as *mut u16)
            .byte_add(IMAGE_SIZE_OF_BASE_RELOCATION);

        for _ in 0..(relocation.SizeOfBlock as usize - IMAGE_SIZE_OF_BASE_RELOCATION) / 2 {
            let t = (*rel_info >> 12) as u32;
            let offset = (*rel_info & 0xfff) as usize;

            if t == IMAGE_REL_BASED_HIGHLOW {
                let patch_addr = &mut *dst.byte_add(offset);
                *patch_addr += delta as usize;
            } else {
                cfg_if! {
                    if #[cfg(target_pointer_width = "64")] {
                        if t == IMAGE_REL_BASED_DIR64 {
                            let patch_addr = &mut *dst.byte_add(offset);
                            *patch_addr += delta as usize;
                        }
                    }
                }
            }

            rel_info = &mut *(rel_info as *mut u16).add(1);
        }

        relocation = &mut *(relocation as *mut IMAGE_BASE_RELOCATION)
            .byte_add(relocation.SizeOfBlock as usize);
    }

    true
}

unsafe fn build_import_table(module: &mut Module) -> Result<()> {
    let code_base = module.code_base;

    let directory = get_header_dictionary(module, IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize);
    if directory.Size == 0 {
        return Ok(());
    }

    let mut import_desc =
        &mut *(code_base.add(directory.VirtualAddress as usize) as *mut IMAGE_IMPORT_DESCRIPTOR);

    while !IsBadReadPtr(
        Some(import_desc as *const IMAGE_IMPORT_DESCRIPTOR as *const c_void),
        IMAGE_IMPORT_DESCRIPTOR_SIZE,
    )
    .as_bool()
        && import_desc.Name > 0
    {
        let lib_name = PCSTR(code_base.add(import_desc.Name as usize) as *const u8);
        let handle = LoadLibraryA(lib_name).map_err(|e| {
            Error::SystemError(WIN32_ERROR::from_error(&e).unwrap_or(ERROR_UNKNOWN_EXCEPTION))
        })?;

        module.modules.push(handle);

        let mut thunk_ref = if import_desc.Anonymous.OriginalFirstThunk > 0 {
            code_base.add(import_desc.Anonymous.OriginalFirstThunk as usize) as *mut usize
        } else {
            code_base.add(import_desc.FirstThunk as usize) as *mut usize
        };

        let mut func_ref = &mut *(code_base.add(import_desc.FirstThunk as usize) as *mut FARPROC);

        while !thunk_ref.is_null() && *thunk_ref > 0 {
            let str;
            if image_snap_by_ordinal(*thunk_ref) {
                str = PCSTR(image_ordinal(*thunk_ref) as *const u8);
            } else {
                let thunk_data = &*(code_base.add(*thunk_ref) as *const IMAGE_IMPORT_BY_NAME);
                str = PCSTR((&thunk_data.Name) as *const i8 as *const u8);
            }
            *func_ref = GetProcAddress(handle, str);

            if func_ref.is_none() {
                let _ = FreeLibrary(handle);
                return Err(Error::ProcNotFound);
            }

            thunk_ref = thunk_ref.add(1);
            func_ref = &mut *(func_ref as *mut FARPROC).add(1);
        }

        import_desc = &mut *(import_desc as *mut IMAGE_IMPORT_DESCRIPTOR).add(1);
    }

    Ok(())
}

struct SectionFinalizeData {
    address: *const c_void,
    aligned_address: *const c_void,
    size: usize,
    characteristics: IMAGE_SECTION_CHARACTERISTICS,
    last: bool,
}

unsafe fn finalize_section(
    module: &mut Module,
    section_data: &mut SectionFinalizeData,
) -> Result<()> {
    if section_data.size == 0 {
        return Ok(());
    }

    if section_data.characteristics & IMAGE_SCN_MEM_DISCARDABLE == IMAGE_SCN_MEM_DISCARDABLE {
        if section_data.address == section_data.aligned_address
            && (section_data.last
                || module.headers.OptionalHeader.SectionAlignment == module.page_size
                || (section_data.size % module.page_size as usize) == 0)
        {
            VirtualFree(
                section_data.address as *mut c_void,
                section_data.size,
                MEM_DECOMMIT,
            )
            .map_err(|e| {
                Error::SystemError(WIN32_ERROR::from_error(&e).unwrap_or(ERROR_UNKNOWN_EXCEPTION))
            })?;
        }
        return Ok(());
    }

    fn bitand_zero_one(
        a: IMAGE_SECTION_CHARACTERISTICS,
        b: IMAGE_SECTION_CHARACTERISTICS,
    ) -> usize {
        if (a & b).0 != 0 {
            1
        } else {
            0
        }
    }

    let executable = bitand_zero_one(section_data.characteristics, IMAGE_SCN_MEM_EXECUTE);
    let readable = bitand_zero_one(section_data.characteristics, IMAGE_SCN_MEM_READ);
    let writeable = bitand_zero_one(section_data.characteristics, IMAGE_SCN_MEM_WRITE);
    let mut protect = PROTECTION_FLAGS[executable][readable][writeable];
    if (section_data.characteristics & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED {
        protect |= PAGE_NOCACHE;
    }

    let mut pr: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);

    VirtualProtect(
        section_data.address,
        section_data.size,
        protect,
        (&mut pr) as *mut PAGE_PROTECTION_FLAGS,
    )
    .map_err(|e| {
        Error::SystemError(WIN32_ERROR::from_error(&e).unwrap_or(ERROR_UNKNOWN_EXCEPTION))
    })?;

    Ok(())
}

unsafe fn finalize_sections(module: &mut Module) -> Result<()> {
    let mut section = &mut *(image_first_section(module.headers) as *mut IMAGE_SECTION_HEADER);

    cfg_if! {
        if #[cfg(target_pointer_width = "64")] {
            let image_offset = (module.headers.OptionalHeader.ImageBase as usize) & 0xffffffff00000000 ;
        } else {
            let image_offset = 0_usize;
        }
    }

    let address = ((section.Misc.PhysicalAddress as usize) | image_offset) as *const c_void;

    let mut section_data = SectionFinalizeData {
        address,
        aligned_address: align_address_down(address, module.page_size as usize),
        size: get_real_section_size(module, &*(section as *const IMAGE_SECTION_HEADER)),
        characteristics: (*section).Characteristics,
        last: false,
    };
    section = &mut *(section as *mut IMAGE_SECTION_HEADER).add(1);

    for _ in 1..module.headers.FileHeader.NumberOfSections {
        let section_address =
            ((section.Misc.PhysicalAddress as usize) | image_offset) as *const c_void;
        let aligned_address = align_address_down(section_address, module.page_size as usize);
        let section_size = get_real_section_size(module, section);

        if section_data.aligned_address == aligned_address
            || (section_data.address as usize) + section_data.size > aligned_address as usize
        {
            if (section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE).0 == 0
                || (section_data.characteristics & IMAGE_SCN_MEM_DISCARDABLE).0 == 0
            {
                section_data.characteristics = (section_data.characteristics
                    | section.Characteristics)
                    & !IMAGE_SCN_MEM_DISCARDABLE;
            } else {
                section_data.characteristics |= section.Characteristics;
            }
            section_data.size =
                (section_address as usize + section_size) - section_data.address as usize;
        } else {
            finalize_section(module, &mut section_data)?;
            section_data.address = section_address;
            section_data.aligned_address = aligned_address;
            section_data.size = section_size;
            section_data.characteristics = section.Characteristics;
        }

        section = &mut *(section as *mut IMAGE_SECTION_HEADER).add(1);
    }

    section_data.last = true;
    finalize_section(module, &mut section_data)?;

    Ok(())
}

unsafe fn execute_tls(module: &mut Module) -> Result<()> {
    let code_base = module.code_base;

    let directory = get_header_dictionary(module, IMAGE_DIRECTORY_ENTRY_TLS.0 as usize);
    if directory.VirtualAddress == 0 {
        return Ok(());
    }

    cfg_if! {
        if #[cfg(target_pointer_width = "64")] {
            let tls =
                &mut *(code_base.add(directory.VirtualAddress as usize) as *mut IMAGE_TLS_DIRECTORY64);
        } else {
            let tls =
                &mut *(code_base.add(directory.VirtualAddress as usize) as *mut IMAGE_TLS_DIRECTORY32);
        }
    }

    let mut callback_with_option = &mut *(tls.AddressOfCallBacks as *mut PIMAGE_TLS_CALLBACK);
    while let Some(callback) = callback_with_option {
        callback(
            code_base as *mut c_void,
            DLL_PROCESS_ATTACH,
            ptr::null_mut(),
        );
        callback_with_option = &mut *(callback_with_option as *mut PIMAGE_TLS_CALLBACK).add(1);
    }

    Ok(())
}

#[allow(dead_code)]
pub struct Module {
    pub(crate) headers: &'static mut ImageNtHeaders,
    pub(crate) code_base: *const c_void,
    pub(crate) modules: Vec<Win32::Foundation::HMODULE>,
    pub(crate) initialized: bool,
    pub(crate) is_dll: bool,
    pub(crate) is_relocated: bool,
    pub(crate) page_size: u32,
    pub(crate) exports: HashMap<String, usize>,
    pub(crate) dll_entry: DllEntryFunc,
    pub(crate) exe_entry: ExeEntryFunc,
    #[cfg(target_pointer_width = "64")]
    pub(crate) blocked_memory: PointerList,
}

impl Drop for Module {
    fn drop(&mut self) {
        if self.initialized {
            if let Some(entry) = self.dll_entry {
                unsafe {
                    entry(
                        HINSTANCE(self.code_base.cast_mut()),
                        DLL_PROCESS_DETACH,
                        ptr::null_mut(),
                    );
                }
            }
        }

        for module in &self.modules {
            if !module.is_invalid() {
                unsafe {
                    let _ = FreeLibrary(*module);
                }
            }
        }

        unsafe {
            let _ = VirtualFree(self.code_base.cast_mut(), 0, MEM_RELEASE);
        }
    }
}

pub unsafe fn load_library(data: *mut u8, data_size: usize) -> Result<Module> {
    if data_size < IMAGE_DOS_HEADER_SIZE {
        return Err(Error::InvalidSize);
    }

    let data_ptr = data;

    let dos_header = &*(data_ptr as *const IMAGE_DOS_HEADER);
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return Err(Error::InvalidFormat);
    }

    let lfanew = dos_header.e_lfanew as usize;

    if data_size < lfanew + IMAGE_NT_HEADER_SIZE {
        return Err(Error::InvalidSize);
    }

    let old_header = &*(data_ptr.add(dos_header.e_lfanew as usize) as *const ImageNtHeaders);
    if old_header.Signature != IMAGE_NT_SIGNATURE {
        return Err(Error::InvalidFormat);
    }

    if !check_file_machine(old_header.FileHeader.Machine) {
        return Err(Error::InvalidFormat);
    }

    if (old_header.OptionalHeader.SectionAlignment & 1) == 1 {
        return Err(Error::InvalidFormat);
    }

    let mut section = &*(image_first_section(old_header as *const ImageNtHeaders));
    let optional_section_size = old_header.OptionalHeader.SectionAlignment;

    let mut last_section_end = 0;
    for _ in 0..old_header.FileHeader.NumberOfSections {
        let end_of_section = if section.SizeOfRawData == 0 {
            section.VirtualAddress + optional_section_size
        } else {
            section.VirtualAddress + section.SizeOfRawData
        };

        if end_of_section > last_section_end {
            last_section_end = end_of_section
        }

        section = &*(section as *const IMAGE_SECTION_HEADER as *mut IMAGE_SECTION_HEADER).add(1);
    }

    let mut sys_info = SYSTEM_INFO::default();
    GetNativeSystemInfo((&mut sys_info) as *mut SYSTEM_INFO);
    let err = GetLastError();
    if err != ERROR_SUCCESS {
        return Err(Error::SystemError(err));
    }

    let aligned_image_size =
        align_value_up(old_header.OptionalHeader.SizeOfImage, sys_info.dwPageSize);

    if aligned_image_size != align_value_up(last_section_end, sys_info.dwPageSize) {
        return Err(Error::InvalidFormat);
    }

    let mut code = VirtualAlloc(
        Some(old_header.OptionalHeader.ImageBase as *const c_void),
        aligned_image_size as usize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    );

    if code.is_null() {
        code = VirtualAlloc(
            None,
            aligned_image_size as usize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );
        if code.is_null() {
            return Err(Error::OutOfMemory);
        }
    }

    cfg_if! {
        if #[cfg(target_pointer_width = "64")] {
            let mut blocked_memory = PointerList(LinkedList::new());
            while (code as usize) >> 32
                < (code as usize + aligned_image_size as usize) >>32
            {
                blocked_memory.push_front(code);
                code = VirtualAlloc(
                    None,
                    aligned_image_size as usize,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                );
                if code.is_null() {
                    return Err(Error::OutOfMemory);
                }
            }
        }
    }

    if data_size < old_header.OptionalHeader.SizeOfHeaders as usize {
        return Err(Error::InvalidSize);
    }

    let headers = VirtualAlloc(
        Some(code.cast_const()),
        old_header.OptionalHeader.SizeOfHeaders as usize,
        MEM_COMMIT,
        PAGE_READWRITE,
    );

    // copy PE header to code
    ptr::copy_nonoverlapping(
        dos_header as *const IMAGE_DOS_HEADER,
        headers as *mut IMAGE_DOS_HEADER,
        old_header.OptionalHeader.SizeOfHeaders as usize,
    );

    let mut module = Module {
        headers: &mut *(headers.add(dos_header.e_lfanew as usize) as *mut ImageNtHeaders),
        code_base: code as *const c_void,
        modules: Vec::with_capacity(32),
        initialized: false,
        is_dll: (old_header.FileHeader.Characteristics & IMAGE_FILE_DLL).0 != 0,
        is_relocated: false,
        page_size: sys_info.dwPageSize,
        exports: HashMap::new(),
        exe_entry: None,
        dll_entry: None,
        #[cfg(target_pointer_width = "64")]
        blocked_memory,
    };

    cfg_if! {
        if #[cfg(target_pointer_width = "64")] {
            module.headers.OptionalHeader.ImageBase = code as u64;
        } else {
            module.headers.OptionalHeader.ImageBase = code as u32;
        }
    }

    copy_sections(data, data_size, old_header, &mut module)?;

    let location_delta =
        (module.headers.OptionalHeader.ImageBase - old_header.OptionalHeader.ImageBase) as isize;
    if location_delta != 0 {
        module.is_relocated = perform_base_relocation(&mut module, location_delta);
    } else {
        module.is_relocated = true;
    }

    build_import_table(&mut module)?;
    finalize_sections(&mut module)?;
    execute_tls(&mut module)?;

    if module.headers.OptionalHeader.AddressOfEntryPoint != 0 {
        if module.is_dll {
            let dll_entry: DllEntryFunc = mem::transmute(
                code.add(module.headers.OptionalHeader.AddressOfEntryPoint as usize),
            );

            if let Some(entry) = dll_entry {
                if !entry(HINSTANCE(code), DLL_PROCESS_ATTACH, ptr::null_mut()) {
                    return Err(Error::DLLInitFailed);
                }
            }

            module.dll_entry = dll_entry;
            module.initialized = true;
        } else {
            module.exe_entry =
                mem::transmute(code.add(module.headers.OptionalHeader.AddressOfEntryPoint as usize))
        }
    }

    module.load_export();

    Ok(module)
}
