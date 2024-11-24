use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        target_os = "windows"
    ))] {
        mod error;
        mod export;
        mod loader;
    }
}

use lazy_static::lazy_static;
use std::arch::asm;
use std::ffi::{c_void, CStr};
use windows::Win32::Foundation::{FARPROC, HINSTANCE};
use windows::Win32::System::Console::AllocConsole;
use windows::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows::Win32::System::Threading::{CreateThread, THREAD_CREATE_RUN_IMMEDIATELY};

const DLL: &[u8] = include_bytes!("../ijl15.dll");

struct ProxyModule {
    module: *const loader::Module,
    ijl_get_lib_version: FARPROC,
    ijl_get_lib_init: FARPROC,
    ijl_get_lib_free: FARPROC,
    ijl_get_lib_read: FARPROC,
    ijl_get_lib_write: FARPROC,
    ijl_get_lib_error_str: FARPROC,
}

unsafe impl Sync for ProxyModule {}

lazy_static! {
    static ref MODULE: ProxyModule = {
        unsafe {
            let dll_size = DLL.len();
            let dll_ptr = DLL.as_ptr() as *mut u8;
            let module = loader::load_library(dll_ptr, dll_size);

            if let Ok(module) = module {
                let leak_module = Box::leak(Box::new(module)) as *const loader::Module;
                let module_ref = &*leak_module;
                ProxyModule {
                    module: leak_module,
                    ijl_get_lib_version: module_ref.get_proc_address("ijlGetLibVersion"),
                    ijl_get_lib_init: module_ref.get_proc_address("ijlInit"),
                    ijl_get_lib_free: module_ref.get_proc_address("ijlFree"),
                    ijl_get_lib_read: module_ref.get_proc_address("ijlRead"),
                    ijl_get_lib_write: module_ref.get_proc_address("ijlWrite"),
                    ijl_get_lib_error_str: module_ref.get_proc_address("ijlErrorStr"),
                }
            } else {
                panic!("failed to load module from memory");
            }
        }
    };
}

macro_rules! cstr {
    ($str:literal) => {
        CStr::from_bytes_with_nul_unchecked(concat!($str, "\0").as_bytes()).as_ptr()
    };
}

unsafe extern "system" fn actual_main(_param: *mut c_void) -> u32 {
    AllocConsole().expect("alloc console failed");

    libc::freopen(
        cstr!("CONOUT$"),
        cstr!("w"),
        libc::fopen(cstr!("0"), cstr!("w")),
    );

    println!("dada successful running on new thread");

    0
}

#[no_mangle]
pub extern "system" fn DllMain(h_module: HINSTANCE, fdw_reason: u32, _: *mut c_void) -> bool {
    if fdw_reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(h_module).expect("disabled failed");
            CreateThread(
                None,
                0x1000,
                Some(actual_main),
                None,
                THREAD_CREATE_RUN_IMMEDIATELY,
                None,
            )
            .expect("create thread failed");
        }
    } else if fdw_reason == DLL_PROCESS_DETACH {
        unsafe {
            drop(Box::from_raw(MODULE.module as *mut loader::Module));
        }
    }
    true
}

#[no_mangle]
pub extern "system" fn ijlGetLibVersion() {
    unsafe {
        asm!("jmp dword ptr [{}]", in(reg) MODULE.ijl_get_lib_version.unwrap());
    }
}

#[no_mangle]
pub extern "system" fn ijlInit() {
    unsafe {
        asm!("jmp dword ptr [{}]", in(reg) MODULE.ijl_get_lib_init.unwrap());
    }
}

#[no_mangle]
pub extern "system" fn ijlFree() {
    unsafe {
        asm!("jmp dword ptr [{}]", in(reg) MODULE.ijl_get_lib_free.unwrap());
    }
}

#[no_mangle]
pub extern "system" fn ijlRead() {
    unsafe {
        asm!("jmp dword ptr [{}]", in(reg) MODULE.ijl_get_lib_read.unwrap());
    }
}

#[no_mangle]
pub extern "system" fn ijlWrite() {
    unsafe {
        asm!("jmp dword ptr [{}]", in(reg) MODULE.ijl_get_lib_write.unwrap());
    }
}

#[no_mangle]
pub extern "system" fn ijlErrorStr() {
    unsafe {
        asm!("jmp dword ptr [{}]", in(reg) MODULE.ijl_get_lib_error_str.unwrap());
    }
}
