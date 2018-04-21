use ::*;
use std::{
    ffi::{CStr, CString},
    os::raw::*,
    ptr
};

/// Free the Rust-owned string in a safe way.
#[no_mangle]
pub extern fn rot26_free(input: *mut c_char) {
    unsafe { CString::from_raw(input); }
}

/// Encrypt the input using rot26.
#[no_mangle]
pub extern fn rot26_encrypt(input: *const c_char) -> *const c_char {
    rot26_encrypt_any(input, 26)
}

/// Decrypt the input using rot26.
#[no_mangle]
pub extern fn rot26_decrypt(input: *const c_char) -> *const c_char {
    rot26_decrypt_any(input, 26)
}

/// Encrypt the input using rot13.
/// Warning: Security researchers have managed to crack rot13.
/// New users are recommended to use rot26 for the best security.
#[no_mangle]
pub extern fn rot26_encrypt_rot13(input: *const c_char) -> *const c_char {
    rot26_encrypt_any(input, 13)
}

/// Decrypt the input using rot13.
/// Warning: Security researchers have managed to crack rot13.
/// New users are recommended to use rot26 for the best security.
#[no_mangle]
pub extern fn rot26_decrypt_rot13(input: *const c_char) -> *const c_char {
    rot26_decrypt_any(input, 13)
}

/// Encrypt using any amount.
/// Warning: Please carefully choose the right amount.
/// New users are recommended to use rot26 for the best security.
#[no_mangle]
pub extern fn rot26_encrypt_any(input: *const c_char, amount: u32) -> *const c_char {
    let input = match unsafe { CStr::from_ptr(input).to_str() } {
        Ok(input) => input,
        Err(_) => return ptr::null()
    };
    let output = encrypt_any(input, amount);
    match CString::new(output) {
        Ok(output) => output.into_raw(),
        Err(_) => ptr::null()
    }
}

/// Decrypt using any amount.
/// Warning: Please carefully choose the right amount.
/// New users are recommended to use rot26 for the best security.
#[no_mangle]
pub extern fn rot26_decrypt_any(input: *const c_char, amount: u32) -> *const c_char {
    let input = match unsafe { CStr::from_ptr(input).to_str() } {
        Ok(input) => input,
        Err(_) => return ptr::null()
    };
    let output = decrypt_any(input, amount);
    match CString::new(output) {
        Ok(output) => output.into_raw(),
        Err(_) => return ptr::null()
    }
}
