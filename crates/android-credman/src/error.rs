use android_credman_sys::credman;
use std::ffi::CString;
use std::ptr;

pub fn return_error(title: &str) {
    let Ok(cred_id) = CString::new("some_id") else {
        return;
    };
    let Ok(title) = CString::new(title) else {
        return;
    };
    let Ok(subtitle) = CString::new("error") else {
        return;
    };
    let Ok(field_name) = CString::new("error") else {
        return;
    };

    unsafe {
        credman::AddStringIdEntry(
            cred_id.as_ptr(),
            ptr::null(),
            0,
            title.as_ptr(),
            subtitle.as_ptr(),
            ptr::null(),
            ptr::null(),
        );
        credman::AddFieldForStringIdEntry(cred_id.as_ptr(), field_name.as_ptr(), ptr::null());
    }
}
