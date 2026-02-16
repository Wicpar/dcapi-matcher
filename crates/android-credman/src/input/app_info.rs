use crate::*;

/// Information about the application requesting the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallingAppInfo {
    pub package_name: String,
    pub origin: String,
}

/// Gets information about the application requesting the credential as a Rust struct.
pub fn get_calling_app_info() -> CallingAppInfo {
    let raw = abi::get_calling_app_info();

    fn c_arr_to_string(bytes: &[u8]) -> String {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }

    CallingAppInfo {
        package_name: c_arr_to_string(&raw.package_name),
        origin: c_arr_to_string(&raw.origin),
    }
}
