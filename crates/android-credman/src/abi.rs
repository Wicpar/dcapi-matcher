#![allow(clippy::too_many_arguments)]

use android_credman_sys::{credman, credman_v2, credman_v4};
use std::ffi::{CString, c_char};
use std::ptr;

fn to_c_str(s: Option<&str>) -> (Option<CString>, *const c_char) {
    match s {
        Some(str_val) => {
            let c_str = CString::new(str_val).unwrap_or_default();
            let ptr = c_str.as_ptr();
            (Some(c_str), ptr)
        }
        None => (None, ptr::null()),
    }
}

fn to_bytes_ptr_len(b: Option<&[u8]>) -> (*const c_char, usize) {
    match b {
        Some(bytes) => (bytes.as_ptr() as *const c_char, bytes.len()),
        None => (ptr::null(), 0),
    }
}

pub fn add_string_id_entry(
    cred_id: &str,
    icon: Option<&[u8]>,
    title: &str,
    subtitle: Option<&str>,
    disclaimer: Option<&str>,
    warning: Option<&str>,
) {
    let (_c_cred_id, p_cred_id) = to_c_str(Some(cred_id));
    let (p_icon, len_icon) = to_bytes_ptr_len(icon);
    let (_c_title, p_title) = to_c_str(Some(title));
    let (_c_subtitle, p_subtitle) = to_c_str(subtitle);
    let (_c_disclaimer, p_disclaimer) = to_c_str(disclaimer);
    let (_c_warning, p_warning) = to_c_str(warning);

    unsafe {
        credman::AddStringIdEntry(
            p_cred_id,
            p_icon,
            len_icon,
            p_title,
            p_subtitle,
            p_disclaimer,
            p_warning,
        );
    }
}

pub fn add_field_for_string_id_entry_opt(
    cred_id: &str,
    field_display_name: &str,
    field_display_value: Option<&str>,
) {
    let (_c_cred_id, p_cred_id) = to_c_str(Some(cred_id));
    let (_c_name, p_name) = to_c_str(Some(field_display_name));
    let (_c_val, p_val) = to_c_str(field_display_value);

    unsafe {
        credman::AddFieldForStringIdEntry(p_cred_id, p_name, p_val);
    }
}

pub fn add_payment_entry(
    cred_id: &str,
    merchant_name: &str,
    payment_method_name: Option<&str>,
    payment_method_subtitle: Option<&str>,
    payment_method_icon: Option<&[u8]>,
    transaction_amount: &str,
    bank_icon: Option<&[u8]>,
    payment_provider_icon: Option<&[u8]>,
) {
    let (_c_cred_id, p_cred_id) = to_c_str(Some(cred_id));
    let (_c_merchant, p_merchant) = to_c_str(Some(merchant_name));
    let (_c_pm_name, p_pm_name) = to_c_str(payment_method_name);
    let (_c_pm_sub, p_pm_sub) = to_c_str(payment_method_subtitle);
    let (p_pm_icon, len_pm_icon) = to_bytes_ptr_len(payment_method_icon);
    let (_c_amount, p_amount) = to_c_str(Some(transaction_amount));
    let (p_bank_icon, len_bank_icon) = to_bytes_ptr_len(bank_icon);
    let (p_pp_icon, len_pp_icon) = to_bytes_ptr_len(payment_provider_icon);

    unsafe {
        credman::AddPaymentEntry(
            p_cred_id,
            p_merchant,
            p_pm_name,
            p_pm_sub,
            p_pm_icon,
            len_pm_icon,
            p_amount,
            p_bank_icon,
            len_bank_icon,
            p_pp_icon,
            len_pp_icon,
        );
    }
}

pub fn add_inline_issuance_entry(
    cred_id: &str,
    icon: Option<&[u8]>,
    title: &str,
    subtitle: Option<&str>,
) {
    let (_c_cred_id, p_cred_id) = to_c_str(Some(cred_id));
    let (p_icon, len_icon) = to_bytes_ptr_len(icon);
    let (_c_title, p_title) = to_c_str(Some(title));
    let (_c_subtitle, p_subtitle) = to_c_str(subtitle);

    unsafe {
        credman::AddInlineIssuanceEntry(p_cred_id, p_icon, len_icon, p_title, p_subtitle);
    }
}

pub fn set_additional_disclaimer_and_url(
    cred_id: &str,
    secondary_disclaimer: Option<&str>,
    url_display_text: Option<&str>,
    url_value: Option<&str>,
) {
    let (_c_cred_id, p_cred_id) = to_c_str(Some(cred_id));
    let (_c_disc, p_disc) = to_c_str(secondary_disclaimer);
    let (_c_url_txt, p_url_txt) = to_c_str(url_display_text);
    let (_c_url_val, p_url_val) = to_c_str(url_value);

    unsafe {
        credman::SetAdditionalDisclaimerAndUrlForVerificationEntry(
            p_cred_id, p_disc, p_url_txt, p_url_val,
        );
    }
}

// --- V2 ---

pub fn add_entry_set(set_id: &str, set_length: i32) {
    let (_c_set_id, p_set_id) = to_c_str(Some(set_id));
    unsafe {
        credman_v2::AddEntrySet(p_set_id, set_length);
    }
}

pub fn add_entry_to_set(
    cred_id: &str,
    icon: Option<&[u8]>,
    title: &str,
    subtitle: Option<&str>,
    disclaimer: Option<&str>,
    warning: Option<&str>,
    metadata: Option<&str>,
    set_id: &str,
    set_index: i32,
) {
    let (_c_cred_id, p_cred_id) = to_c_str(Some(cred_id));
    let (p_icon, len_icon) = to_bytes_ptr_len(icon);
    let (_c_title, p_title) = to_c_str(Some(title));
    let (_c_subtitle, p_subtitle) = to_c_str(subtitle);
    let (_c_disclaimer, p_disclaimer) = to_c_str(disclaimer);
    let (_c_warning, p_warning) = to_c_str(warning);
    let (_c_metadata, p_metadata) = to_c_str(metadata);
    let (_c_set_id, p_set_id) = to_c_str(Some(set_id));

    unsafe {
        credman_v2::AddEntryToSet(
            p_cred_id,
            p_icon,
            len_icon,
            p_title,
            p_subtitle,
            p_disclaimer,
            p_warning,
            p_metadata,
            p_set_id,
            set_index,
        );
    }
}

pub fn add_field_to_entry_set_opt(
    cred_id: &str,
    field_display_name: &str,
    field_display_value: Option<&str>,
    set_id: &str,
    set_index: i32,
) {
    let (_c_cred_id, p_cred_id) = to_c_str(Some(cred_id));
    let (_c_name, p_name) = to_c_str(Some(field_display_name));
    let (_c_val, p_val) = to_c_str(field_display_value);
    let (_c_set_id, p_set_id) = to_c_str(Some(set_id));

    unsafe {
        credman_v2::AddFieldToEntrySet(p_cred_id, p_name, p_val, p_set_id, set_index);
    }
}

pub fn add_payment_entry_to_set(
    cred_id: &str,
    merchant_name: &str,
    payment_method_name: Option<&str>,
    payment_method_subtitle: Option<&str>,
    payment_method_icon: Option<&[u8]>,
    transaction_amount: &str,
    bank_icon: Option<&[u8]>,
    payment_provider_icon: Option<&[u8]>,
    metadata: Option<&str>,
    set_id: &str,
    set_index: i32,
) {
    let (_c_cred_id, p_cred_id) = to_c_str(Some(cred_id));
    let (_c_merchant, p_merchant) = to_c_str(Some(merchant_name));
    let (_c_pm_name, p_pm_name) = to_c_str(payment_method_name);
    let (_c_pm_sub, p_pm_sub) = to_c_str(payment_method_subtitle);
    let (p_pm_icon, len_pm_icon) = to_bytes_ptr_len(payment_method_icon);
    let (_c_amount, p_amount) = to_c_str(Some(transaction_amount));
    let (p_bank_icon, len_bank_icon) = to_bytes_ptr_len(bank_icon);
    let (p_pp_icon, len_pp_icon) = to_bytes_ptr_len(payment_provider_icon);
    let (_c_metadata, p_metadata) = to_c_str(metadata);
    let (_c_set_id, p_set_id) = to_c_str(Some(set_id));

    unsafe {
        credman_v2::AddPaymentEntryToSet(
            p_cred_id,
            p_merchant,
            p_pm_name,
            p_pm_sub,
            p_pm_icon,
            len_pm_icon,
            p_amount,
            p_bank_icon,
            len_bank_icon,
            p_pp_icon,
            len_pp_icon,
            p_metadata,
            p_set_id,
            set_index,
        );
    }
}

pub fn add_payment_entry_to_set_v2(
    cred_id: &str,
    merchant_name: &str,
    payment_method_name: Option<&str>,
    payment_method_subtitle: Option<&str>,
    payment_method_icon: Option<&[u8]>,
    transaction_amount: &str,
    bank_icon: Option<&[u8]>,
    payment_provider_icon: Option<&[u8]>,
    additional_info: Option<&str>,
    metadata: Option<&str>,
    set_id: &str,
    set_index: i32,
) {
    let (_c_cred_id, p_cred_id) = to_c_str(Some(cred_id));
    let (_c_merchant, p_merchant) = to_c_str(Some(merchant_name));
    let (_c_pm_name, p_pm_name) = to_c_str(payment_method_name);
    let (_c_pm_sub, p_pm_sub) = to_c_str(payment_method_subtitle);
    let (p_pm_icon, len_pm_icon) = to_bytes_ptr_len(payment_method_icon);
    let (_c_amount, p_amount) = to_c_str(Some(transaction_amount));
    let (p_bank_icon, len_bank_icon) = to_bytes_ptr_len(bank_icon);
    let (p_pp_icon, len_pp_icon) = to_bytes_ptr_len(payment_provider_icon);
    let (_c_additional_info, p_additional_info) = to_c_str(additional_info);
    let (_c_metadata, p_metadata) = to_c_str(metadata);
    let (_c_set_id, p_set_id) = to_c_str(Some(set_id));

    unsafe {
        credman_v2::AddPaymentEntryToSetV2(
            p_cred_id,
            p_merchant,
            p_pm_name,
            p_pm_sub,
            p_pm_icon,
            len_pm_icon,
            p_amount,
            p_bank_icon,
            len_bank_icon,
            p_pp_icon,
            len_pp_icon,
            p_additional_info,
            p_metadata,
            p_set_id,
            set_index,
        );
    }
}

pub fn self_declare_package_info(package_display_name: &str, package_icon: Option<&[u8]>) {
    let (_c_name, p_name) = to_c_str(Some(package_display_name));
    let (p_icon, len_icon) = to_bytes_ptr_len(package_icon);
    unsafe {
        credman_v4::SelfDeclarePackageInfo(p_name, p_icon, len_icon);
    }
}

pub fn get_request_size() -> u32 {
    let mut size: u32 = 0;
    unsafe {
        credman::GetRequestSize(&mut size);
    }
    size
}

pub fn get_request_buffer(buffer: &mut [u8]) {
    unsafe {
        credman::GetRequestBuffer(buffer.as_mut_ptr() as *mut _);
    }
}

pub fn get_credentials_size() -> u32 {
    let mut size: u32 = 0;
    unsafe {
        credman::GetCredentialsSize(&mut size);
    }
    size
}

pub fn read_credentials_buffer(buffer: &mut [u8], offset: usize) -> usize {
    unsafe { credman::ReadCredentialsBuffer(buffer.as_mut_ptr() as *mut _, offset, buffer.len()) }
}

pub fn get_wasm_version() -> u32 {
    let mut version: u32 = 0;
    unsafe {
        credman::GetWasmVersion(&mut version);
    }
    version
}

pub fn get_calling_app_info() -> android_credman_sys::CallingAppInfo {
    let mut info = android_credman_sys::CallingAppInfo {
        package_name: [0; 256],
        origin: [0; 512],
    };
    unsafe {
        credman::GetCallingAppInfo(&mut info);
    }
    info
}
