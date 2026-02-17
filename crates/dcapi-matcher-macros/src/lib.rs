extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

#[proc_macro_attribute]
pub fn dcapi_matcher(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;

    let expanded = quote! {
        #input_fn

        pub fn main() {
            ::dcapi_matcher::diagnostics::begin();
            #fn_name(
                ::android_credman::FromRequest::from_request(),
                ::android_credman::FromCredentials::from_credentials(),
            );
            ::dcapi_matcher::diagnostics::flush_and_apply();
        }
    };

    TokenStream::from(expanded)
}
