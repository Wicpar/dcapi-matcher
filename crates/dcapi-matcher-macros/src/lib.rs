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

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn android_credman_matcher_match() {
            ::dcapi_matcher::tracing_backend::begin();
            ::dcapi_matcher::tracing_backend::set_level(None);
            let invocation = ::dcapi_matcher::tracing_backend::with_collector(|| {
                let result = ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                    #fn_name(
                        ::android_credman::FromRequest::from_request(),
                        ::android_credman::FromCredentials::from_credentials(),
                    );
                }));
                if let Err(payload) = &result {
                    let detail = if let Some(msg) = payload.downcast_ref::<&'static str>() {
                        (*msg).to_string()
                    } else if let Some(msg) = payload.downcast_ref::<String>() {
                        msg.clone()
                    } else {
                        "non-string panic payload".to_string()
                    };
                    ::tracing::error!(detail = %detail, "matcher panicked");
                }
                result
            });
            let _ = invocation;
            ::dcapi_matcher::tracing_backend::flush_and_apply();
        }
    };

    TokenStream::from(expanded)
}
