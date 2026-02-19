extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{FnArg, ItemFn, parse_macro_input, spanned::Spanned};

#[proc_macro_attribute]
pub fn dcapi_matcher(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let mut inputs = input_fn.sig.inputs.iter();
    let arg = match inputs.next() {
        Some(FnArg::Typed(arg)) => arg,
        _ => {
            return syn::Error::new(
                input_fn.sig.span(),
                "dcapi_matcher entrypoint must take exactly one store parameter",
            )
            .to_compile_error()
            .into();
        }
    };
    if inputs.next().is_some() {
        return syn::Error::new(
            input_fn.sig.span(),
            "dcapi_matcher entrypoint must take exactly one store parameter",
        )
        .to_compile_error()
        .into();
    }
    let arg_ty = &arg.ty;

    let expanded = quote! {
        #input_fn

        pub fn main() {
            ::dcapi_matcher::diagnostics::begin();
            let mut reader = ::android_credman::CredentialReader::new();
            let store = match <#arg_ty as ::dcapi_dcql::CredentialStore>::from_reader(&mut reader) {
                Ok(store) => store,
                Err(err) => {
                    ::dcapi_matcher::diagnostics::error(
                        ::std::format!("credential package read failed: {}", err),
                    );
                    ::dcapi_matcher::diagnostics::flush_and_apply();
                    return;
                }
            };
            #fn_name(store);
            ::dcapi_matcher::diagnostics::flush_and_apply();
        }
    };

    TokenStream::from(expanded)
}
