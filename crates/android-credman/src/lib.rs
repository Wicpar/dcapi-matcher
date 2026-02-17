#![doc = include_str!("../README.md")]

mod abi;
mod error;
mod host;
mod input;
mod structs;
mod traits;

pub use error::return_error;
pub use host::*;
pub use input::*;
pub use structs::*;
pub use traits::*;

#[cfg(not(target_arch = "wasm32"))]
pub use android_credman_sys::test_shim;
