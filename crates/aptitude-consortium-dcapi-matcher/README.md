# aptitude-consortium-dcapi-matcher

## Build (wasm32-wasip1)

From the repo root:

```sh
cargo build -p aptitude-consortium-dcapi-matcher --target wasm32-wasip1 --release && \
  wasm-opt --enable-bulk-memory -Oz \
    -o target/wasm32-wasip1/release/aptitude-consortium-dcapi-matcher.opt.wasm \
    target/wasm32-wasip1/release/aptitude-consortium-dcapi-matcher.wasm
```
