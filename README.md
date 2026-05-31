# almond

A syscall fuzzer library built on [LibAFL](https://github.com/AFLplusplus/LibAFL).

Almond provides the building blocks — `AlmondInput`, the mutator suite,
KCov/coverage observers, the capture feedback, and the subthread executor.

## Using it

Write a staticlib crate that depends on `almond` and defines `libafl_main`:

```toml
[lib]
crate-type = ["staticlib"]

[dependencies]
almond = { path = "../almond" }   # or a git/version dependency

[profile.release]
panic = "abort"   # REQUIRED: panics must not unwind across common.c's main()
```

```rust
use almond::prelude::*;

#[unsafe(no_mangle)]
pub extern "C" fn libafl_main() {
    // ... assemble LibAFL state, scheduler, stages, executor, and run the loop ...
}
```

## License

Licensed under MIT OR Apache-2.0.
