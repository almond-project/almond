//! build.rs for `almond`

use std::path::Path;

fn main() {
    let src_dir = Path::new("src");

    println!("cargo:rerun-if-changed=src/common.h");
    println!("cargo:rerun-if-changed=src/common.c");
    println!("cargo:rerun-if-changed=build.rs");

    // `cc` emits the `rustc-link-search` and `rustc-link-lib=static=common`
    // directives for us.
    cc::Build::new()
        .file(src_dir.join("common.c"))
        .compile("common");
}
