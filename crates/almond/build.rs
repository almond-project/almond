//! build.rs for `almond`

use std::{env, path::Path};

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    #[allow(unused_variables)]
    let src_dir = Path::new("src");

    {
        println!("cargo:rerun-if-changed=src/common.h");
        println!("cargo:rerun-if-changed=src/common.c");

        let mut common = cc::Build::new();

        common.file(src_dir.join("common.c")).compile("common");
    }

    println!("cargo:rustc-link-search=native={}", &out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}
