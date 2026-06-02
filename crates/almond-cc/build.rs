// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2020 AFLplusplus Project.
// Copyright (c) 2025 Almond Contributors.

use core::str;
use std::{env, fs::File, io::Write, path::Path, process::Command};

#[cfg(target_vendor = "apple")]
use glob::glob;
#[cfg(target_vendor = "apple")]
use std::path::PathBuf;
use which::which;

/// The max version of `LLVM` we're looking for
#[cfg(not(target_vendor = "apple"))]
const LLVM_VERSION_MAX: u32 = 21;

/// The min version of `LLVM` we're looking for
#[cfg(not(target_vendor = "apple"))]
const LLVM_VERSION_MIN: u32 = 15;

/// Github Actions for `MacOS` seems to have troubles finding `llvm-config`.
/// Hence, we go look for it ourselves.
#[cfg(target_vendor = "apple")]
fn find_llvm_config_brew() -> Result<PathBuf, String> {
    match Command::new("brew").arg("--cellar").output() {
        Ok(output) => {
            let brew_cellar_location = str::from_utf8(&output.stdout).unwrap_or_default().trim();
            if brew_cellar_location.is_empty() {
                return Err("Empty return from brew --cellar".to_string());
            }
            let location_suffix = "*/bin/llvm-config";
            let cellar_glob = [
                // location for explicitly versioned brew formulae
                format!("{brew_cellar_location}/llvm@*/{location_suffix}"),
                // location for current release brew formulae
                format!("{brew_cellar_location}/llvm/{location_suffix}"),
            ];
            let glob_results = cellar_glob.iter().flat_map(|location| {
                glob(location).unwrap_or_else(|err| {
                    panic!("Could not read glob path {location} ({err})");
                })
            });
            match glob_results.last() {
                Some(path) => Ok(path.unwrap()),
                None => Err(format!(
                    "No llvm-config found in brew cellar with patterns {}",
                    cellar_glob.join(" ")
                )),
            }
        }
        Err(err) => Err(format!("Could not execute brew --cellar: {err:?}")),
    }
}

fn find_llvm_config() -> Result<String, String> {
    if let Ok(var) = env::var("LLVM_CONFIG") {
        return Ok(var);
    }

    // for Github Actions, we check if we find llvm-config in brew.
    #[cfg(target_vendor = "apple")]
    match find_llvm_config_brew() {
        Ok(llvm_dir) => return Ok(llvm_dir.to_str().unwrap().to_string()),
        Err(err) => {
            println!("cargo:warning={err}");
        }
    }

    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    for version in (LLVM_VERSION_MIN..=LLVM_VERSION_MAX).rev() {
        let llvm_config_name: String = format!("/usr/clang/{version}.0/bin/llvm-config");
        if Path::new(&llvm_config_name).exists() {
            return Ok(llvm_config_name);
        }
    }

    #[cfg(not(any(target_vendor = "apple", target_os = "solaris", target_os = "illumos")))]
    for version in (LLVM_VERSION_MIN..=LLVM_VERSION_MAX).rev() {
        let llvm_config_name: String = format!("llvm-config-{version}");
        if which(&llvm_config_name).is_ok() {
            return Ok(llvm_config_name);
        }
    }

    if which("llvm-config").is_ok() {
        return Ok("llvm-config".to_owned());
    }

    Err("could not find llvm-config".to_owned())
}

fn exec_llvm_config(args: &[&str]) -> String {
    let llvm_config = find_llvm_config().expect("Unexpected error");
    match Command::new(&llvm_config).args(args).output() {
        Ok(output) => String::from_utf8(output.stdout)
            .expect("Unexpected llvm-config output")
            .trim()
            .to_string(),
        Err(e) => panic!("Could not execute {llvm_config}: {e}"),
    }
}

fn find_llvm_version() -> Option<i32> {
    let llvm_env_version = env::var("LLVM_VERSION");
    let output = if let Ok(version) = llvm_env_version {
        version
    } else {
        exec_llvm_config(&["--version"])
    };
    if let Some(major) = output.split('.').collect::<Vec<&str>>().first()
        && let Ok(res) = major.parse::<i32>()
    {
        return Some(res);
    }
    None
}

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);

    let dest_path = Path::new(&out_dir).join("clang_constants.rs");
    let mut clang_constants_file = File::create(dest_path).expect("Could not create file");

    println!("cargo:rerun-if-env-changed=LLVM_CONFIG");
    println!("cargo:rerun-if-env-changed=LLVM_BINDIR");
    println!("cargo:rerun-if-env-changed=LLVM_VERSION");
    println!("cargo:rerun-if-changed=build.rs");

    let llvm_bindir = env::var("LLVM_BINDIR");
    let llvm_version = env::var("LLVM_VERSION");

    // test if llvm-config is available so we can locate clang
    if find_llvm_config().is_err() && !(llvm_bindir.is_ok() && llvm_version.is_ok()) {
        println!(
            "cargo:warning=Failed to find llvm-config, falling back to `clang`/`clang++` on PATH. If you need a specific toolchain, set the LLVM_CONFIG environment variable to a recent llvm-config, else just ignore this message."
        );

        write!(
            clang_constants_file,
            "// These constants are autogenerated by build.rs
/// The path to the `clang` executable
pub const CLANG_PATH: &str = \"clang\";
/// The path to the `clang++` executable
pub const CLANGXX_PATH: &str = \"clang++\";

/// The llvm version of the located toolchain
pub const LIBAFL_CC_LLVM_VERSION: Option<usize> = None;
    "
        )
        .expect("Could not write file");

        return;
    }

    let llvm_bindir = if let Ok(bindir) = llvm_bindir {
        bindir
    } else {
        exec_llvm_config(&["--bindir"])
    };
    let bindir_path = Path::new(&llvm_bindir);

    let clang;
    let clangcpp;

    if cfg!(windows) {
        clang = bindir_path.join("clang.exe");
        clangcpp = bindir_path.join("clang++.exe");
    } else {
        clang = bindir_path.join("clang");
        clangcpp = bindir_path.join("clang++");
    }

    let mut found = true;

    if !clang.exists() {
        println!("cargo:warning=Failed to find binary: clang.");
        found = false;
    }

    if !clangcpp.exists() {
        println!("cargo:warning=Failed to find binary: clang++.");
        found = false;
    }

    assert!(
        found,
        "\n\tAt least one of the LLVM dependencies could not be found.\n\tThe following search directory was considered: {}\n",
        bindir_path.display()
    );

    let llvm_version = find_llvm_version();

    // We want the paths quoted, and debug formatting does that - allow debug formatting.
    #[allow(unknown_lints)] // not on stable yet
    #[allow(clippy::unnecessary_debug_formatting)]
    write!(
        clang_constants_file,
        "// These constants are autogenerated by build.rs

/// The path to the `clang` executable
pub const CLANG_PATH: &str = {clang:?};
/// The path to the `clang++` executable
pub const CLANGXX_PATH: &str = {clangcpp:?};

/// The llvm version of the located toolchain
pub const LIBAFL_CC_LLVM_VERSION: Option<usize> = {llvm_version:?};
        ",
    )
    .expect("Could not write file");
}
