// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2020 AFLplusplus Project.
// Copyright (c) 2025 Almond Contributors.

//! Almond compiler wrapper, exposed both as a library and as the `almond-cc`
//! binary.

use std::env;

use libafl_cc::{CompilerWrapper, ToolWrapper};

pub mod clang;

pub use clang::{ClangWrapper, LLVMPass};

/// Run the Almond clang wrapper against the given command line arguments,
/// loading the caller-defined LLVM `passes`, and returning the wrapped
/// compiler's exit code (if any).
///
/// `args` is expected to be the full argument vector, including the program
/// name at index 0. `passes` lets the caller choose which passes to load — the
/// built-in [`LLVMPass::transform`] / [`LLVMPass::syscall`], any
/// [`LLVMPass::new`] pass, or none.
///
/// # Panics
///
/// Panics if no arguments are given, or if the wrapper name cannot be mapped to
/// a C or C++ compiler.
#[must_use]
pub fn run(mut args: Vec<String>, passes: impl IntoIterator<Item = LLVMPass>) -> Option<i32> {
    assert!(args.len() > 1, "Almond CC: No Arguments given");

    let mut dir = env::current_exe().unwrap();
    let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

    let is_cpp = match wrapper_name[wrapper_name.len() - 2..]
        .to_lowercase()
        .as_str()
    {
        "cc" => false,
        "++" | "pp" | "xx" => true,
        _ => panic!(
            "Could not figure out if c or c++ wrapper was called. Expected {dir:?} to end with c or cxx"
        ),
    };

    dir.pop();
    dir.pop();
    dir.push("lib");

    let mut cc = ClangWrapper::new();

    cc.filter(&mut args);

    for pass in passes {
        cc.add_pass(pass);
    }
    cc.link_staticlib(&dir, "almond");

    cc.cpp(is_cpp)
        .silence(true)
        .parse_args(&args)
        .expect("Failed to parse the command line")
        .run()
        .expect("Failed to run the wrapped compiler")
}
