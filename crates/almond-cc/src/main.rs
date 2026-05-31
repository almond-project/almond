// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2020 AFLplusplus Project.
// Copyright (c) 2025 Almond Contributors.

use std::env;

use libafl_cc::{CompilerWrapper, ToolWrapper};
mod clang;
use clang::ClangWrapper;

pub fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() > 1 {
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

        cc.add_pass(clang::LLVMPasses::Transform);
        cc.add_pass(clang::LLVMPasses::Syscall);
        cc.link_staticlib(&dir, "almond");

        if let Some(code) = cc
            .cpp(is_cpp)
            .silence(true)
            .parse_args(&args)
            .expect("Failed to parse the command line")
            .run()
            .expect("Failed to run the wrapped compiler")
        {
            std::process::exit(code);
        }
    } else {
        panic!("Almond CC: No Arguments given");
    }
}
