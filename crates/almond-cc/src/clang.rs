// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2020 AFLplusplus Project.
// Copyright (c) 2025 Almond Contributors.

use core::{env, str::FromStr};
use std::{
    env::current_exe,
    path::{Path, PathBuf},
};

use libafl_cc::{CompilerWrapper, Error, LIB_EXT, LIB_PREFIX, ToolWrapper};

fn dll_extension<'a>() -> &'a str {
    if cfg!(target_os = "windows") {
        "dll"
    } else if cfg!(target_vendor = "apple") {
        "dylib"
    } else {
        "so"
    }
}

include!(concat!(env!("OUT_DIR"), "/clang_constants.rs"));

/// An LLVM pass for the wrapper to load, identified by the basename of its
/// compiled plugin — looked up next to the wrapper or in `../lib/`, with the
/// platform's dynamic library extension appended.
///
/// [`transform`](LLVMPass::transform) and [`syscall`](LLVMPass::syscall) name
/// the passes shipped with Almond; [`new`](LLVMPass::new) takes any other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LLVMPass {
    name: String,
}

impl LLVMPass {
    /// A pass identified by its plugin basename (e.g. `"my-pass"` resolves to
    /// `my-pass.so` / `.dylib` / `.dll`).
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Almond's built-in `transform-pass`.
    #[must_use]
    pub fn transform() -> Self {
        Self::new("transform-pass")
    }

    /// Almond's built-in `syscall-pass`.
    #[must_use]
    pub fn syscall() -> Self {
        Self::new("syscall-pass")
    }

    /// The basename of the pass plugin to load.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Gets the path of the LLVM pass
    #[must_use]
    pub fn path(&self) -> PathBuf {
        find_pass(&self.name).unwrap_or_else(|| panic!("Could not find {}", self.name))
    }
}

fn find_pass(pass_name: &str) -> Option<PathBuf> {
    let exe_path = current_exe().ok()?;

    // Under the assumption that the pass is next to the executable
    let pass_path = exe_path
        .parent()
        .unwrap()
        .join(format!("{pass_name}.{}", dll_extension()));
    if pass_path.exists() {
        return Some(pass_path);
    }

    // Under the assumption that the pass is in ../lib/
    let pass_path = exe_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("lib")
        .join(format!("{pass_name}.{}", dll_extension()));
    if pass_path.exists() {
        return Some(pass_path);
    }

    None
}

/// Wrap Clang
#[expect(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct ClangWrapper {
    is_silent: bool,
    optimize: bool,
    wrapped_cc: String,
    wrapped_cxx: String,

    name: String,
    is_cpp: bool,
    is_asm: bool,
    linking: bool,
    shared: bool,
    x_set: bool,
    bit_mode: u32,
    need_libafl_arg: bool,
    has_libafl_arg: bool,

    output: Option<PathBuf>,
    configurations: Vec<libafl_cc::Configuration>,
    ignoring_configurations: bool,
    parse_args_called: bool,
    base_args: Vec<String>,
    cc_args: Vec<String>,
    link_args: Vec<String>,
    passes: Vec<LLVMPass>,
    passes_args: Vec<String>,
    passes_linking_args: Vec<String>,
}

#[expect(clippy::match_same_arms)] // for the linking = false wip for "shared"
impl ToolWrapper for ClangWrapper {
    #[expect(clippy::too_many_lines)]
    fn parse_args<S>(&mut self, args: &[S]) -> Result<&'_ mut Self, Error>
    where
        S: AsRef<str>,
    {
        let mut new_args: Vec<String> = vec![];
        if args.is_empty() {
            return Err(Error::InvalidArguments(
                "The number of arguments cannot be 0".to_string(),
            ));
        }

        if self.parse_args_called {
            return Err(Error::Unknown(
                "ToolWrapper::parse_args cannot be called twice on the same instance".to_string(),
            ));
        }
        self.parse_args_called = true;

        if args.len() == 1 {
            return Err(Error::InvalidArguments(
                "LibAFL Tool wrapper - no commands specified. Use me as compiler.".to_string(),
            ));
        }

        self.name = args[0].as_ref().to_string();
        // Detect C++ compiler looking at the wrapper name
        self.is_cpp = if cfg!(windows) {
            self.is_cpp || self.name.ends_with("++.exe")
        } else {
            self.is_cpp || self.name.ends_with("++")
        };

        // Sancov flag
        // new_args.push("-fsanitize-coverage=trace-pc-guard".into());

        let mut linking = true;
        let mut shared = false;
        // Detect stray -v calls from ./configure scripts.
        if args.len() > 1 && args[1].as_ref() == "-v" {
            if args.len() == 2 {
                self.base_args.push(args[1].as_ref().into());
                return Ok(self);
            }
            linking = false;
        }

        let mut suppress_linking = 0;
        let mut i = 1;
        while i < args.len() {
            let arg_as_path = Path::new(args[i].as_ref());

            if arg_as_path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("s"))
            {
                self.is_asm = true;
            }

            match args[i].as_ref() {
                "--libafl-no-link" => {
                    suppress_linking += 1;
                    self.has_libafl_arg = true;
                    i += 1;
                    continue;
                }
                "--libafl" => {
                    suppress_linking += 1337;
                    self.has_libafl_arg = true;
                    i += 1;
                    continue;
                }
                "-fsanitize=fuzzer-no-link" => {
                    suppress_linking += 1;
                    self.has_libafl_arg = true;
                    i += 1;
                    continue;
                }
                "-fsanitize=fuzzer" => {
                    suppress_linking += 1337;
                    self.has_libafl_arg = true;
                    i += 1;
                    continue;
                }
                "-Wl,-z,defs" | "-Wl,--no-undefined" | "--no-undefined" => {
                    i += 1;
                    continue;
                }
                "-z" | "-Wl,-z" => {
                    if i + 1 < args.len()
                        && (args[i + 1].as_ref() == "defs" || args[i + 1].as_ref() == "-Wl,defs")
                    {
                        i += 2;
                        continue;
                    }
                }
                "--libafl-ignore-configurations" | "-print-prog-name=ld" => {
                    self.ignoring_configurations = true;
                    i += 1;
                    continue;
                }
                "--libafl-configurations" => {
                    if i + 1 < args.len() {
                        self.configurations.extend(
                            args[i + 1]
                                .as_ref()
                                .split(',')
                                .map(|x| libafl_cc::Configuration::from_str(x).unwrap()),
                        );
                        i += 2;
                        continue;
                    }
                }
                "-o" => {
                    if i + 1 < args.len() {
                        self.output = Some(PathBuf::from(args[i + 1].as_ref()));
                        i += 2;
                        continue;
                    }
                }
                "-x" => self.x_set = true,
                "-m32" => self.bit_mode = 32,
                "-m64" => self.bit_mode = 64,
                "-c" | "-S" | "-E" => linking = false,
                "-shared" => {
                    linking = false;
                    shared = true;
                } // TODO dynamic list?
                _ => (),
            }
            new_args.push(args[i].as_ref().to_string());
            i += 1;
        }
        if linking
            && (suppress_linking > 0 || (self.has_libafl_arg && suppress_linking == 0))
            && suppress_linking < 1337
        {
            linking = false;
            new_args.push(
                PathBuf::from(env!("OUT_DIR"))
                    .join(format!("{LIB_PREFIX}no-link-rt.{LIB_EXT}"))
                    .into_os_string()
                    .into_string()
                    .unwrap(),
            );
        }

        self.linking = linking;
        self.shared = shared;

        new_args.push("-g".into());
        if self.optimize {
            new_args.push("-O3".into());
            new_args.push("-funroll-loops".into());
        }

        // Fuzzing define common among tools
        new_args.push("-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1".into());

        // Libraries needed by libafl on Windows
        #[cfg(windows)]
        if linking {
            new_args.push("-lws2_32".into());
            new_args.push("-lBcrypt".into());
            new_args.push("-lAdvapi32".into());
        }
        // required by timer API (timer_create, timer_settime)
        #[cfg(target_os = "linux")]
        if linking {
            new_args.push("-lrt".into());
        }
        // `MacOS` has odd linker behavior sometimes
        #[cfg(target_vendor = "apple")]
        if linking || shared {
            new_args.push("-undefined".into());
            new_args.push("dynamic_lookup".into());
        }

        self.base_args.extend(new_args);
        Ok(self)
    }

    fn add_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        self.base_args.push(arg.as_ref().to_string());
        self
    }

    fn add_configuration(&mut self, configuration: libafl_cc::Configuration) -> &'_ mut Self {
        self.configurations.push(configuration);
        self
    }

    fn configurations(&self) -> Result<Vec<libafl_cc::Configuration>, Error> {
        let mut configs = self.configurations.clone();
        configs.reverse();
        Ok(configs)
    }

    fn ignore_configurations(&self) -> Result<bool, Error> {
        Ok(self.ignoring_configurations)
    }

    fn command(&mut self) -> Result<Vec<String>, Error> {
        self.command_for_configuration(libafl_cc::Configuration::Default)
    }

    #[expect(clippy::too_many_lines)]
    fn command_for_configuration(
        &mut self,
        configuration: libafl_cc::Configuration,
    ) -> Result<Vec<String>, Error> {
        let mut args = vec![];
        let mut use_pass = false;

        if self.is_cpp {
            args.push(self.wrapped_cxx.clone());
        } else {
            args.push(self.wrapped_cc.clone());
        }

        if !self.is_silent() {
            match LIBAFL_CC_LLVM_VERSION {
                Some(version) => {
                    dbg!("Using LLVM version: {}", version);
                }
                None => {
                    dbg!("Using unknown LLVM version");
                }
            }
        }

        let base_args = self
            .base_args
            .iter()
            .map(|r| {
                let arg_as_path = PathBuf::from(r);
                if r.ends_with('.') {
                    r.to_string()
                } else {
                    if let Some(extension) = arg_as_path.extension() {
                        let extension = extension.to_str().unwrap();
                        let extension_lowercase = extension.to_lowercase();
                        match &extension_lowercase[..] {
                            "a" | "la" | "pch" => configuration.replace_extension(&arg_as_path),
                            _ => arg_as_path,
                        }
                    } else {
                        arg_as_path
                    }
                    .into_os_string()
                    .into_string()
                    .unwrap()
                }
            })
            .collect::<Vec<_>>();

        if let libafl_cc::Configuration::Default = configuration {
            if let Some(output) = self.output.clone() {
                let output = configuration.replace_extension(&output);
                let new_filename = output.into_os_string().into_string().unwrap();
                args.push("-o".to_string());
                args.push(new_filename);
            }
        } else if let Some(output) = self.output.clone() {
            let output = configuration.replace_extension(&output);
            let new_filename = output.into_os_string().into_string().unwrap();
            args.push("-o".to_string());
            args.push(new_filename);
        } else {
            // No output specified, we need to rewrite the single .c file's name into a -o
            // argument.
            for arg in &base_args {
                let arg_as_path = PathBuf::from(arg);
                if !arg.ends_with('.')
                    && !arg.starts_with('-')
                    && let Some(extension) = arg_as_path.extension()
                {
                    let extension = extension.to_str().unwrap();
                    let extension_lowercase = extension.to_lowercase();
                    match &extension_lowercase[..] {
                        "c" | "cc" | "cxx" | "cpp" => {
                            args.push("-o".to_string());
                            args.push(if self.linking {
                                configuration
                                    .replace_extension(&PathBuf::from("a.out"))
                                    .into_os_string()
                                    .into_string()
                                    .unwrap()
                            } else {
                                let mut result = configuration.replace_extension(&arg_as_path);
                                result.set_extension("o");
                                result.into_os_string().into_string().unwrap()
                            });
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        args.extend_from_slice(base_args.as_slice());

        args.extend_from_slice(&configuration.to_flags()?);

        if self.need_libafl_arg && !self.has_libafl_arg {
            return Ok(args);
        }

        for pass in &self.passes {
            use_pass = true;
            // https://github.com/llvm/llvm-project/issues/56137
            // Need this -Xclang -load -Xclang -<pass>.so thing even with the new PM
            // to pass the arguments to LLVM Passes
            args.push("-Xclang".into());
            args.push("-load".into());
            args.push("-Xclang".into());
            args.push(pass.path().into_os_string().into_string().unwrap());
            args.push("-Xclang".into());
            args.push(format!(
                "-fpass-plugin={}",
                pass.path().into_os_string().into_string().unwrap()
            ));
        }
        if !self.is_asm && !self.passes.is_empty() {
            for passes_arg in &self.passes_args {
                args.push("-mllvm".into());
                args.push(passes_arg.into());
            }
        }
        if self.linking {
            if self.x_set {
                args.push("-x".into());
                args.push("none".into());
            }

            args.extend_from_slice(self.link_args.as_slice());

            if use_pass {
                args.extend_from_slice(self.passes_linking_args.as_slice());
            }

            if cfg!(unix) {
                args.push("-pthread".into());
                args.push("-ldl".into());
                args.push("-lm".into());
            }
        } else {
            args.extend_from_slice(self.cc_args.as_slice());
        }

        Ok(args)
    }

    fn is_linking(&self) -> bool {
        self.linking
    }

    fn filter(&self, args: &mut Vec<String>) {
        let blocklist = [
            "-Werror=unused-command-line-argument",
            "-Wunused-command-line-argument",
            "-fconserve-stack", // GCC-specific flag, not supported by clang
        ];
        for item in blocklist {
            args.retain(|x| x.clone() != item);
        }
    }

    fn silence(&mut self, value: bool) -> &'_ mut Self {
        self.is_silent = value;
        self
    }

    fn is_silent(&self) -> bool {
        self.is_silent
    }
}

impl CompilerWrapper for ClangWrapper {
    fn add_cc_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        self.cc_args.push(arg.as_ref().to_string());
        self
    }

    fn add_link_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        self.link_args.push(arg.as_ref().to_string());
        self
    }

    fn link_staticlib<S>(&mut self, dir: &Path, name: S) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        let lib_file = dir
            .join(format!("{LIB_PREFIX}{}.{LIB_EXT}", name.as_ref()))
            .into_os_string()
            .into_string()
            .unwrap();

        if cfg!(unix) {
            if cfg!(target_vendor = "apple") {
                // Same as --whole-archive on linux
                // Without this option, the linker picks the first symbols it finds and does not care if it's a weak or a strong symbol
                // See: <https://stackoverflow.com/questions/13089166/how-to-make-gcc-link-strong-symbol-in-static-library-to-overwrite-weak-symbol>
                self.add_link_arg("-Wl,-force_load").add_link_arg(lib_file)
            } else {
                self.add_link_arg("-Wl,--whole-archive")
                    .add_link_arg(lib_file)
                    .add_link_arg("-Wl,--no-whole-archive")
            }
        } else {
            self.add_link_arg(format!("-Wl,-wholearchive:{lib_file}"))
        }
    }
}
impl Default for ClangWrapper {
    /// Create a new Clang Wrapper
    fn default() -> Self {
        Self::new()
    }
}

impl ClangWrapper {
    /// Create a new Clang Wrapper
    #[must_use]
    pub fn new() -> Self {
        Self {
            optimize: true,
            wrapped_cc: CLANG_PATH.into(),
            wrapped_cxx: CLANGXX_PATH.into(),
            name: String::new(),
            is_cpp: false,
            is_asm: false,
            linking: false,
            shared: false,
            x_set: false,
            bit_mode: 0,
            need_libafl_arg: false,
            has_libafl_arg: false,
            output: None,
            configurations: vec![libafl_cc::Configuration::Default],
            ignoring_configurations: false,
            parse_args_called: false,
            base_args: vec![],
            cc_args: vec![],
            link_args: vec![],
            passes: vec![],
            passes_args: vec![],
            passes_linking_args: vec![],
            is_silent: false,
        }
    }

    /// Set cpp mode, call this before calling `parse_args`
    pub fn cpp(&mut self, value: bool) -> &'_ mut Self {
        self.is_cpp = value;
        self
    }

    /// Add LLVM pass
    pub fn add_pass(&mut self, pass: LLVMPass) -> &'_ mut Self {
        self.passes.push(pass);
        self
    }

    // Configure optimization
    pub fn optimize(&mut self, value: bool) -> &'_ mut Self {
        self.optimize = value;
        self
    }
}
