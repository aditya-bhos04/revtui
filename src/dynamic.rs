use std::process::Command;
use std::path::Path;

#[derive(Debug, Clone)]
pub enum DynKind {
    Strace, Ltrace, Ldd, File, Readelf, Objdump, Checksec, Strings, Custom,
}

#[derive(Debug, Clone)]
pub struct DynamicResult {
    pub tool:    String,
    pub command: String,
    pub output:  Vec<String>,
    pub success: bool,
    pub kind:    DynKind,
}

pub struct DynamicAnalyzer {
    pub binary: String,
}

// ── Checksec variant auto-detection ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum ChecksecFlavour {
    /// checksec --file=<binary>   (shell script version, most common on Debian/Ubuntu)
    ShellScriptEq,
    /// checksec --file <binary>   (Python pwntools / some newer versions)
    PythonSpace,
    /// Not installed
    NotFound,
}

fn detect_checksec() -> ChecksecFlavour {
    if !tool_exists("checksec") { return ChecksecFlavour::NotFound; }

    // Run checksec --version and inspect output to guess flavour
    let ver = Command::new("checksec").arg("--version").output();
    let ver_str = ver.map(|o| {
        let s = String::from_utf8_lossy(&o.stdout).to_string()
            + &String::from_utf8_lossy(&o.stderr);
        s.to_lowercase()
    }).unwrap_or_default();

    // Python/pwntools checksec prints "checksec version X" or mentions python
    if ver_str.contains("python") || ver_str.contains("pwntools") {
        return ChecksecFlavour::PythonSpace;
    }

    // Try to detect shell-script version by checking --help output for "file="
    let help = Command::new("checksec").arg("--help").output();
    let help_str = help.map(|o| {
        String::from_utf8_lossy(&o.stdout).to_string()
            + &String::from_utf8_lossy(&o.stderr)
    }).unwrap_or_default();

    if help_str.contains("--file=") {
        return ChecksecFlavour::ShellScriptEq;
    }
    if help_str.contains("--file ") || help_str.contains("--file\n") {
        return ChecksecFlavour::PythonSpace;
    }

    // Default: try ShellScriptEq first (most common on Linux distros)
    ChecksecFlavour::ShellScriptEq
}

fn tool_exists(program: &str) -> bool {
    Command::new("which").arg(program).output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

impl DynamicAnalyzer {
    pub fn new(binary: &str) -> Self {
        Self { binary: binary.to_string() }
    }

    pub fn run_all(&self) -> Vec<DynamicResult> {
        vec![
            self.run_file(),
            self.run_ldd(),
            self.run_checksec(),
            self.run_readelf_headers(),
            self.run_readelf_dynamic(),
            self.run_readelf_segments(),
            self.run_strace(),
            self.run_ltrace(),
            self.run_objdump_plt(),
            self.run_strings_cmd(),
        ]
    }

    pub fn run_file(&self) -> DynamicResult {
        run_tool_with_args("file", "file", &[&self.binary], DynKind::File)
    }

    pub fn run_ldd(&self) -> DynamicResult {
        run_tool_with_args("ldd", "ldd", &[&self.binary], DynKind::Ldd)
    }

    pub fn run_strace(&self) -> DynamicResult {
        run_tool_with_args(
            "strace -c  (syscall summary)",
            "strace",
            &["-c", "-e", "trace=all", "--", &self.binary],
            DynKind::Strace,
        )
    }

    pub fn run_ltrace(&self) -> DynamicResult {
        run_tool_with_args(
            "ltrace -c  (library call summary)",
            "ltrace",
            &["-c", "--", &self.binary],
            DynKind::Ltrace,
        )
    }

    pub fn run_readelf_headers(&self) -> DynamicResult {
        run_tool_with_args("readelf -h  (ELF header)", "readelf", &["-h", &self.binary], DynKind::Readelf)
    }

    pub fn run_readelf_dynamic(&self) -> DynamicResult {
        run_tool_with_args("readelf -d  (dynamic section)", "readelf", &["-d", &self.binary], DynKind::Readelf)
    }

    pub fn run_readelf_segments(&self) -> DynamicResult {
        run_tool_with_args("readelf -l  (program headers)", "readelf", &["-l", &self.binary], DynKind::Readelf)
    }

    /// Smart checksec runner: auto-detects installed flavour, always falls back
    /// to built-in readelf-based check so the user always gets useful output.
    pub fn run_checksec(&self) -> DynamicResult {
        let flavour = detect_checksec();

        match flavour {
            ChecksecFlavour::NotFound => {
                // No checksec installed — run our own built-in check
                self.run_builtin_checksec()
            }

            ChecksecFlavour::ShellScriptEq => {
                // e.g. checksec --file=/path/to/binary
                let file_arg = format!("--file={}", self.binary);
                let mut result = run_tool_with_args(
                    "checksec (shell script)",
                    "checksec",
                    &[&file_arg],
                    DynKind::Checksec,
                );
                // If it failed, try fallback
                if !result.success || result.output.iter().any(|l| l.contains("Unknown option")) {
                    let fallback = self.run_builtin_checksec();
                    result.output.push(String::new());
                    result.output.push("[*] checksec failed — showing built-in analysis:".into());
                    result.output.extend(fallback.output);
                }
                result
            }

            ChecksecFlavour::PythonSpace => {
                // e.g. checksec --file /path/to/binary
                let mut result = run_tool_with_args(
                    "checksec (python)",
                    "checksec",
                    &["--file", &self.binary],
                    DynKind::Checksec,
                );
                if !result.success || result.output.iter().any(|l| l.contains("Unknown option") || l.contains("Error")) {
                    // Try the = variant as last resort
                    let file_arg = format!("--file={}", self.binary);
                    result = run_tool_with_args(
                        "checksec (shell script fallback)",
                        "checksec",
                        &[&file_arg],
                        DynKind::Checksec,
                    );
                }
                if !result.success {
                    let fallback = self.run_builtin_checksec();
                    result.output.push(String::new());
                    result.output.push("[*] checksec failed — showing built-in analysis:".into());
                    result.output.extend(fallback.output);
                }
                result
            }
        }
    }

    /// Built-in security check using readelf + goblin-compatible parsing.
    /// Always available — no external tools needed.
    pub fn run_builtin_checksec(&self) -> DynamicResult {
        let binary = &self.binary;
        let label = "checksec (built-in via readelf)";
        let cmd   = format!("readelf -l -d -s {binary}");

        if !Path::new(binary).exists() {
            return DynamicResult {
                tool: label.into(), command: cmd,
                output: vec![format!("[!] File not found: {binary}")],
                success: false, kind: DynKind::Checksec,
            };
        }

        // Gather data from readelf
        let phdr = run_silent("readelf", &["-l", binary]);
        let dyn_sec = run_silent("readelf", &["-d", binary]);
        let syms  = run_silent("readelf", &["-s", binary]);

        let phdr_text = phdr.join("\n").to_lowercase();
        let dyn_text  = dyn_sec.join("\n").to_lowercase();
        let sym_text  = syms.join("\n").to_lowercase();

        // ── Detection logic ───────────────────────────────────────────────

        // PIE: ET_DYN in ELF type
        let elf_header = run_silent("readelf", &["-h", binary]).join("\n");
        let is_pie = elf_header.contains("DYN (");

        // NX: GNU_STACK segment must NOT have 'E' flag
        let nx = if let Some(stack_line) = phdr_text.lines()
            .find(|l| l.contains("gnu_stack")) {
            !stack_line.contains(" e ")        // no execute flag
        } else { false };

        // Stack canary: __stack_chk_fail in dynamic symbols
        let canary = sym_text.contains("__stack_chk_fail")
            || sym_text.contains("stack_chk");

        // RELRO: PT_GNU_RELRO segment present
        let relro_partial = phdr_text.contains("gnu_relro");
        // Full RELRO: BIND_NOW in dynamic section
        let relro_full = dyn_text.contains("bind_now")
            || dyn_text.contains("(flags)") && dyn_text.contains("bind_now");
        let relro = if relro_full { "Full RELRO" }
            else if relro_partial { "Partial RELRO" }
            else { "No RELRO" };

        // RPATH / RUNPATH
        let rpath = dyn_text.contains("(rpath)") || dyn_text.contains("(runpath)");

        // Fortify: check for __printf_chk, __strcpy_chk etc.
        let fortify = sym_text.contains("_chk@") || sym_text.contains("_chk ");

        // ASLR: kernel feature, not binary — mention it
        // Stripped
        let stripped = !sym_text.contains(" func ") && !sym_text.contains(" object ");

        // ── Format output ─────────────────────────────────────────────────
        let bin_name = Path::new(binary).file_name()
            .and_then(|n| n.to_str()).unwrap_or(binary);

        let mut out: Vec<String> = vec![
            format!("  Binary: {bin_name}"),
            String::new(),
            format!("  {:.<30} {}", "RELRO",         relro_flag(relro_partial, relro_full)),
            format!("  {:.<30} {}", "Stack Canary",  flag(canary)),
            format!("  {:.<30} {}", "NX (No-Execute)",flag(nx)),
            format!("  {:.<30} {}", "PIE",           flag(is_pie)),
            format!("  {:.<30} {}", "RPATH",         if rpath  { "⚠  RPATH set (bad)" } else { "✓  None" }),
            format!("  {:.<30} {}", "RUNPATH",       if rpath  { "⚠  RUNPATH set"     } else { "✓  None" }),
            format!("  {:.<30} {}", "Fortify",       flag(fortify)),
            format!("  {:.<30} {}", "Fortify Source",flag(fortify)),
            format!("  {:.<30} {}", "Stripped",      flag(stripped)),
            String::new(),
        ];

        // Risk summary
        let mut risks: Vec<&str> = vec![];
        if !nx       { risks.push("NX disabled — stack/heap executable"); }
        if !canary   { risks.push("No stack canary — vulnerable to stack overflow"); }
        if !is_pie   { risks.push("No PIE — fixed load address, easier to exploit"); }
        if relro == "No RELRO" { risks.push("No RELRO — GOT overwrite possible"); }

        if risks.is_empty() {
            out.push("  ✓  All major mitigations enabled — well-hardened binary".into());
        } else {
            out.push("  ⚠  Security concerns:".into());
            for r in risks { out.push(format!("     • {r}")); }
        }

        DynamicResult {
            tool: label.into(), command: cmd,
            output: out, success: true, kind: DynKind::Checksec,
        }
    }

    pub fn run_objdump_plt(&self) -> DynamicResult {
        run_tool_with_args(
            "objdump -d .plt  (PLT stubs)",
            "objdump",
            &["-d", "-j", ".plt", &self.binary],
            DynKind::Objdump,
        )
    }

    pub fn run_strings_cmd(&self) -> DynamicResult {
        run_tool_with_args(
            "strings -n 6  (printable strings)",
            "strings",
            &["-n", "6", &self.binary],
            DynKind::Strings,
        )
    }

    pub fn run_custom(&self, cmd: &str) -> DynamicResult {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return DynamicResult {
                tool: "custom".into(), command: cmd.into(),
                output: vec!["Empty command.".into()], success: false, kind: DynKind::Custom,
            };
        }
        let expanded: Vec<String> = parts.iter()
            .map(|p| if *p == "%f" { self.binary.clone() } else { p.to_string() })
            .collect();
        let refs: Vec<&str> = expanded.iter().map(|s| s.as_str()).collect();
        run_tool_with_args(cmd, refs[0], &refs[1..], DynKind::Custom)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn run_silent(program: &str, args: &[&str]) -> Vec<String> {
    Command::new(program).args(args).output()
        .map(|o| {
            let mut lines: Vec<String> = String::from_utf8_lossy(&o.stdout)
                .lines().map(|l| l.to_string()).collect();
            lines.extend(String::from_utf8_lossy(&o.stderr).lines().map(|l| l.to_string()));
            lines
        })
        .unwrap_or_default()
}

fn flag(enabled: bool) -> &'static str {
    if enabled { "✓  Enabled" } else { "✗  Disabled" }
}

fn relro_flag(partial: bool, full: bool) -> &'static str {
    if full        { "✓  Full RELRO" }
    else if partial{ "~  Partial RELRO" }
    else           { "✗  No RELRO" }
}

fn run_tool_with_args(label: &str, program: &str, args: &[&str], kind: DynKind) -> DynamicResult {
    let command_str = format!("{program} {}", args.join(" "));

    if !tool_exists(program) {
        return DynamicResult {
            tool: label.into(), command: command_str,
            output: vec![
                format!("[!] '{}' not found.", program),
                format!("    Install: sudo apt install {}", program),
            ],
            success: false, kind,
        };
    }

    match Command::new(program).args(args).output() {
        Ok(o) => {
            let mut lines: Vec<String> = String::from_utf8_lossy(&o.stdout)
                .lines().map(|l| l.to_string()).collect();
            let stderr: Vec<String> = String::from_utf8_lossy(&o.stderr)
                .lines().map(|l| format!("[stderr] {l}")).collect();
            if lines.is_empty()                    { lines = stderr.clone(); }
            else if !stderr.is_empty() && stderr.len() < 50 {
                lines.push(String::new());
                lines.extend(stderr);
            }
            if lines.is_empty() { lines.push("(no output)".into()); }
            DynamicResult {
                tool: label.into(), command: command_str,
                output: lines, success: o.status.success(), kind,
            }
        }
        Err(e) => DynamicResult {
            tool: label.into(), command: command_str,
            output: vec![format!("Error: {e}")], success: false, kind,
        },
    }
}
