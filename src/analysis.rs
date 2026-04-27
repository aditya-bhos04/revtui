use anyhow::{Context, Result};
use goblin::Object;
use sha2::{Digest, Sha256};
use std::fs;

// ── Data Types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BinaryInfo {
    pub path: String,
    pub file_type: String,
    pub architecture: String,
    pub bits: u32,
    pub endian: String,
    pub entry_point: u64,
    pub file_size: u64,
    pub md5: String,
    pub sha256: String,
    pub is_stripped: bool,
    pub is_pie: bool,
    pub has_nx: bool,
    pub has_canary: bool,
    pub has_relro: bool,
    pub compiler_hint: String,
    pub packer_hint: Option<String>,
    pub linked: String,
    pub os_abi: String,
    pub num_sections: usize,
    pub num_symbols: usize,
    pub num_imports: usize,
}

#[derive(Debug, Clone)]
pub struct DisasmLine {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub comment: String,
    pub is_call: bool,
    pub is_jump: bool,
    pub is_ret: bool,
}

/// A function entry parsed from the symbol table / heuristics
#[derive(Debug, Clone)]
pub struct FunctionEntry {
    pub name: String,
    pub address: u64,
    pub size: u64,           // 0 = unknown
    pub section: String,
    pub binding: String,     // GLOBAL / LOCAL / WEAK
    pub is_entry: bool,      // true if this is the binary entry point
}

#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub offset: u64,
    pub value: String,
    pub encoding: String,
    pub section: String,
    pub length: usize,
    pub kind: StringKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StringKind {
    Ascii,
    Unicode,
    Url,
    Ip,
    Path,
    Registry,
    Interesting,
}

impl StringKind {
    pub fn label(&self) -> &str {
        match self {
            StringKind::Ascii       => "ASCII",
            StringKind::Unicode     => "UTF-16",
            StringKind::Url         => "URL",
            StringKind::Ip          => "IP",
            StringKind::Path        => "PATH",
            StringKind::Registry    => "REG",
            StringKind::Interesting => "!INT",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub vaddr: u64,
    pub offset: u64,
    pub size: u64,
    pub flags: String,
    pub entropy: f64,
    pub kind: SectionKind,
}

#[derive(Debug, Clone)]
pub enum SectionKind {
    Code,
    Data,
    ReadOnly,
    Bss,
    Other,
}

#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: String,
    pub binding: String,
    pub section: String,
    pub demangled: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub name: String,
    pub library: String,
    pub address: u64,
    pub ordinal: Option<u32>,
    pub category: ImportCategory,
}

#[derive(Debug, Clone)]
pub enum ImportCategory {
    Network,
    File,
    Process,
    Memory,
    Crypto,
    Registry,
    Debug,
    Other,
}

impl ImportCategory {
    pub fn label(&self) -> &str {
        match self {
            ImportCategory::Network  => "NET",
            ImportCategory::File     => "FILE",
            ImportCategory::Process  => "PROC",
            ImportCategory::Memory   => "MEM",
            ImportCategory::Crypto   => "CRYPT",
            ImportCategory::Registry => "REG",
            ImportCategory::Debug    => "DBG",
            ImportCategory::Other    => "  -  ",
        }
    }
    pub fn from_name(name: &str) -> Self {
        let n = name.to_lowercase();
        if n.contains("socket")||n.contains("recv")||n.contains("send")||n.contains("connect")||n.contains("bind")||n.contains("http") { return ImportCategory::Network; }
        if n.contains("open")||n.contains("fread")||n.contains("fwrite")||n.contains("unlink")||n.contains("fopen") { return ImportCategory::File; }
        if n.contains("fork")||n.contains("exec")||n.contains("spawn")||n.contains("ptrace")||n.contains("kill")||n.contains("signal") { return ImportCategory::Process; }
        if n.contains("malloc")||n.contains("calloc")||n.contains("realloc")||n.contains("free")||n.contains("mmap")||n.contains("mprotect") { return ImportCategory::Memory; }
        if n.contains("crypt")||n.contains("aes")||n.contains("rsa")||n.contains("sha")||n.contains("md5")||n.contains("rand")||n.contains("ssl") { return ImportCategory::Crypto; }
        if n.contains("reg")&&(n.contains("open")||n.contains("query")||n.contains("set")) { return ImportCategory::Registry; }
        if n.contains("debug")||n.contains("breakpoint")||n.contains("trace") { return ImportCategory::Debug; }
        ImportCategory::Other
    }
}

#[derive(Debug, Clone)]
pub struct EntropyBlock {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub section: String,
}

pub struct AnalysisResult {
    pub info: BinaryInfo,
    pub disasm: Vec<DisasmLine>,
    pub functions: Vec<FunctionEntry>,
    pub strings: Vec<ExtractedString>,
    pub hex_data: Vec<u8>,
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub imports: Vec<ImportInfo>,
    pub entropy: Vec<EntropyBlock>,
}

// ── Main Analysis ─────────────────────────────────────────────────────────────

pub fn analyze_binary(path: &str) -> Result<AnalysisResult> {
    let data = fs::read(path).with_context(|| format!("Cannot read {path}"))?;
    let md5_hash  = format!("{:x}", md5::compute(&data));
    let sha256_hash = { let mut h = Sha256::new(); h.update(&data); format!("{:x}", h.finalize()) };

    let mut info = BinaryInfo {
        path: path.to_string(),
        file_type: "Unknown".into(),
        architecture: "Unknown".into(),
        bits: 64,
        endian: "LE".into(),
        entry_point: 0,
        file_size: data.len() as u64,
        md5: md5_hash,
        sha256: sha256_hash,
        is_stripped: false,
        is_pie: false,
        has_nx: false,
        has_canary: false,
        has_relro: false,
        compiler_hint: detect_compiler(&data),
        packer_hint: detect_packer(&data),
        linked: "dynamic".into(),
        os_abi: "Linux".into(),
        num_sections: 0,
        num_symbols: 0,
        num_imports: 0,
    };

    let mut sections: Vec<SectionInfo> = vec![];
    let mut symbols:  Vec<SymbolInfo>  = vec![];
    let mut imports:  Vec<ImportInfo>  = vec![];
    let mut functions: Vec<FunctionEntry> = vec![];
    let mut code_bytes: Vec<u8> = vec![];
    let mut code_addr:  u64     = 0;

    match Object::parse(&data)? {
        Object::Elf(elf) => {
            info.file_type    = if elf.is_lib { "ELF Shared Library".into() } else { "ELF Executable".into() };
            info.architecture = elf_arch(elf.header.e_machine);
            info.bits         = if elf.is_64 { 64 } else { 32 };
            info.entry_point  = elf.header.e_entry;
            info.is_pie       = elf.header.e_type == goblin::elf::header::ET_DYN;

            for ph in &elf.program_headers {
                if ph.p_type == goblin::elf::program_header::PT_GNU_STACK {
                    info.has_nx = ph.p_flags & 1 == 0;
                }
            }

            for s in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(s.sh_name).unwrap_or("?").to_string();
                let raw: Vec<u8> = if s.sh_type != goblin::elf::section_header::SHT_NOBITS {
                    let st = s.sh_offset as usize;
                    let en = (s.sh_offset + s.sh_size) as usize;
                    if en <= data.len() { data[st..en].to_vec() } else { vec![] }
                } else { vec![] };

                if name == ".text" && !raw.is_empty() {
                    code_bytes = raw.clone();
                    code_addr  = s.sh_addr;
                }

                sections.push(SectionInfo {
                    entropy: calc_entropy(&raw),
                    flags:   format_elf_flags(s.sh_flags),
                    kind:    section_kind_elf(&name, s.sh_flags),
                    name, vaddr: s.sh_addr, offset: s.sh_offset, size: s.sh_size,
                });
            }

            // Symbols + functions
            for sym in elf.syms.iter() {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if name.is_empty() { continue; }
                    let sec = if sym.st_shndx < sections.len() { sections[sym.st_shndx].name.clone() } else { String::new() };
                    let kind = elf_sym_type(sym.st_type());
                    let binding = elf_sym_bind(sym.st_bind());

                    if kind == "FUNC" && sym.st_value != 0 {
                        functions.push(FunctionEntry {
                            name: name.to_string(),
                            address: sym.st_value,
                            size: sym.st_size,
                            section: sec.clone(),
                            binding: binding.clone(),
                            is_entry: sym.st_value == info.entry_point,
                        });
                    }

                    symbols.push(SymbolInfo {
                        name: name.to_string(),
                        address: sym.st_value,
                        size: sym.st_size,
                        kind,
                        binding,
                        section: sec,
                        demangled: demangle_cpp(name),
                    });
                }
            }

            info.is_stripped = functions.is_empty() && symbols.is_empty();

            // Dynamic syms as functions too
            for sym in elf.dynsyms.iter() {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if name.is_empty() { continue; }
                    if elf_sym_type(sym.st_type()) == "FUNC" {
                        if !functions.iter().any(|f| f.name == name) {
                            functions.push(FunctionEntry {
                                name: name.to_string(),
                                address: sym.st_value,
                                size: sym.st_size,
                                section: String::new(),
                                binding: "GLOBAL".into(),
                                is_entry: false,
                            });
                        }
                    }
                }
            }

            // Imports
            for rel in elf.pltrelocs.iter() {
                if let Some(sym) = elf.dynsyms.get(rel.r_sym) {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        imports.push(ImportInfo {
                            name: name.to_string(), library: String::new(),
                            address: rel.r_offset, ordinal: None,
                            category: ImportCategory::from_name(name),
                        });
                    }
                }
            }
            for sym in elf.dynsyms.iter() {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() && !imports.iter().any(|i| i.name == name) {
                        imports.push(ImportInfo {
                            name: name.to_string(), library: String::new(),
                            address: sym.st_value, ordinal: None,
                            category: ImportCategory::from_name(name),
                        });
                    }
                }
            }
        }

        Object::PE(pe) => {
            info.file_type    = if pe.is_lib { "PE DLL".into() } else { "PE Executable".into() };
            info.architecture = if pe.is_64 { "x86_64".into() } else { "x86".into() };
            info.bits         = if pe.is_64 { 64 } else { 32 };
            info.entry_point  = pe.entry as u64;
            info.has_nx       = pe.header.optional_header.map(|o| o.windows_fields.dll_characteristics & 0x100 != 0).unwrap_or(false);
            info.is_pie       = pe.header.optional_header.map(|o| o.windows_fields.dll_characteristics & 0x40 != 0).unwrap_or(false);
            info.os_abi       = "Windows".into();

            for s in &pe.sections {
                let name = String::from_utf8_lossy(&s.name).trim_matches('\0').to_string();
                let st = s.pointer_to_raw_data as usize;
                let en = st + s.size_of_raw_data as usize;
                let raw: Vec<u8> = if en <= data.len() { data[st..en].to_vec() } else { vec![] };
                if name == ".text" && !raw.is_empty() {
                    code_bytes = raw.clone();
                    code_addr  = s.virtual_address as u64 + 0x400000;
                }
                sections.push(SectionInfo {
                    entropy: calc_entropy(&raw),
                    flags:   format_pe_flags(s.characteristics),
                    kind:    section_kind_pe(&name),
                    name, vaddr: s.virtual_address as u64,
                    offset: s.pointer_to_raw_data as u64,
                    size: s.size_of_raw_data as u64,
                });
            }
            for imp in &pe.imports {
                imports.push(ImportInfo {
                    name: imp.name.to_string(), library: imp.dll.to_string(),
                    address: imp.rva as u64, ordinal: None,
                    category: ImportCategory::from_name(&imp.name),
                });
            }
        }
        _ => { info.file_type = "Unknown/Raw Binary".into(); }
    }

    // Build address→name map from all symbols + imports for call resolution
    let mut sym_map: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    for sym in &symbols {
        if sym.address != 0 && !sym.name.is_empty() {
            sym_map.insert(sym.address, sym.name.clone());
        }
    }
    for imp in &imports {
        if imp.address != 0 && !imp.name.is_empty() {
            sym_map.insert(imp.address, format!("{}@plt", imp.name));
        }
    }
    // Also add functions discovered so far
    for func in &functions {
        if func.address != 0 {
            sym_map.entry(func.address).or_insert_with(|| func.name.clone());
        }
    }

    // Full disassembly of .text
    let mut disasm = vec![];
    if !code_bytes.is_empty() {
        disasm = disassemble(&code_bytes, code_addr, &info.architecture, info.bits, &sym_map);
    }

    // If stripped, heuristically detect function entries from disasm (CALL targets + ret boundaries)
    if functions.is_empty() && !disasm.is_empty() {
        functions = heuristic_functions(&disasm, info.entry_point);
    }

    // Sort functions by address
    functions.sort_by_key(|f| f.address);
    functions.dedup_by_key(|f| f.address);

    // Tag each function's disasm range (set size if unknown)
    annotate_function_sizes(&mut functions, &disasm);

    let strings       = extract_strings(&data, &sections);
    let entropy       = compute_entropy_blocks(&data, &sections);

    info.has_canary  = symbols.iter().any(|s| s.name.contains("stack_chk"));
    info.has_relro   = sections.iter().any(|s| s.name == ".got.plt");
    info.num_sections = sections.len();
    info.num_symbols  = symbols.len();
    info.num_imports  = imports.len();

    Ok(AnalysisResult { info, disasm, functions, strings, hex_data: data, sections, symbols, imports, entropy })
}

// ── Function heuristics (stripped binaries) ───────────────────────────────────

fn heuristic_functions(disasm: &[DisasmLine], entry: u64) -> Vec<FunctionEntry> {
    let mut funcs = vec![];
    let mut in_func = false;
    let mut func_start = 0u64;
    let mut idx = 0;

    // Always add entry point
    if entry != 0 {
        funcs.push(FunctionEntry {
            name: "entry".into(), address: entry, size: 0,
            section: ".text".into(), binding: "GLOBAL".into(), is_entry: true,
        });
    }

    for (i, line) in disasm.iter().enumerate() {
        // New function starts after ret or at a push rbp / push ebp sequence
        let is_prologue = (line.mnemonic == "push" && (line.operands == "rbp" || line.operands == "ebp"))
            || (line.mnemonic == "endbr64")
            || (line.mnemonic == "endbr32");

        if !in_func && is_prologue {
            in_func    = true;
            func_start = line.address;
            idx        = funcs.len();
            let label = format!("sub_{:x}", func_start);
            funcs.push(FunctionEntry {
                name: label, address: func_start, size: 0,
                section: ".text".into(), binding: "LOCAL".into(), is_entry: func_start == entry,
            });
        }

        if in_func && line.is_ret {
            if let Some(f) = funcs.get_mut(idx) {
                if f.size == 0 {
                    f.size = line.address - func_start + line.bytes.len() as u64;
                }
            }
            in_func = false;
        }

        let _ = i; // suppress unused
    }

    funcs
}

fn annotate_function_sizes(functions: &mut Vec<FunctionEntry>, disasm: &[DisasmLine]) {
    for i in 0..functions.len() {
        if functions[i].size == 0 {
            let start     = functions[i].address;
            let next_func = functions.get(i + 1).map(|f| f.address).unwrap_or(u64::MAX);

            // For stripped binaries: walk until the LAST ret before next function boundary.
            // We collect ALL instructions up to next function, then trim after the last ret.
            // This handles multiple ret paths (early returns) correctly.
            let block: Vec<&DisasmLine> = disasm.iter()
                .filter(|d| d.address >= start && d.address < next_func)
                .collect();

            // Find the last ret in the block — that is the true function end
            let end_addr = block.iter()
                .filter(|d| d.is_ret)
                .last()
                .map(|d| d.address + d.bytes.len() as u64)
                .unwrap_or_else(|| {
                    // No ret found — use next function boundary
                    block.last().map(|d| d.address + d.bytes.len() as u64).unwrap_or(start)
                });

            functions[i].size = end_addr.saturating_sub(start);
        }
    }
}

/// Extract disasm lines belonging to a specific function.
///
/// Priority:
///   1. If `func.size > 0` (from ELF symbol table) — use that exact byte range.
///      Never break early on intermediate `ret` instructions; the symbol size is the truth.
///   2. If `func.size == 0` (stripped / heuristic) — walk until the LAST ret,
///      bounded by the next function's address.
pub fn disasm_for_function(disasm: &[DisasmLine], func: &FunctionEntry) -> Vec<DisasmLine> {
    let start = func.address;

    if func.size > 0 {
        // ── Symbol-size mode: trust ELF st_size exactly ──────────────────
        // A function may have multiple `ret` instructions (early exits, tail calls).
        // We include ALL instructions in [start, start+size) — no early break on ret.
        let end = start + func.size;
        return disasm.iter()
            .filter(|d| d.address >= start && d.address < end)
            .cloned()
            .collect();
    }

    // ── Stripped / heuristic mode ─────────────────────────────────────────
    // No symbol size available. Walk forward and collect everything until
    // we see the LAST ret before the next function starts.
    // Strategy: collect all candidates up to next function, then cut after last ret.
    let mut result: Vec<DisasmLine> = vec![];
    let mut last_ret_idx: Option<usize> = None;

    for line in disasm {
        if line.address < start { continue; }
        // Stop hard if we hit what looks like another function's prologue
        // (push rbp or endbr64 after we've already started)
        if !result.is_empty() {
            let is_new_prologue =
                (line.mnemonic == "push" && (line.operands == "rbp" || line.operands == "ebp"))
                || line.mnemonic == "endbr64"
                || line.mnemonic == "endbr32";
            // Only treat as new function boundary if we've already seen a ret
            if is_new_prologue && last_ret_idx.is_some() {
                break;
            }
        }
        result.push(line.clone());
        if line.is_ret {
            last_ret_idx = Some(result.len() - 1);
        }
        // Safety cap: 2000 instructions max for heuristic mode
        if result.len() >= 2000 { break; }
    }

    // Trim to just after the last ret
    if let Some(idx) = last_ret_idx {
        result.truncate(idx + 1);
    }
    result
}

// ── Disassembly ───────────────────────────────────────────────────────────────

pub fn disassemble(code: &[u8], base_addr: u64, arch: &str, bits: u32, sym_map: &std::collections::HashMap<u64,String>) -> Vec<DisasmLine> {
    use capstone::prelude::*;
    let cs = match arch {
        "x86_64"|"amd64" => Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).detail(true).build(),
        "x86"            => Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).detail(true).build(),
        "ARM"|"arm"      => Capstone::new().arm().mode(arch::arm::ArchMode::Arm).detail(true).build(),
        "AArch64"|"ARM64"|"aarch64" => Capstone::new().arm64().mode(arch::arm64::ArchMode::Arm).detail(true).build(),
        "MIPS"           => Capstone::new().mips().mode(arch::mips::ArchMode::Mips32).detail(true).build(),
        _ if bits == 64  => Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).detail(true).build(),
        _                => Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).detail(true).build(),
    };
    let cs = match cs { Ok(c) => c, Err(_) => return vec![] };
    let limit = code.len().min(8 * 1024 * 1024);
    let insns = match cs.disasm_all(&code[..limit], base_addr) { Ok(i) => i, Err(_) => return vec![] };
    insns.iter().map(|i| {
        let mne = i.mnemonic().unwrap_or("").to_string();
        let ops = i.op_str().unwrap_or("").to_string();
        let is_call = matches!(mne.as_str(), "call"|"bl"|"blx"|"blr");
        let is_jump = mne.starts_with('j') || matches!(mne.as_str(), "b"|"bne"|"beq"|"bge"|"blt"|"bgt"|"ble");
        let is_ret  = matches!(mne.as_str(), "ret"|"retn"|"retf"|"iret");
        // Resolve call/jump target address to a symbol name if possible
        let resolved_ops = if (is_call || is_jump) && !ops.is_empty() {
            if let Some(target) = parse_op_addr(&ops) {
                if let Some(name) = sym_map.get(&target) {
                    format!("{name}")
                } else {
                    ops.clone()
                }
            } else { ops.clone() }
        } else { ops.clone() };

        let comment = if is_call {
            if resolved_ops != ops {
                format!("; → {}  ({})", resolved_ops, ops)
            } else {
                format!("; → {ops}")
            }
        } else { classify_insn(&mne, &ops) };

        DisasmLine { address: i.address(), bytes: i.bytes().to_vec(), mnemonic: mne,
            operands: resolved_ops, comment, is_call, is_jump, is_ret }
    }).collect()
}

fn parse_op_addr(ops: &str) -> Option<u64> {
    let s = ops.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        return u64::from_str_radix(&s[2..], 16).ok();
    }
    // plain hex like "1080"
    if s.len() >= 3 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return u64::from_str_radix(s, 16).ok();
    }
    None
}

fn classify_insn(mne: &str, ops: &str) -> String {
    match mne {
        "call"|"bl"    => format!("; → {ops}"),
        "ret"|"retn"   => "; ← return".into(),
        "syscall"      => "; ← SYSCALL".into(),
        "int" if ops == "0x80" => "; ← SYSCALL (int 0x80)".into(),
        "nop"          => "; nop".into(),
        "push" if ops.contains("rbp")||ops.contains("ebp") => "; fn prologue".into(),
        "xor" => {
            let p: Vec<_> = ops.split(", ").collect();
            if p.len() == 2 && p[0] == p[1] { "; zero reg".into() } else { String::new() }
        }
        _ => String::new(),
    }
}

// ── String Extraction ─────────────────────────────────────────────────────────

pub fn extract_strings(data: &[u8], sections: &[SectionInfo]) -> Vec<ExtractedString> {
    let min_len = 4usize;
    let mut results = vec![];

    // ASCII
    let mut i = 0usize;
    while i < data.len() {
        if data[i].is_ascii_graphic() || data[i] == b' ' {
            let start = i;
            while i < data.len() && (data[i].is_ascii_graphic() || data[i] == b' ') { i += 1; }
            if i - start >= min_len {
                let s = String::from_utf8_lossy(&data[start..i]).to_string();
                results.push(ExtractedString {
                    offset: start as u64, length: s.len(),
                    section: section_for_offset(start as u64, sections),
                    kind: classify_string(&s),
                    encoding: "ASCII".into(), value: s,
                });
            }
        } else { i += 1; }
    }

    // UTF-16LE
    let mut j = 0usize;
    while j + 1 < data.len() {
        if data[j+1] == 0 && (data[j].is_ascii_graphic() || data[j] == b' ') {
            let start = j;
            let mut chars = vec![];
            while j + 1 < data.len() && data[j+1] == 0 && (data[j].is_ascii_graphic() || data[j] == b' ') {
                chars.push(data[j] as char); j += 2;
            }
            if chars.len() >= min_len {
                let s: String = chars.into_iter().collect();
                results.push(ExtractedString {
                    offset: start as u64, length: s.len(),
                    section: section_for_offset(start as u64, sections),
                    kind: classify_string(&s),
                    encoding: "UTF-16".into(), value: s,
                });
            }
        } else { j += 1; }
    }

    results.sort_by_key(|s| s.offset);
    results.dedup_by_key(|s| s.value.clone());
    results
}

fn classify_string(s: &str) -> StringKind {
    if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://") { return StringKind::Url; }
    if s.starts_with('/') || s.starts_with("C:\\") || s.starts_with("c:\\") { return StringKind::Path; }
    if s.starts_with("HKEY_") || s.contains("\\Software\\") { return StringKind::Registry; }
    let parts: Vec<_> = s.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) { return StringKind::Ip; }
    let lower = s.to_lowercase();
    let keywords = ["password","secret","token","api_key","private","admin","shell","cmd.exe",
                    "powershell","base64","encrypt","decrypt","backdoor","payload","exploit",
                    "reverse","wget","curl","/etc/passwd","/etc/shadow","chmod","VirtualAlloc",
                    "CreateRemoteThread","WriteProcessMemory"];
    if keywords.iter().any(|k| lower.contains(k)) { return StringKind::Interesting; }
    StringKind::Ascii
}

fn section_for_offset(offset: u64, sections: &[SectionInfo]) -> String {
    sections.iter().find(|s| offset >= s.offset && offset < s.offset + s.size)
        .map(|s| s.name.clone()).unwrap_or_default()
}

// ── Entropy ───────────────────────────────────────────────────────────────────

pub fn calc_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    -freq.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / len; p * p.log2() }).sum::<f64>()
}

pub fn compute_entropy_blocks(data: &[u8], sections: &[SectionInfo]) -> Vec<EntropyBlock> {
    let block = 256usize;
    let mut blocks = vec![];
    let mut i = 0usize;
    while i + block <= data.len() {
        let chunk = &data[i..i+block];
        blocks.push(EntropyBlock {
            offset: i as u64, size: block as u64,
            entropy: calc_entropy(chunk),
            section: section_for_offset(i as u64, sections),
        });
        i += block;
    }
    blocks
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn elf_arch(machine: u16) -> String {
    match machine {
        0x03 => "x86".into(),    0x3E => "x86_64".into(),
        0x28 => "ARM".into(),    0xB7 => "AArch64".into(),
        0x08 => "MIPS".into(),   0xF3 => "RISC-V".into(),
        0x15 => "PowerPC".into(),other => format!("0x{other:04x}"),
    }
}
fn format_elf_flags(f: u64) -> String {
    format!("{}{}{}",
        if f&4!=0{'R'}else{'-'}, if f&2!=0{'W'}else{'-'}, if f&1!=0{'X'}else{'-'})
}
fn format_pe_flags(c: u32) -> String {
    format!("{}{}{}",
        if c&0x40000000!=0{'R'}else{'-'}, if c&0x80000000!=0{'W'}else{'-'}, if c&0x20000000!=0{'X'}else{'-'})
}
fn section_kind_elf(name: &str, flags: u64) -> SectionKind {
    if flags&4!=0 && flags&2==0 { return SectionKind::ReadOnly; }
    match name {
        ".text"|".plt"|".plt.got"|".plt.sec" => SectionKind::Code,
        ".data"|".data.rel.ro" => SectionKind::Data,
        ".rodata"|".rodata1"   => SectionKind::ReadOnly,
        ".bss"|".tbss"         => SectionKind::Bss,
        _                      => SectionKind::Other,
    }
}
fn section_kind_pe(name: &str) -> SectionKind {
    match name { ".text"|"CODE"=>SectionKind::Code, ".data"|"DATA"=>SectionKind::Data,
                 ".rdata"=>SectionKind::ReadOnly, ".bss"=>SectionKind::Bss, _=>SectionKind::Other }
}
fn elf_sym_type(t: u8) -> String {
    match t { 0=>"NOTYPE".into(), 1=>"OBJECT".into(), 2=>"FUNC".into(), 3=>"SECTION".into(), 4=>"FILE".into(), _=>format!("{t}") }
}
fn elf_sym_bind(b: u8) -> String {
    match b { 0=>"LOCAL".into(), 1=>"GLOBAL".into(), 2=>"WEAK".into(), _=>format!("{b}") }
}
fn demangle_cpp(name: &str) -> Option<String> {
    if name.starts_with("_Z") { Some(format!("[C++ mangled]")) } else { None }
}
fn detect_compiler(data: &[u8]) -> String {
    let s = String::from_utf8_lossy(data);
    if s.contains("GCC: (")         { return "GCC".into(); }
    if s.contains("clang")||s.contains("LLVM") { return "Clang/LLVM".into(); }
    if s.contains("Microsoft")||s.contains("MSVC") { return "MSVC".into(); }
    if s.contains("runtime.main")   { return "Go".into(); }
    if s.contains("__rust_")        { return "Rust".into(); }
    if s.contains("PyInstaller")    { return "PyInstaller".into(); }
    "Unknown".into()
}
fn detect_packer(data: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(data);
    if s.contains("UPX!")           { return Some("UPX".into()); }
    if s.contains("Themida")        { return Some("Themida".into()); }
    if s.contains("VMProtect")      { return Some("VMProtect".into()); }
    if s.contains("ASPack")         { return Some("ASPack".into()); }
    if calc_entropy(data) > 7.5     { return Some("Possible packer (high entropy)".into()); }
    None
}
