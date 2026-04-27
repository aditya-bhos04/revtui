/// Format bytes as hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// Format a u64 address
pub fn fmt_addr(addr: u64) -> String {
    format!("{addr:#010x}")
}

/// Human-readable file size
pub fn fmt_size(n: u64) -> String {
    if n < 1024 { return format!("{n} B"); }
    if n < 1024 * 1024 { return format!("{:.1} KB", n as f64 / 1024.0); }
    format!("{:.2} MB", n as f64 / (1024.0 * 1024.0))
}

/// Entropy bar (0..8)
pub fn entropy_bar(entropy: f64, width: usize) -> String {
    let filled = ((entropy / 8.0) * width as f64) as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

/// Entropy classification
pub fn entropy_label(e: f64) -> &'static str {
    if e < 1.0 { "Very Low (zeros/constant)" }
    else if e < 3.5 { "Low (structured data)" }
    else if e < 6.0 { "Medium (code/text)" }
    else if e < 7.5 { "High (compressed/encrypted?)" }
    else            { "Very High — likely packed/encrypted" }
}

/// Truncate string to fit width
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max.saturating_sub(1)]) }
}

/// Format hex dump line (classic xxd style)
pub fn hex_dump_line(offset: usize, data: &[u8]) -> String {
    let hex: String = data.chunks(1).map(|b| format!("{:02x}", b[0])).collect::<Vec<_>>().join(" ");
    let ascii: String = data.iter().map(|&b| {
        if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
    }).collect();
    format!("{offset:08x}:  {hex:<47}  |{ascii}|")
}
