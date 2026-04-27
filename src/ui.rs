use crate::app::{App, DisasmView, InputMode, Tab};
use crate::cfg::CellColor;
use crate::analysis::{ImportCategory, SectionKind, StringKind};
use crate::utils::*;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, BorderType, Cell, Clear, List, ListItem,
        Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, Tabs, Wrap,
    },
    Frame,
};

// ── Palette ───────────────────────────────────────────────────────────────────
const CLR_BG:      Color = Color::Rgb(13,  13,  23);
const CLR_PANEL:   Color = Color::Rgb(20,  20,  35);
const CLR_PANEL2:  Color = Color::Rgb(26,  26,  44);
const CLR_BORDER:  Color = Color::Rgb(55,  75,  115);
const CLR_ACCENT:  Color = Color::Rgb(80,  160, 255);
const CLR_ACCENT2: Color = Color::Rgb(180, 80,  255);
const CLR_GREEN:   Color = Color::Rgb(80,  220, 120);
const CLR_RED:     Color = Color::Rgb(255, 80,  80);
const CLR_YELLOW:  Color = Color::Rgb(255, 210, 60);
const CLR_ORANGE:  Color = Color::Rgb(255, 140, 40);
const CLR_TEAL:    Color = Color::Rgb(60,  200, 200);
const CLR_FG:      Color = Color::Rgb(210, 215, 235);
const CLR_DIM:     Color = Color::Rgb(100, 105, 130);
const CLR_CALL:    Color = Color::Rgb(120, 200, 255);
const CLR_JUMP:    Color = Color::Rgb(255, 200, 80);
const CLR_RET:     Color = Color::Rgb(255, 100, 100);
const CLR_ADDR:    Color = Color::Rgb(100, 130, 185);
const CLR_BYTES:   Color = Color::Rgb(85,  105, 140);
const CLR_MNE:     Color = Color::Rgb(200, 220, 255);
const CLR_SEL:     Color = Color::Rgb(30,  50,  90);

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.size();
    f.render_widget(Block::default().style(Style::default().bg(CLR_BG)), area);
    // Tab bar: 3 rows (top border + tabs + bottom border shared with body)
    // Body: everything in between
    // Status: 1 row at bottom
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tab bar with top+bottom border
            Constraint::Min(0),    // body content
            Constraint::Length(1), // status bar (1 line, no border)
        ])
        .split(area);
    draw_tab_bar(f, app, chunks[0]);
    draw_body(f, app, chunks[1]);
    draw_status_bar(f, app, chunks[2]);
    if app.show_popup { draw_popup(f, app, area); }
}

// ── Tab bar ───────────────────────────────────────────────────────────────────

fn draw_tab_bar(f: &mut Frame, app: &App, area: Rect) {
    let all_tabs = Tab::all();
    let selected_idx = all_tabs.iter().position(|t| t == &app.active_tab).unwrap_or(0);

    let titles: Vec<Line> = all_tabs.iter().enumerate().map(|(i, t)| {
        let label = format!(" {} {} ", i + 1, t.label());
        if t == &app.active_tab {
            Line::from(Span::styled(label, Style::default().fg(CLR_BG).bg(CLR_ACCENT).add_modifier(Modifier::BOLD)))
        } else {
            Line::from(Span::styled(label, Style::default().fg(CLR_DIM)))
        }
    }).collect();

    let file_label = app.file_path.as_deref()
        .map(|p| std::path::Path::new(p).file_name().and_then(|n| n.to_str()).unwrap_or(p))
        .unwrap_or("No file loaded");
    let title = format!(" ▌RevETUI▐  ·  {} ", file_label);

    let tabs = Tabs::new(titles)
        .select(selected_idx)
        .block(Block::default()
            .title(Span::styled(title, Style::default().fg(CLR_ACCENT2).add_modifier(Modifier::BOLD)))
            // TOP + SIDES only — no bottom border so body content sits flush below
            .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(CLR_BORDER))
            .style(Style::default().bg(CLR_PANEL)))
        .highlight_style(Style::default().fg(CLR_BG).bg(CLR_ACCENT).add_modifier(Modifier::BOLD))
        .divider(Span::styled("│", Style::default().fg(CLR_BORDER)));

    f.render_widget(tabs, area);
}

// ── Status bar ────────────────────────────────────────────────────────────────

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let left = match app.input_mode {
        InputMode::Search => {
            let q = if app.active_tab == Tab::Static { &app.func_search_query } else { &app.search_query };
            format!(" 🔍 Filter: {}█", q)
        }
        InputMode::Normal => format!(" {}", app.status_msg),
    };
    let right = " q:quit  Tab:panels  j/k:scroll  Enter:open  Esc:back  /:filter  r:dyn  ?:help ";
    let lstyle = match app.input_mode {
        InputMode::Search => Style::default().fg(CLR_YELLOW).bg(CLR_PANEL2).add_modifier(Modifier::BOLD),
        _ => Style::default().fg(CLR_FG).bg(CLR_PANEL2),
    };
    // Fill entire status row with background first
    f.render_widget(Block::default().style(Style::default().bg(CLR_PANEL2)), area);
    let rlen = right.len() as u16;
    let chunks = Layout::default().direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(rlen)])
        .split(area);
    f.render_widget(Paragraph::new(left).style(lstyle), chunks[0]);
    f.render_widget(
        Paragraph::new(right).style(Style::default().fg(CLR_DIM).bg(CLR_PANEL2)).alignment(Alignment::Right),
        chunks[1],
    );
}

// ── Body router ───────────────────────────────────────────────────────────────

fn draw_body(f: &mut Frame, app: &mut App, area: Rect) {
    match app.active_tab {
        Tab::Dashboard => draw_dashboard(f, app, area),
        Tab::Static    => draw_disasm(f, app, area),
        Tab::Dynamic   => draw_dynamic(f, app, area),
        Tab::Strings   => draw_strings(f, app, area),
        Tab::Hex       => draw_hex(f, app, area),
        Tab::Symbols   => draw_symbols(f, app, area),
        Tab::Sections  => draw_sections(f, app, area),
        Tab::Imports   => draw_imports(f, app, area),
        Tab::Entropy   => draw_entropy(f, app, area),
        Tab::Help      => draw_help(f, app, area),
    }
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

fn draw_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let h = Layout::default().direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)]).split(area);
    let left = Layout::default().direction(Direction::Vertical)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)]).split(h[0]);
    let right = Layout::default().direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(h[1]);
    draw_binary_info(f, app, left[0]);
    draw_security_panel(f, app, left[1]);
    draw_stats_panel(f, app, right[0]);
    draw_log_panel(f, app, right[1]);
}

fn draw_binary_info(f: &mut Frame, app: &App, area: Rect) {
    let block = styled_block(" ◈ Binary Information ", CLR_ACCENT);
    if let Some(ref info) = app.binary_info {
        let f_path  = truncate(&info.path, 50);
        let f_arch  = format!("{} ({}-bit, {})", info.architecture, info.bits, info.endian);
        let f_entry = format!("{:#010x}", info.entry_point);
        let f_size  = fmt_size(info.file_size);
        let f_pack  = info.packer_hint.as_deref().unwrap_or("None detected").to_string();
        let f_strip = if info.is_stripped { "Yes — no debug symbols" } else { "No — symbols present" };
        let f_sha   = truncate(&info.sha256, 50);
        let rows = vec![
            kv_row("File",        &f_path),
            kv_row("Type",        &info.file_type),
            kv_row("Arch",        &f_arch),
            kv_row("Entry",       &f_entry),
            kv_row("Size",        &f_size),
            kv_row("OS / ABI",    &info.os_abi),
            kv_row("Compiler",    &info.compiler_hint),
            kv_row("Packer",      &f_pack),
            kv_row("Stripped",    f_strip),
            kv_row("MD5",         &info.md5),
            kv_row("SHA-256",     &f_sha),
        ];
        let tbl = Table::new(rows, [Constraint::Length(12), Constraint::Min(0)])
            .block(block)
            .header(Row::new(vec!["Field","Value"])
                .style(Style::default().fg(CLR_ACCENT).add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
                .bottom_margin(1));
        f.render_widget(tbl, area);
    } else {
        f.render_widget(Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled("  No binary loaded.", Style::default().fg(CLR_DIM))),
            Line::from(""),
            Line::from(Span::styled("  Usage: revetui /path/to/binary", Style::default().fg(CLR_TEAL))),
        ]).block(block), area);
    }
}

fn draw_security_panel(f: &mut Frame, app: &App, area: Rect) {
    let block = styled_block(" ◈ Security Mitigations ", CLR_ACCENT2);
    if let Some(ref info) = app.binary_info {
        let items = vec![
            sec_item("PIE   (Position Independent Executable)", info.is_pie),
            sec_item("NX    (No-Execute / DEP on stack)",       info.has_nx),
            sec_item("SSP   (Stack Canary / Stack Smashing)",   info.has_canary),
            sec_item("RELRO (Relocation Read-Only)",            info.has_relro),
        ];
        f.render_widget(List::new(items).block(block), area);
    } else {
        f.render_widget(Paragraph::new("").block(block), area);
    }
}

fn draw_stats_panel(f: &mut Frame, app: &App, area: Rect) {
    let block = styled_block(" ◈ Statistics ", CLR_GREEN);
    let mut lines: Vec<Line> = vec![];
    if let Some(ref info) = app.binary_info {
        lines.push(stat_kv("Functions",    app.functions.len()));
        lines.push(stat_kv("Symbols",      info.num_symbols));
        lines.push(stat_kv("Imports",      info.num_imports));
        lines.push(stat_kv("Sections",     info.num_sections));
        lines.push(stat_kv("Strings",      app.strings.len()));
        lines.push(stat_kv("Disasm Lines", app.disassembly.len()));
        let hot = app.strings.iter().filter(|s|
            matches!(s.kind, StringKind::Interesting|StringKind::Url|StringKind::Ip)).count();
        lines.push(Line::from(vec![
            Span::styled("  Interesting Strs: ", Style::default().fg(CLR_DIM)),
            Span::styled(hot.to_string(), Style::default().fg(if hot>0{CLR_RED}else{CLR_FG}).add_modifier(Modifier::BOLD)),
        ]));
        if info.packer_hint.is_some() {
            lines.push(Line::from(Span::styled("  ⚠  PACKER DETECTED",
                Style::default().fg(CLR_RED).add_modifier(Modifier::BOLD))));
        }
    }
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_log_panel(f: &mut Frame, app: &App, area: Rect) {
    let block = styled_block(" ◈ Analysis Log ", CLR_TEAL);
    let items: Vec<ListItem> = app.log.iter().rev().take(30).map(|l| {
        let s = if l.starts_with("[+]") { Style::default().fg(CLR_GREEN) }
            else if l.starts_with("[-]")||l.starts_with("[!]") { Style::default().fg(CLR_RED) }
            else { Style::default().fg(CLR_DIM) };
        ListItem::new(l.as_str()).style(s)
    }).collect();
    f.render_widget(List::new(items).block(block), area);
}

// ── Disassembly — Function Browser + Detail ───────────────────────────────────

fn draw_disasm(f: &mut Frame, app: &mut App, area: Rect) {
    match app.disasm_view {
        DisasmView::FunctionList   => draw_func_list(f, app, area),
        DisasmView::FunctionDetail => draw_func_detail(f, app, area),
        DisasmView::CfgView        => draw_cfg(f, app, area),
    }
}

fn draw_func_list(f: &mut Frame, app: &App, area: Rect) {
    let filtered = app.filtered_functions();
    let q_display = if app.func_search_query.is_empty() {
        String::new()
    } else {
        format!("  filter: \"{}\"", app.func_search_query)
    };
    let title = format!(
        " ◈ Functions  {}({} / {} total)  — Enter: open · /: filter · Esc: clear ",
        q_display, filtered.len(), app.functions.len()
    );
    let block = styled_block(&title, CLR_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if filtered.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                if app.functions.is_empty() { "  No functions found (binary may be stripped or unsupported)" }
                else { "  No matches for current filter" },
                Style::default().fg(CLR_DIM))),
            inner,
        );
        return;
    }

    let visible  = inner.height as usize;
    let selected = app.func_list_scroll.min(filtered.len().saturating_sub(1));
    // Keep selected row visible
    let start = if selected >= visible { selected - visible + 1 } else { 0 };
    let end   = (start + visible).min(filtered.len());

    let rows: Vec<Row> = filtered[start..end].iter().enumerate().map(|(rel_i, (orig_idx, func))| {
        let abs_i = start + rel_i;
        let is_sel = abs_i == selected;
        let row_bg = if is_sel { CLR_SEL } else { CLR_PANEL };

        let bind_color = match func.binding.as_str() {
            "GLOBAL" => CLR_YELLOW, "WEAK" => CLR_ORANGE, _ => CLR_DIM,
        };
        let name_color = if func.is_entry { CLR_RED }
            else if func.binding == "GLOBAL" { CLR_CALL }
            else { CLR_FG };

        let cursor = if is_sel { "▶ " } else { "  " };
        let entry_tag = if func.is_entry { " ★ENTRY" } else { "" };
        let name_disp = format!("{}{}{}", cursor, func.name, entry_tag);
        let size_disp = if func.size > 0 { fmt_size(func.size) } else { "?".into() };
        let insn_count = {
            let end_addr = func.address + func.size.max(1);
            app.disassembly.iter().filter(|d| d.address >= func.address && d.address < end_addr).count()
        };

        let sel_style = Style::default().bg(row_bg);
        Row::new(vec![
            Cell::from(Span::styled(format!("{:>4}", orig_idx + 1),           Style::default().fg(CLR_DIM).bg(row_bg))),
            Cell::from(Span::styled(format!("{:#010x}", func.address),         Style::default().fg(CLR_ADDR).bg(row_bg))),
            Cell::from(Span::styled(format!("{:<7}", func.binding),            Style::default().fg(bind_color).bg(row_bg))),
            Cell::from(Span::styled(format!("{:>8}", size_disp),               Style::default().fg(CLR_DIM).bg(row_bg))),
            Cell::from(Span::styled(format!("{:>6} insns", insn_count),        Style::default().fg(CLR_DIM).bg(row_bg))),
            Cell::from(Span::styled(truncate(&name_disp, 70),                  Style::default().fg(name_color).add_modifier(if is_sel{Modifier::BOLD}else{Modifier::empty()}).bg(row_bg))),
        ]).style(sel_style)
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(5),  // #
        Constraint::Length(12), // address
        Constraint::Length(8),  // binding
        Constraint::Length(9),  // size
        Constraint::Length(12), // insn count
        Constraint::Min(0),     // name
    ]).header(Row::new(vec!["#", "Address", "Bind", "Size", "Insns", "Function Name"])
        .style(Style::default().fg(CLR_ACCENT).add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
        .bottom_margin(1));

    f.render_widget(table, inner);

    let mut sb = ScrollbarState::new(filtered.len()).position(selected);
    f.render_stateful_widget(Scrollbar::new(ScrollbarOrientation::VerticalRight), area, &mut sb);
}

fn draw_func_detail(f: &mut Frame, app: &App, area: Rect) {
    let func_name = app.selected_func
        .and_then(|i| app.functions.get(i))
        .map(|f| f.name.clone())
        .unwrap_or_else(|| "?".into());
    let func_addr = app.selected_func
        .and_then(|i| app.functions.get(i))
        .map(|f| f.address)
        .unwrap_or(0);

    let disasm = app.current_func_disasm();
    let title = format!(
        " ◈ {}  @{:#010x}  ({} instructions)  — Esc: back to list ",
        func_name, func_addr, disasm.len()
    );
    let block = styled_block(&title, CLR_CALL);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if disasm.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled("  No disassembly found for this function.", Style::default().fg(CLR_DIM))),
            inner,
        );
        return;
    }

    let visible = inner.height as usize;
    let start   = app.func_detail_scroll.min(disasm.len().saturating_sub(1));
    let end     = (start + visible).min(disasm.len());

    let rows: Vec<Row> = disasm[start..end].iter().map(|d| {
        let mne_color = if d.is_call { CLR_CALL }
            else if d.is_ret  { CLR_RET  }
            else if d.is_jump { CLR_JUMP }
            else              { CLR_MNE  };
        let ops_color = if d.operands.starts_with("0x") { CLR_TEAL } else { CLR_FG };
        // Relative offset from function start
        let rel = d.address.saturating_sub(func_addr);
        Row::new(vec![
            Cell::from(Span::styled(format!("+{:<6x}", rel),          Style::default().fg(CLR_DIM))),
            Cell::from(Span::styled(format!("{:#010x}", d.address),   Style::default().fg(CLR_ADDR))),
            Cell::from(Span::styled(format!("{:<20}", bytes_to_hex(&d.bytes)), Style::default().fg(CLR_BYTES))),
            Cell::from(Span::styled(format!("{:<8}", d.mnemonic),     Style::default().fg(mne_color).add_modifier(Modifier::BOLD))),
            Cell::from(Span::styled(format!("{:<34}", d.operands),    Style::default().fg(ops_color))),
            Cell::from(Span::styled(d.comment.clone(),                Style::default().fg(CLR_DIM))),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(8),  // +offset
        Constraint::Length(12), // address
        Constraint::Length(22), // bytes
        Constraint::Length(10), // mnemonic
        Constraint::Length(36), // operands
        Constraint::Min(0),     // comment
    ]).header(Row::new(vec!["+Offset", "Address", "Bytes", "Mnemonic", "Operands", "Comment"])
        .style(Style::default().fg(CLR_CALL).add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
        .bottom_margin(1));

    f.render_widget(table, inner);

    let mut sb = ScrollbarState::new(disasm.len()).position(start);
    f.render_stateful_widget(Scrollbar::new(ScrollbarOrientation::VerticalRight), area, &mut sb);
}

// ── Dynamic Analysis ──────────────────────────────────────────────────────────

fn draw_dynamic(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default().direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)]).split(area);

    let hint = if app.file_path.is_some() {
        " [r] Run all tools: strace · ltrace · ldd · readelf · checksec · objdump · strings "
    } else {
        " No binary loaded — run: revetui /path/to/binary "
    };
    f.render_widget(
        Paragraph::new(hint).style(Style::default().fg(CLR_YELLOW))
            .block(styled_block(" ◈ Dynamic Analysis ", CLR_ORANGE)),
        chunks[0],
    );

    if app.dynamic_results.is_empty() {
        f.render_widget(
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled("  No results yet. Press [r] to run all dynamic tools.", Style::default().fg(CLR_DIM))),
                Line::from(Span::styled("  Requires: strace ltrace binutils file checksec", Style::default().fg(CLR_TEAL))),
            ]).block(styled_block(" Results ", CLR_ACCENT)),
            chunks[1],
        );
        return;
    }

    let title = format!(" ◈ Results ({} tools) — j/k scroll ", app.dynamic_results.len());
    let block = styled_block(&title, CLR_ORANGE);
    let inner = block.inner(chunks[1]);
    f.render_widget(block, chunks[1]);

    // Build lines now that we know inner.width for the separator
    let sep_width = inner.width.saturating_sub(2) as usize;
    let mut all_lines: Vec<(String, Style)> = vec![];
    for result in &app.dynamic_results {
        let hdr = if result.success { Style::default().fg(CLR_GREEN).add_modifier(Modifier::BOLD) }
                  else              { Style::default().fg(CLR_ORANGE).add_modifier(Modifier::BOLD) };
        // Header line: truncate command to fit terminal width
        let cmd_disp = truncate(&result.command, sep_width.saturating_sub(20));
        all_lines.push((format!("┌─[ {} ]─$ {}", result.tool.to_uppercase(), cmd_disp), hdr));
        for line in &result.output {
            let s = if line.starts_with("[!]") || line.to_lowercase().contains("error") {
                Style::default().fg(CLR_RED)
            } else if line.starts_with("[stderr]") {
                Style::default().fg(CLR_ORANGE)
            } else {
                Style::default().fg(CLR_FG)
            };
            all_lines.push((format!("│  {line}"), s));
        }
        // Separator: exactly fits the inner width — no overflow
        all_lines.push((format!("└{}", "─".repeat(sep_width)), Style::default().fg(CLR_BORDER)));
        all_lines.push((String::new(), Style::default()));
    }

    let visible = inner.height as usize;
    let start   = app.dynamic_scroll.min(all_lines.len().saturating_sub(1));
    let end     = (start + visible).min(all_lines.len());

    let items: Vec<ListItem> = all_lines[start..end].iter()
        .map(|(t, s)| ListItem::new(t.as_str()).style(*s)).collect();
    f.render_widget(List::new(items), inner);

    let mut sb = ScrollbarState::new(all_lines.len()).position(start);
    f.render_stateful_widget(Scrollbar::new(ScrollbarOrientation::VerticalRight), chunks[1], &mut sb);
}

// ── Strings ───────────────────────────────────────────────────────────────────

fn draw_strings(f: &mut Frame, app: &App, area: Rect) {
    let filtered = app.filtered_strings();
    let fq = if app.search_query.is_empty() { String::new() } else { format!("  filter:\"{}\"  ", app.search_query) };
    let title = format!(" ◈ Strings {}({}/{}) ", fq, filtered.len(), app.strings.len());
    let block = styled_block(&title, CLR_GREEN);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let visible = inner.height as usize;
    let start   = app.strings_scroll.min(filtered.len().saturating_sub(1));
    let end     = (start + visible).min(filtered.len());

    let rows: Vec<Row> = filtered[start..end].iter().map(|s| {
        let kc = match s.kind {
            StringKind::Url         => CLR_TEAL,
            StringKind::Ip          => CLR_ORANGE,
            StringKind::Path        => CLR_ACCENT,
            StringKind::Registry    => CLR_ACCENT2,
            StringKind::Interesting => CLR_RED,
            StringKind::Ascii       => CLR_FG,
            StringKind::Unicode     => CLR_YELLOW,
        };
        Row::new(vec![
            Cell::from(Span::styled(format!("{:#010x}", s.offset), Style::default().fg(CLR_ADDR))),
            Cell::from(Span::styled(format!("{:>5}", s.length),    Style::default().fg(CLR_DIM))),
            Cell::from(Span::styled(s.kind.label(),                Style::default().fg(kc).add_modifier(Modifier::BOLD))),
            Cell::from(Span::styled(s.encoding.clone(),            Style::default().fg(CLR_DIM))),
            Cell::from(Span::styled(s.section.clone(),             Style::default().fg(CLR_DIM))),
            Cell::from(Span::styled(truncate(&s.value, 90),        Style::default().fg(CLR_FG))),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(12), Constraint::Length(6), Constraint::Length(7),
        Constraint::Length(7),  Constraint::Length(10), Constraint::Min(0),
    ]).header(Row::new(vec!["Offset","Len","Kind","Enc","Section","String"])
        .style(Style::default().fg(CLR_GREEN).add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
        .bottom_margin(1));

    f.render_widget(table, inner);
    let mut sb = ScrollbarState::new(filtered.len()).position(start);
    f.render_stateful_widget(Scrollbar::new(ScrollbarOrientation::VerticalRight), area, &mut sb);
}

// ── Hex View ──────────────────────────────────────────────────────────────────

fn draw_hex(f: &mut Frame, app: &App, area: Rect) {
    let hex_title = format!(" ◈ Hex View ({}) ", fmt_size(app.hex_data.len() as u64));
    let block = styled_block(&hex_title, CLR_TEAL);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let bpr     = 16usize;
    let visible = inner.height as usize;
    let total   = (app.hex_data.len() + bpr - 1) / bpr;
    let start   = app.hex_scroll.min(total.saturating_sub(1));
    let end     = (start + visible).min(total);

    let lines: Vec<Line> = (start..end).map(|row| {
        let off   = row * bpr;
        let chunk = &app.hex_data[off..(off + bpr).min(app.hex_data.len())];
        let mut spans = vec![Span::styled(format!("{off:08x}  "), Style::default().fg(CLR_ADDR))];
        for (i, &b) in chunk.iter().enumerate() {
            let col = if b == 0 { CLR_DIM } else if b.is_ascii_graphic() { CLR_GREEN } else if b < 0x20 { CLR_RED } else { CLR_FG };
            spans.push(Span::styled(format!("{b:02x}"), Style::default().fg(col)));
            if i < chunk.len() - 1 { spans.push(Span::raw(if i == 7 { "  " } else { " " })); }
        }
        let miss = bpr - chunk.len();
        if miss > 0 {
            let pad = "   ".repeat(miss);
            spans.push(Span::raw(if chunk.len() <= 8 { format!("  {pad}") } else { pad }));
        }
        spans.push(Span::styled("  │", Style::default().fg(CLR_BORDER)));
        for &b in chunk {
            let (c, col) = if b.is_ascii_graphic() { (b as char, CLR_FG) }
                else if b == b' ' { (' ', CLR_DIM) }
                else if b == 0   { ('.', CLR_DIM) }
                else              { ('·', CLR_BYTES) };
            spans.push(Span::styled(c.to_string(), Style::default().fg(col)));
        }
        spans.push(Span::styled("│", Style::default().fg(CLR_BORDER)));
        Line::from(spans)
    }).collect();

    f.render_widget(Paragraph::new(lines), inner);
    let mut sb = ScrollbarState::new(total).position(start);
    f.render_stateful_widget(Scrollbar::new(ScrollbarOrientation::VerticalRight), area, &mut sb);
}

// ── Symbols ───────────────────────────────────────────────────────────────────

fn draw_symbols(f: &mut Frame, app: &App, area: Rect) {
    let filtered = app.filtered_symbols();
    let title = format!(" ◈ Symbols ({}/{}) ", filtered.len(), app.symbols.len());
    let block = styled_block(&title, CLR_ACCENT2);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let visible = inner.height as usize;
    let start   = app.symbols_scroll.min(filtered.len().saturating_sub(1));
    let end     = (start + visible).min(filtered.len());

    let rows: Vec<Row> = filtered[start..end].iter().map(|s| {
        let kc = match s.kind.as_str() { "FUNC"=>"CLR_CALL", "OBJECT"=>"CLR_GREEN", _=>"" };
        let kc = if kc == "CLR_CALL" { CLR_CALL } else if kc == "CLR_GREEN" { CLR_GREEN } else { CLR_DIM };
        let bc = match s.binding.as_str() { "GLOBAL"=>CLR_YELLOW, "WEAK"=>CLR_ORANGE, _=>CLR_DIM };
        Row::new(vec![
            Cell::from(Span::styled(format!("{:#010x}", s.address), Style::default().fg(CLR_ADDR))),
            Cell::from(Span::styled(format!("{:>6}", s.size),       Style::default().fg(CLR_DIM))),
            Cell::from(Span::styled(format!("{:<7}", s.kind),       Style::default().fg(kc))),
            Cell::from(Span::styled(format!("{:<6}", s.binding),    Style::default().fg(bc))),
            Cell::from(Span::styled(truncate(&s.name, 60),          Style::default().fg(CLR_FG))),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(12), Constraint::Length(8),
        Constraint::Length(8),  Constraint::Length(8), Constraint::Min(0),
    ]).header(Row::new(vec!["Address","Size","Type","Bind","Name"])
        .style(Style::default().fg(CLR_ACCENT2).add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
        .bottom_margin(1));

    f.render_widget(table, inner);
    let mut sb = ScrollbarState::new(filtered.len()).position(start);
    f.render_stateful_widget(Scrollbar::new(ScrollbarOrientation::VerticalRight), area, &mut sb);
}

// ── Sections ──────────────────────────────────────────────────────────────────

fn draw_sections(f: &mut Frame, app: &App, area: Rect) {
    let sec_title = format!(" ◈ Sections ({}) ", app.sections.len());
    let block = styled_block(&sec_title, CLR_YELLOW);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let visible = inner.height as usize;
    let start   = app.sections_scroll.min(app.sections.len().saturating_sub(1));
    let end     = (start + visible).min(app.sections.len());

    let rows: Vec<Row> = app.sections[start..end].iter().map(|s| {
        let (kl, kc) = match s.kind {
            SectionKind::Code     => ("CODE", CLR_CALL),
            SectionKind::Data     => ("DATA", CLR_GREEN),
            SectionKind::ReadOnly => ("RDAT", CLR_TEAL),
            SectionKind::Bss      => ("BSS ", CLR_DIM),
            SectionKind::Other    => ("    ", CLR_FG),
        };
        let ec = ent_color(s.entropy);
        let ebar = entropy_bar(s.entropy, 12);
        let ent_str = format!("{:.4}  {}", s.entropy, ebar);
        Row::new(vec![
            Cell::from(Span::styled(format!("{:<15}", s.name),          Style::default().fg(CLR_FG).add_modifier(Modifier::BOLD))),
            Cell::from(Span::styled(kl,                                  Style::default().fg(kc))),
            Cell::from(Span::styled(format!("{:#010x}", s.vaddr),        Style::default().fg(CLR_ADDR))),
            Cell::from(Span::styled(format!("{:#010x}", s.offset),       Style::default().fg(CLR_DIM))),
            Cell::from(Span::styled(fmt_size(s.size),                    Style::default().fg(CLR_FG))),
            Cell::from(Span::styled(s.flags.clone(),                     Style::default().fg(CLR_YELLOW))),
            Cell::from(Span::styled(ent_str,                             Style::default().fg(ec))),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(16), Constraint::Length(5),  Constraint::Length(12),
        Constraint::Length(12), Constraint::Length(10), Constraint::Length(5), Constraint::Min(0),
    ]).header(Row::new(vec!["Name","Kind","VAddr","Offset","Size","Flg","Entropy"])
        .style(Style::default().fg(CLR_YELLOW).add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
        .bottom_margin(1));

    f.render_widget(table, inner);
    let mut sb = ScrollbarState::new(app.sections.len()).position(start);
    f.render_stateful_widget(Scrollbar::new(ScrollbarOrientation::VerticalRight), area, &mut sb);
}

// ── Imports ───────────────────────────────────────────────────────────────────

fn draw_imports(f: &mut Frame, app: &App, area: Rect) {
    let filtered = app.filtered_imports();
    let title = format!(" ◈ Imports ({}/{}) ", filtered.len(), app.imports.len());
    let block = styled_block(&title, CLR_ORANGE);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let visible = inner.height as usize;
    let start   = app.imports_scroll.min(filtered.len().saturating_sub(1));
    let end     = (start + visible).min(filtered.len());

    let rows: Vec<Row> = filtered[start..end].iter().map(|imp| {
        let cc = match imp.category {
            ImportCategory::Network  => CLR_TEAL,   ImportCategory::File    => CLR_ACCENT,
            ImportCategory::Process  => CLR_ACCENT2, ImportCategory::Memory  => CLR_YELLOW,
            ImportCategory::Crypto   => CLR_RED,     ImportCategory::Registry=> CLR_ORANGE,
            ImportCategory::Debug    => CLR_DIM,     ImportCategory::Other   => CLR_FG,
        };
        Row::new(vec![
            Cell::from(Span::styled(format!("{:#010x}", imp.address), Style::default().fg(CLR_ADDR))),
            Cell::from(Span::styled(imp.category.label(),             Style::default().fg(cc).add_modifier(Modifier::BOLD))),
            Cell::from(Span::styled(truncate(&imp.library, 25),       Style::default().fg(CLR_DIM))),
            Cell::from(Span::styled(truncate(&imp.name, 65),          Style::default().fg(CLR_FG))),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(12), Constraint::Length(7),
        Constraint::Length(26), Constraint::Min(0),
    ]).header(Row::new(vec!["Address","Cat","Library","Name"])
        .style(Style::default().fg(CLR_ORANGE).add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
        .bottom_margin(1));

    f.render_widget(table, inner);
    let mut sb = ScrollbarState::new(filtered.len()).position(start);
    f.render_stateful_widget(Scrollbar::new(ScrollbarOrientation::VerticalRight), area, &mut sb);
}

// ── Entropy ── FIXED ──────────────────────────────────────────────────────────

fn draw_entropy(f: &mut Frame, app: &App, area: Rect) {
    // Split into 3 vertical zones: section table | sparkline | legend
    let zones = Layout::default().direction(Direction::Vertical)
        .constraints([
            Constraint::Length(app.sections.len() as u16 + 4), // section table
            Constraint::Min(10),                                 // heatmap
            Constraint::Length(4),                               // legend
        ])
        .split(area);

    // ── Zone 1: per-section entropy table ─────────────────────────────────────
    {
        let block = styled_block(" ◈ Per-Section Entropy ", CLR_YELLOW);
        let inner = block.inner(zones[0]);
        f.render_widget(block, zones[0]);

        if app.sections.is_empty() {
            f.render_widget(Paragraph::new(Span::styled("No sections.", Style::default().fg(CLR_DIM))), inner);
        } else {
            let rows: Vec<Row> = app.sections.iter().map(|s| {
                let ec    = ent_color(s.entropy);
                let bar   = entropy_bar(s.entropy, 20);
                let label = ent_label(s.entropy);
                Row::new(vec![
                    Cell::from(Span::styled(format!("{:<16}", s.name),           Style::default().fg(CLR_FG).add_modifier(Modifier::BOLD))),
                    Cell::from(Span::styled(fmt_size(s.size),                    Style::default().fg(CLR_DIM))),
                    Cell::from(Span::styled(format!("{:.4}", s.entropy),         Style::default().fg(ec).add_modifier(Modifier::BOLD))),
                    Cell::from(Span::styled(bar,                                  Style::default().fg(ec))),
                    Cell::from(Span::styled(label,                                Style::default().fg(ec))),
                ])
            }).collect();

            let tbl = Table::new(rows, [
                Constraint::Length(17),
                Constraint::Length(9),
                Constraint::Length(7),
                Constraint::Length(22),
                Constraint::Min(0),
            ]).header(Row::new(vec!["Section","Size","H(X)","Bar (0–8)","Classification"])
                .style(Style::default().fg(CLR_YELLOW).add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
                .bottom_margin(1));

            f.render_widget(tbl, inner);
        }
    }

    // ── Zone 2: entropy heatmap ───────────────────────────────────────────────
    {
        let emap_title = format!(
            " ◈ Entropy Heatmap  ({} blocks × 256 B  |  file size: {}) ",
            app.entropy_blocks.len(),
            fmt_size(app.hex_data.len() as u64)
        );
        let block = styled_block(&emap_title, CLR_ORANGE);
        let inner = block.inner(zones[1]);
        f.render_widget(block, zones[1]);

        let blocks = &app.entropy_blocks;
        if blocks.is_empty() {
            f.render_widget(Paragraph::new(Span::styled("No data.", Style::default().fg(CLR_DIM))), inner);
        } else {
            let width  = inner.width  as usize;
            let height = inner.height as usize;
            // Map each column of the chart to a block index
            // Each column covers (blocks.len() / width) blocks — pick max entropy in that range
            let lines: Vec<Line> = (0..height).rev().map(|row| {
                // row 0 = bottom (entropy ~0), row height-1 = top (entropy ~8)
                let threshold = (row as f64 / height.max(1) as f64) * 8.0;
                let spans: Vec<Span> = (0..width).map(|col| {
                    // Map col → block range
                    let b_start = col * blocks.len() / width.max(1);
                    let b_end   = ((col + 1) * blocks.len() / width.max(1)).min(blocks.len());
                    let b_end   = b_end.max(b_start + 1).min(blocks.len());
                    // Use max entropy in this column bucket for accurate representation
                    let max_ent = blocks[b_start..b_end].iter()
                        .map(|b| b.entropy)
                        .fold(f64::NEG_INFINITY, f64::max);
                    if max_ent >= threshold {
                        let color = ent_color(max_ent);
                        Span::styled("█", Style::default().fg(color))
                    } else {
                        Span::styled(" ", Style::default().bg(CLR_PANEL))
                    }
                }).collect();
                Line::from(spans)
            }).collect();

            // Y-axis labels on left: overlay entropy scale
            let label_area = Rect {
                x: inner.x, y: inner.y,
                width: 4.min(inner.width),
                height: inner.height,
            };
            let chart_area = Rect {
                x: inner.x + 4, y: inner.y,
                width: inner.width.saturating_sub(4),
                height: inner.height,
            };

            // Y-axis
            let y_labels: Vec<Line> = (0..height).rev().map(|row| {
                let ent_val = (row as f64 / height.max(1) as f64) * 8.0;
                if row % (height / 4).max(1) == 0 {
                    Line::from(Span::styled(format!("{:.1}│", ent_val), Style::default().fg(CLR_DIM)))
                } else {
                    Line::from(Span::styled("   │", Style::default().fg(CLR_BORDER)))
                }
            }).collect();
            f.render_widget(Paragraph::new(y_labels), label_area);
            f.render_widget(Paragraph::new(lines), chart_area);

            // X-axis: file offset markers
            if inner.height > 2 {
                let xaxis_area = Rect {
                    x: inner.x + 4, y: inner.y + inner.height.saturating_sub(1),
                    width: inner.width.saturating_sub(4),
                    height: 1,
                };
                let file_size = app.hex_data.len() as u64;
                let ticks = 5usize;
                let mut tick_spans = vec![];
                let w = xaxis_area.width as usize;
                for t in 0..=ticks {
                    let offset_val = file_size * t as u64 / ticks as u64;
                    let label = format!("{:#x}", offset_val);
                    let pos = t * w / ticks;
                    let pad = pos.saturating_sub(tick_spans.iter().map(|s: &Span| s.content.len()).sum::<usize>());
                    if pad > 0 { tick_spans.push(Span::styled(" ".repeat(pad), Style::default())); }
                    tick_spans.push(Span::styled(label, Style::default().fg(CLR_DIM)));
                }
                f.render_widget(Paragraph::new(Line::from(tick_spans)), xaxis_area);
            }
        }
    }

    // ── Zone 3: legend ────────────────────────────────────────────────────────
    {
        let block = styled_block(" Legend ", CLR_BORDER);
        let inner = block.inner(zones[2]);
        f.render_widget(block, zones[2]);

        let legend = Line::from(vec![
            Span::styled("  █ ", Style::default().fg(CLR_GREEN)),
            Span::styled("Low (<4.0) plain/code    ", Style::default().fg(CLR_DIM)),
            Span::styled("█ ", Style::default().fg(CLR_YELLOW)),
            Span::styled("Medium (4–6.5) mixed     ", Style::default().fg(CLR_DIM)),
            Span::styled("█ ", Style::default().fg(CLR_ORANGE)),
            Span::styled("High (6.5–7.5) compressed?  ", Style::default().fg(CLR_DIM)),
            Span::styled("█ ", Style::default().fg(CLR_RED)),
            Span::styled("Very High (>7.5) packed/encrypted", Style::default().fg(CLR_DIM)),
        ]);
        f.render_widget(Paragraph::new(legend), inner);
    }
}

// ── Help ──────────────────────────────────────────────────────────────────────

fn draw_help(f: &mut Frame, _app: &App, area: Rect) {
    let block = styled_block(" ◈ RevETUI — Help & Keyboard Reference ", CLR_ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let cols = Layout::default().direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(inner);

    let left = build_help(&[
        ("NAVIGATION", &[
            ("Tab / →",         "Next panel"),
            ("Shift+Tab / ←",   "Previous panel"),
            ("1–0",             "Jump to panel directly"),
            ("j / ↓",           "Scroll / select down"),
            ("k / ↑",           "Scroll / select up"),
            ("d / PgDn",        "Page down"),
            ("u / PgUp",        "Page up"),
            ("g / Home",        "Go to top"),
        ]),
        ("DISASSEMBLY (panel 2)", &[
            ("Enter",           "Open selected function"),
            ("Esc",             "Back to function list"),
            ("j / k",           "Navigate function list"),
            ("/",               "Filter functions by name/addr"),
            ("★ ENTRY",         "Binary entry point marker"),
        ]),
        ("SEARCH / FILTER", &[
            ("/",               "Open filter bar"),
            ("Enter",           "Apply filter"),
            ("Esc",             "Clear filter / close"),
        ]),
    ]);

    let right = build_help(&[
        ("ACTIONS", &[
            ("r",               "Run all dynamic tools (Dyn tab)"),
            ("e",               "Show binary summary popup"),
            ("o",               "How to open a binary"),
            ("? / F1",          "This help screen"),
            ("q / Ctrl+C",      "Quit"),
        ]),
        ("PANELS", &[
            ("1  Dashboard",    "Overview · hashes · mitigations"),
            ("2  Disasm",       "Function list → disassembly"),
            ("3  Dynamic",      "strace/ltrace/ldd/checksec/readelf"),
            ("4  Strings",      "ASCII/UTF-16, URLs, IPs, paths"),
            ("5  Hex",          "Full xxd-style hex dump"),
            ("6  Symbols",      "ELF/PE symbol table"),
            ("7  Sections",     "Section headers + per-section entropy"),
            ("8  Imports",      "Imported fns, auto-categorised"),
            ("9  Entropy",      "Per-section table + heatmap chart"),
        ]),
        ("DYNAMIC TOOLS", &[
            ("strace -c",       "System call summary & counts"),
            ("ltrace -c",       "Library call summary"),
            ("ldd",             "Shared library dependencies"),
            ("readelf -h/-d/-l","ELF headers + segments"),
            ("checksec",        "Security mitigation checker"),
            ("objdump .plt",    "PLT stub disassembly"),
            ("strings -n 4",    "Printable strings extraction"),
        ]),
    ]);

    f.render_widget(Paragraph::new(left).wrap(Wrap{trim:false}),  cols[0]);
    f.render_widget(Paragraph::new(right).wrap(Wrap{trim:false}), cols[1]);
}

fn build_help<'a>(groups: &[(&'a str, &[(&'a str, &'a str)])]) -> Vec<Line<'a>> {
    let mut lines = vec![];
    for (hdr, items) in groups {
        lines.push(Line::from(Span::styled(*hdr,
            Style::default().fg(CLR_ACCENT).add_modifier(Modifier::BOLD | Modifier::UNDERLINED))));
        for (key, desc) in *items {
            lines.push(Line::from(vec![
                Span::styled(format!("  {:<20}", key), Style::default().fg(CLR_YELLOW)),
                Span::styled(*desc, Style::default().fg(CLR_FG)),
            ]));
        }
        lines.push(Line::from(""));
    }
    lines
}

// ── Popup ─────────────────────────────────────────────────────────────────────

fn draw_popup(f: &mut Frame, app: &App, area: Rect) {
    let w = (area.width * 60 / 100).max(55).min(area.width.saturating_sub(4));
    let h = ((app.popup_content.len() as u16) + 4).min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(w))  / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let popup_area = Rect::new(x, y, w, h);
    f.render_widget(Clear, popup_area);
    let items: Vec<Line> = app.popup_content.iter()
        .map(|l| Line::from(Span::styled(l.as_str(), Style::default().fg(CLR_FG)))).collect();
    f.render_widget(
        Paragraph::new(items)
            .block(Block::default()
                .title(Span::styled(format!(" {} ", app.popup_title),
                    Style::default().fg(CLR_ACCENT2).add_modifier(Modifier::BOLD)))
                .borders(Borders::ALL).border_type(BorderType::Double)
                .border_style(Style::default().fg(CLR_ACCENT))
                .style(Style::default().bg(CLR_PANEL2)))
            .wrap(Wrap{trim:false}),
        popup_area,
    );
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn styled_block<'a>(title: &'a str, color: Color) -> Block<'a> {
    Block::default()
        .title(Span::styled(title, Style::default().fg(color).add_modifier(Modifier::BOLD)))
        .borders(Borders::ALL).border_type(BorderType::Rounded)
        .border_style(Style::default().fg(CLR_BORDER))
        .style(Style::default().bg(CLR_PANEL))
}

fn kv_row<'a>(key: &'a str, val: &'a str) -> Row<'a> {
    Row::new(vec![
        Cell::from(Span::styled(key, Style::default().fg(CLR_DIM))),
        Cell::from(Span::styled(val, Style::default().fg(CLR_FG))),
    ])
}

fn sec_item(label: &str, enabled: bool) -> ListItem {
    let (icon, color) = if enabled { ("✓", CLR_GREEN) } else { ("✗", CLR_RED) };
    ListItem::new(Line::from(vec![
        Span::styled(format!("  {icon} "), Style::default().fg(color).add_modifier(Modifier::BOLD)),
        Span::styled(label.to_string(), Style::default().fg(if enabled { CLR_FG } else { CLR_DIM })),
    ]))
}

fn stat_kv(label: &str, val: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {label}: "), Style::default().fg(CLR_DIM)),
        Span::styled(val.to_string(), Style::default().fg(CLR_FG).add_modifier(Modifier::BOLD)),
    ])
}

fn ent_color(e: f64) -> Color {
    if e > 7.5 { CLR_RED } else if e > 6.5 { CLR_ORANGE } else if e > 4.0 { CLR_YELLOW } else { CLR_GREEN }
}

fn ent_label(e: f64) -> &'static str {
    if e > 7.5 { "Very High — packed / encrypted" }
    else if e > 6.5 { "High — compressed / obfuscated?" }
    else if e > 4.0 { "Medium — mixed code/data" }
    else if e > 1.0 { "Low — structured code/text" }
    else             { "Very Low — zeros / padding" }
}

// ── CFG View ──────────────────────────────────────────────────────────────────

fn draw_cfg(f: &mut Frame, app: &mut App, area: Rect) {
    use ratatui::style::Color as C;

    let func_name = app.selected_func
        .and_then(|i| app.functions.get(i))
        .map(|f| f.name.clone())
        .unwrap_or_else(|| "?".into());
    let func_addr = app.selected_func
        .and_then(|i| app.functions.get(i))
        .map(|f| f.address)
        .unwrap_or(0);

    let block_count = app.cfg.as_ref().map(|c| c.blocks.len()).unwrap_or(0);
    let edge_count  = app.cfg.as_ref().map(|c| c.edges.len()).unwrap_or(0);

    let title = format!(
        " ◈ CFG: {}  @{:#010x}  [{} blocks, {} edges]  \
         h/l:←→  j/k:↑↓  g:reset  Esc:back to disasm  v:rebuild ",
        func_name, func_addr, block_count, edge_count
    );
    let block = styled_block(&title, CLR_ACCENT2);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let canvas_w = inner.width  as usize;
    let canvas_h = inner.height as usize;

    // Build canvas on first render OR when terminal is resized
    if app.cfg.is_some() && (
        app.cfg_canvas.is_none()
        || app.cfg_canvas_w != canvas_w
        || app.cfg_canvas_h != canvas_h
    ) {
        app.rebuild_cfg_canvas(canvas_w, canvas_h);
    }

    // Now render
    let canvas = match app.cfg_canvas {
        Some(ref c) => c,
        None => {
            f.render_widget(
                Paragraph::new(Span::styled(
                    "  No CFG data — press [v] on a function in the Disasm panel.",
                    Style::default().fg(CLR_DIM),
                )),
                inner,
            );
            return;
        }
    };

    let sx = app.cfg_scroll_x.max(0) as usize;
    let sy = app.cfg_scroll_y.max(0) as usize;

    // Reserve bottom 2 rows for legend
    let render_h = canvas_h.saturating_sub(2);

    // ── Viewport render ──────────────────────────────────────────────────
    let visible_rows = render_h.min(canvas.height.saturating_sub(sy));
    let visible_cols = canvas_w.min(canvas.width.saturating_sub(sx));

    let lines: Vec<Line> = (0..visible_rows).map(|screen_row| {
        let canvas_row = sy + screen_row;
        if canvas_row >= canvas.height { return Line::from(""); }
        let row_cells = &canvas.cells[canvas_row];

        let mut spans: Vec<Span> = vec![];
        let mut run_text  = String::new();
        let mut run_color = C::Reset;

        let end_cx = (sx + visible_cols).min(row_cells.len());
        for cx in sx..end_cx {
            let cell  = &row_cells[cx];
            let tcol  = cell_to_color(cell.color);
            if tcol == run_color {
                run_text.push(cell.ch);
            } else {
                if !run_text.is_empty() {
                    spans.push(Span::styled(run_text.clone(),
                        Style::default().fg(run_color)));
                    run_text.clear();
                }
                run_color = tcol;
                run_text.push(cell.ch);
            }
        }
        if !run_text.is_empty() {
            spans.push(Span::styled(run_text, Style::default().fg(run_color)));
        }
        Line::from(spans)
    }).collect();

    // Render area: all but last 2 rows
    let view_area = Rect { x: inner.x, y: inner.y, width: inner.width, height: render_h as u16 };
    f.render_widget(Paragraph::new(lines), view_area);

    // ── Legend ───────────────────────────────────────────────────────────
    let legend_area = Rect {
        x: inner.x, y: inner.y + render_h as u16,
        width: inner.width, height: 2,
    };
    let scroll_info = format!(
        " scroll ({},{})  canvas {}×{}  ",
        sx, sy, canvas.width, canvas.height
    );
    let legend = Line::from(vec![
        Span::styled("  ─ ", Style::default().fg(C::Rgb(80, 220, 120))),
        Span::styled("True(taken)  ", Style::default().fg(CLR_DIM)),
        Span::styled("─ ", Style::default().fg(C::Rgb(255, 100, 100))),
        Span::styled("False(fall)  ", Style::default().fg(CLR_DIM)),
        Span::styled("─ ", Style::default().fg(C::Rgb(120, 160, 255))),
        Span::styled("Unconditional  ", Style::default().fg(CLR_DIM)),
        Span::styled("╔ ", Style::default().fg(C::Rgb(80, 220, 120))),
        Span::styled("Entry  ", Style::default().fg(CLR_DIM)),
        Span::styled("╔ ", Style::default().fg(C::Rgb(255, 100, 100))),
        Span::styled("Ret  ", Style::default().fg(CLR_DIM)),
        Span::styled("╔ ", Style::default().fg(C::Rgb(255, 210, 60))),
        Span::styled("Cond  ", Style::default().fg(CLR_DIM)),
        Span::styled(&scroll_info, Style::default().fg(CLR_DIM)),
    ]);
    f.render_widget(Paragraph::new(legend)
        .style(Style::default().bg(CLR_PANEL2)), legend_area);

    // ── Scrollbars ───────────────────────────────────────────────────────
    if canvas.height > render_h {
        let mut vsb = ScrollbarState::new(canvas.height.saturating_sub(render_h)).position(sy);
        f.render_stateful_widget(Scrollbar::new(ScrollbarOrientation::VerticalRight), area, &mut vsb);
    }
    if canvas.width > canvas_w {
        let mut hsb = ScrollbarState::new(canvas.width.saturating_sub(canvas_w)).position(sx);
        f.render_stateful_widget(Scrollbar::new(ScrollbarOrientation::HorizontalBottom), area, &mut hsb);
    }
}

fn cell_to_color(c: CellColor) -> ratatui::style::Color {
    use ratatui::style::Color as C;
    match c {
        CellColor::Bg       => CLR_PANEL,
        CellColor::BoxEntry => C::Rgb(80,  220, 120),
        CellColor::BoxExit  => C::Rgb(255, 100, 100),
        CellColor::BoxCond  => C::Rgb(255, 210,  60),
        CellColor::BoxNormal=> C::Rgb(80,  130, 200),
        CellColor::EdgeTrue  => C::Rgb(80,  220, 120),
        CellColor::EdgeFalse => C::Rgb(255, 100, 100),
        CellColor::EdgeUncond=> C::Rgb(120, 160, 255),
        CellColor::ArrTrue   => C::Rgb(80,  255, 120),
        CellColor::ArrFalse  => C::Rgb(255, 140, 140),
        CellColor::ArrUncond => C::Rgb(160, 200, 255),
        CellColor::TxtHdr    => C::Rgb(220, 230, 255),
        CellColor::TxtAddr   => CLR_ADDR,
        CellColor::TxtCall   => CLR_CALL,
        CellColor::TxtJump   => CLR_JUMP,
        CellColor::TxtRet    => CLR_RET,
        CellColor::TxtNorm   => CLR_MNE,
        CellColor::TxtOp     => CLR_FG,
        CellColor::TxtDim    => CLR_DIM,
    }
}
