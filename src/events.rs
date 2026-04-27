use crate::app::{App, DisasmView, InputMode, Tab};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use std::time::Duration;

pub fn handle_events(app: &mut App) -> Result<bool> {
    if event::poll(Duration::from_millis(50))? {
        if let Event::Key(key) = event::read()? {
            if app.show_popup {
                app.show_popup = false;
                return Ok(false);
            }
            match app.input_mode {
                InputMode::Search => handle_search(app, key),
                InputMode::Normal => { if handle_normal(app, key)? { return Ok(true); } }
            }
        }
    }
    Ok(false)
}

fn handle_normal(app: &mut App, key: crossterm::event::KeyEvent) -> Result<bool> {
    // Esc — back navigation or cancel search
    if key.code == KeyCode::Esc {
        if app.active_tab == Tab::Static && (
            app.disasm_view == DisasmView::FunctionDetail ||
            app.disasm_view == DisasmView::CfgView
        ) {
            app.back_to_func_list();
            return Ok(false);
        }
        if app.input_mode == InputMode::Search {
            app.input_mode = InputMode::Normal;
            return Ok(false);
        }
    }

    // Enter — open function detail
    if key.code == KeyCode::Enter && app.active_tab == Tab::Static {
        app.enter_func();
        return Ok(false);
    }

    // 'v' — open CFG view for selected / currently viewed function
    if key.code == KeyCode::Char('v') && app.active_tab == Tab::Static {
        match app.disasm_view {
            DisasmView::FunctionList => {
                // Select the highlighted function first, then open CFG
                app.enter_func();           // sets selected_func + switches to FunctionDetail
                app.open_cfg(0, 0);         // canvas built lazily on first render
            }
            DisasmView::FunctionDetail | DisasmView::CfgView => {
                // Already have a selected function — open/rebuild CFG
                app.cfg_canvas    = None;   // force rebuild on next render
                app.cfg_canvas_w  = 0;
                app.open_cfg(0, 0);
            }
        }
        return Ok(false);
    }

    // CFG horizontal pan: h = left, l = right
    if app.active_tab == Tab::Static && app.disasm_view == DisasmView::CfgView {
        match key.code {
            KeyCode::Char('h') | KeyCode::Left  => { app.scroll_left();  return Ok(false); }
            KeyCode::Char('l') | KeyCode::Right => { app.scroll_right(); return Ok(false); }
            _ => {}
        }
    }

    match (key.modifiers, key.code) {
        (_, KeyCode::Char('q')) | (_, KeyCode::Char('Q')) => return Ok(true),
        (KeyModifiers::CONTROL, KeyCode::Char('c')) => return Ok(true),

        // Tab navigation
        (_, KeyCode::Tab)    => app.next_tab(),
        (_, KeyCode::BackTab) => app.prev_tab(),
        (_, KeyCode::Char('1')) => app.active_tab = Tab::Dashboard,
        (_, KeyCode::Char('2')) => { app.active_tab = Tab::Static; }
        (_, KeyCode::Char('3')) => app.active_tab = Tab::Dynamic,
        (_, KeyCode::Char('4')) => app.active_tab = Tab::Strings,
        (_, KeyCode::Char('5')) => app.active_tab = Tab::Hex,
        (_, KeyCode::Char('6')) => app.active_tab = Tab::Symbols,
        (_, KeyCode::Char('7')) => app.active_tab = Tab::Sections,
        (_, KeyCode::Char('8')) => app.active_tab = Tab::Imports,
        (_, KeyCode::Char('9')) => app.active_tab = Tab::Entropy,
        (_, KeyCode::Char('0')) => app.active_tab = Tab::Help,

        // Scroll
        (_, KeyCode::Down) | (_, KeyCode::Char('j')) => app.scroll_down(),
        (_, KeyCode::Up)   | (_, KeyCode::Char('k')) => app.scroll_up(),
        (_, KeyCode::PageDown) | (_, KeyCode::Char('d')) => app.page_down(),
        (_, KeyCode::PageUp)   | (_, KeyCode::Char('u')) => app.page_up(),
        (_, KeyCode::Home) | (_, KeyCode::Char('g')) => app.go_top(),

        // Search
        (_, KeyCode::Char('/')) => {
            app.input_mode = InputMode::Search;
            // For disasm panel, search filters function list
            if app.active_tab == Tab::Static {
                app.func_search_query.clear();
            } else {
                app.search_query.clear();
            }
        }

        // Dynamic analysis
        (_, KeyCode::Char('r')) if app.active_tab == Tab::Dynamic => run_dynamic(app),

        // Info popup
        (_, KeyCode::Char('e')) => show_info_popup(app),

        // Open help
        (_, KeyCode::Char('?')) | (_, KeyCode::F(1)) => app.active_tab = Tab::Help,

        // Open file info
        (_, KeyCode::Char('o')) => {
            app.show_popup = true;
            app.popup_title = "Open a Binary".into();
            app.popup_content = vec![
                "Pass the binary as the first argument:".into(),
                "".into(),
                "  revetui /bin/ls".into(),
                "  revetui /usr/sbin/sshd".into(),
                "  revetui ./malware.elf".into(),
                "  revetui ./binary --dynamic".into(),
                "".into(),
                "Press any key to close.".into(),
            ];
        }

        _ => {}
    }
    Ok(false)
}

fn handle_search(app: &mut App, key: crossterm::event::KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Enter => {
            app.input_mode = InputMode::Normal;
            if app.active_tab == Tab::Static {
                app.func_list_scroll = 0; // reset cursor when search changes
                if !app.func_search_query.is_empty() {
                    app.status_msg = format!("Filter: \"{}\" | Esc to clear", app.func_search_query);
                }
            } else if !app.search_query.is_empty() {
                app.status_msg = format!("Filter: \"{}\" | Esc to clear", app.search_query);
            }
        }
        KeyCode::Backspace => {
            if app.active_tab == Tab::Static { app.func_search_query.pop(); }
            else { app.search_query.pop(); }
        }
        KeyCode::Char(c) => {
            if app.active_tab == Tab::Static { app.func_search_query.push(c); }
            else { app.search_query.push(c); }
        }
        _ => {}
    }
}

fn run_dynamic(app: &mut App) {
    if let Some(ref path) = app.file_path.clone() {
        app.status_msg = "Running dynamic analysis tools…".into();
        let analyzer = crate::dynamic::DynamicAnalyzer::new(path);
        app.dynamic_results = analyzer.run_all();
        app.status_msg = format!("Dynamic analysis complete — {} tools ran", app.dynamic_results.len());
        app.log.push("[+] Dynamic analysis complete".into());
    } else {
        app.status_msg = "No binary loaded.".into();
    }
}

fn show_info_popup(app: &mut App) {
    if let Some(ref info) = app.binary_info.clone() {
        app.show_popup    = true;
        app.popup_title   = "Binary Summary".into();
        app.popup_content = vec![
            format!("File:          {}", info.path),
            format!("Type:          {}", info.file_type),
            format!("Architecture:  {} ({}-bit {})", info.architecture, info.bits, info.endian),
            format!("Entry Point:   {:#010x}", info.entry_point),
            format!("Size:          {}", crate::utils::fmt_size(info.file_size)),
            String::new(),
            format!("MD5:           {}", info.md5),
            format!("SHA256:        {}", info.sha256),
            String::new(),
            format!("PIE:           {}", yn(info.is_pie)),
            format!("NX / DEP:      {}", yn(info.has_nx)),
            format!("Stack Canary:  {}", yn(info.has_canary)),
            format!("RELRO:         {}", yn(info.has_relro)),
            format!("Stripped:      {}", if info.is_stripped { "Yes" } else { "No" }),
            String::new(),
            format!("Compiler:      {}", info.compiler_hint),
            format!("Packer:        {}", info.packer_hint.as_deref().unwrap_or("None")),
            String::new(),
            "Press any key to close.".into(),
        ];
    }
}

fn yn(b: bool) -> &'static str { if b { "Yes ✓" } else { "No  ✗" } }
