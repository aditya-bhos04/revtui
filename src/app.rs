use crate::analysis::*;
use crate::cfg::{Cfg, Canvas, build_cfg, render_cfg};
use crate::dynamic::DynamicResult;

#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Dashboard,
    Static,
    Dynamic,
    Strings,
    Hex,
    Symbols,
    Sections,
    Imports,
    Entropy,
    Help,
}

impl Tab {
    pub fn all() -> Vec<Tab> {
        vec![Tab::Dashboard, Tab::Static, Tab::Dynamic, Tab::Strings,
             Tab::Hex, Tab::Symbols, Tab::Sections, Tab::Imports, Tab::Entropy, Tab::Help]
    }
    pub fn label(&self) -> &str {
        match self {
            Tab::Dashboard => "Dashboard", Tab::Static   => "Disasm",
            Tab::Dynamic   => "Dynamic",   Tab::Strings  => "Strings",
            Tab::Hex       => "Hex",       Tab::Symbols  => "Symbols",
            Tab::Sections  => "Sections",  Tab::Imports  => "Imports",
            Tab::Entropy   => "Entropy",   Tab::Help     => "Help",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InputMode { Normal, Search }

/// Which sub-view is active in the disasm panel
#[derive(Debug, Clone, PartialEq)]
pub enum DisasmView {
    FunctionList,   // browse functions, press Enter to dive in
    FunctionDetail, // disasm of a single function, Esc to go back
    CfgView,        // control flow graph of a single function
}

pub struct App {
    pub file_path:    Option<String>,
    pub binary_info:  Option<BinaryInfo>,
    pub disassembly:  Vec<DisasmLine>,
    pub functions:    Vec<FunctionEntry>,
    pub strings:      Vec<ExtractedString>,
    pub hex_data:     Vec<u8>,
    pub sections:     Vec<SectionInfo>,
    pub symbols:      Vec<SymbolInfo>,
    pub imports:      Vec<ImportInfo>,
    pub entropy_blocks: Vec<EntropyBlock>,
    pub dynamic_results: Vec<DynamicResult>,

    pub active_tab:   Tab,
    pub input_mode:   InputMode,
    pub search_query: String,
    pub status_msg:   String,

    // Disasm panel state
    pub disasm_view:          DisasmView,
    pub func_list_scroll:     usize,    // selected row in function list
    pub func_detail_scroll:   usize,    // scroll offset in function detail
    pub selected_func:        Option<usize>,
    pub func_search_query:    String,

    // CFG state
    pub cfg:              Option<Cfg>,
    pub cfg_canvas:       Option<Canvas>,
    pub cfg_scroll_x:     i32,
    pub cfg_scroll_y:     i32,
    pub cfg_canvas_w:     usize,
    pub cfg_canvas_h:     usize,

    // Other panel scroll offsets
    pub strings_scroll:  usize,
    pub hex_scroll:      usize,
    pub symbols_scroll:  usize,
    pub sections_scroll: usize,
    pub imports_scroll:  usize,
    pub dynamic_scroll:  usize,

    pub show_popup:    bool,
    pub popup_title:   String,
    pub popup_content: Vec<String>,
    pub log:           Vec<String>,
}

impl App {
    pub fn new(file: Option<String>) -> Self {
        Self {
            file_path: file,
            binary_info: None,
            disassembly: vec![],
            functions: vec![],
            strings: vec![],
            hex_data: vec![],
            sections: vec![],
            symbols: vec![],
            imports: vec![],
            entropy_blocks: vec![],
            dynamic_results: vec![],
            active_tab: Tab::Dashboard,
            input_mode: InputMode::Normal,
            search_query: String::new(),
            status_msg: "Press ? for help | Tab to switch panels | o: open file info".into(),
            disasm_view: DisasmView::FunctionList,
            func_list_scroll: 0,
            func_detail_scroll: 0,
            selected_func: None,
            func_search_query: String::new(),
            cfg: None,
            cfg_canvas: None,
            cfg_scroll_x: 0,
            cfg_scroll_y: 0,
            cfg_canvas_w: 0,
            cfg_canvas_h: 0,
            strings_scroll: 0,
            hex_scroll: 0,
            symbols_scroll: 0,
            sections_scroll: 0,
            imports_scroll: 0,
            dynamic_scroll: 0,
            show_popup: false,
            popup_title: String::new(),
            popup_content: vec![],
            log: vec![],
        }
    }

    pub fn load_binary(&mut self, path: &str) {
        self.file_path = Some(path.to_string());
        self.status_msg = format!("Loading: {path}");
        self.log.push(format!("[*] Loading binary: {path}"));
        match crate::analysis::analyze_binary(path) {
            Ok(r) => {
                self.status_msg = format!(
                    "Loaded: {} | {} fns | {} strings | {} imports",
                    path, r.functions.len(), r.strings.len(), r.imports.len()
                );
                self.log.push(format!("[+] Analysis done: {} fns, {} disasm lines",
                    r.functions.len(), r.disasm.len()));
                self.binary_info   = Some(r.info);
                self.disassembly   = r.disasm;
                self.functions     = r.functions;
                self.strings       = r.strings;
                self.hex_data      = r.hex_data;
                self.sections      = r.sections;
                self.symbols       = r.symbols;
                self.imports       = r.imports;
                self.entropy_blocks = r.entropy;
            }
            Err(e) => {
                self.status_msg = format!("Error: {e}");
                self.log.push(format!("[-] Error: {e}"));
            }
        }
    }

    pub fn next_tab(&mut self) {
        let tabs = Tab::all();
        if let Some(i) = tabs.iter().position(|t| t == &self.active_tab) {
            self.active_tab = tabs[(i + 1) % tabs.len()].clone();
        }
    }

    pub fn prev_tab(&mut self) {
        let tabs = Tab::all();
        if let Some(i) = tabs.iter().position(|t| t == &self.active_tab) {
            self.active_tab = tabs[(i + tabs.len() - 1) % tabs.len()].clone();
        }
    }

    /// Filtered function list (by func_search_query)
    pub fn filtered_functions(&self) -> Vec<(usize, &FunctionEntry)> {
        if self.func_search_query.is_empty() {
            self.functions.iter().enumerate().collect()
        } else {
            let q = self.func_search_query.to_lowercase();
            self.functions.iter().enumerate()
                .filter(|(_, f)| f.name.to_lowercase().contains(&q) ||
                                 format!("{:#x}", f.address).contains(&q))
                .collect()
        }
    }

    /// Disasm lines for currently selected function
    pub fn current_func_disasm(&self) -> Vec<DisasmLine> {
        if let Some(idx) = self.selected_func {
            if let Some(func) = self.functions.get(idx) {
                return crate::analysis::disasm_for_function(&self.disassembly, func);
            }
        }
        vec![]
    }

    pub fn scroll_down(&mut self) {
        match self.active_tab {
            Tab::Static => match self.disasm_view {
                DisasmView::FunctionList   => self.func_list_scroll   = self.func_list_scroll.saturating_add(1),
                DisasmView::FunctionDetail => self.func_detail_scroll = self.func_detail_scroll.saturating_add(3),
                DisasmView::CfgView        => self.cfg_scroll_y       = self.cfg_scroll_y.saturating_add(3),
            },
            Tab::Strings  => self.strings_scroll  = self.strings_scroll.saturating_add(1),
            Tab::Hex      => self.hex_scroll       = self.hex_scroll.saturating_add(1),
            Tab::Symbols  => self.symbols_scroll  = self.symbols_scroll.saturating_add(1),
            Tab::Sections => self.sections_scroll = self.sections_scroll.saturating_add(1),
            Tab::Imports  => self.imports_scroll  = self.imports_scroll.saturating_add(1),
            Tab::Dynamic  => self.dynamic_scroll  = self.dynamic_scroll.saturating_add(1),
            _ => {}
        }
    }

    pub fn scroll_up(&mut self) {
        match self.active_tab {
            Tab::Static => match self.disasm_view {
                DisasmView::FunctionList   => self.func_list_scroll   = self.func_list_scroll.saturating_sub(1),
                DisasmView::FunctionDetail => self.func_detail_scroll = self.func_detail_scroll.saturating_sub(3),
                DisasmView::CfgView        => self.cfg_scroll_y       = self.cfg_scroll_y.saturating_sub(3),
            },
            Tab::Strings  => self.strings_scroll  = self.strings_scroll.saturating_sub(1),
            Tab::Hex      => self.hex_scroll       = self.hex_scroll.saturating_sub(1),
            Tab::Symbols  => self.symbols_scroll  = self.symbols_scroll.saturating_sub(1),
            Tab::Sections => self.sections_scroll = self.sections_scroll.saturating_sub(1),
            Tab::Imports  => self.imports_scroll  = self.imports_scroll.saturating_sub(1),
            Tab::Dynamic  => self.dynamic_scroll  = self.dynamic_scroll.saturating_sub(1),
            _ => {}
        }
    }

    pub fn page_down(&mut self) { for _ in 0..20 { self.scroll_down(); } }
    pub fn page_up(&mut self)   { for _ in 0..20 { self.scroll_up(); }   }

    pub fn scroll_left(&mut self)  { if self.disasm_view == DisasmView::CfgView { self.cfg_scroll_x = self.cfg_scroll_x.saturating_sub(6); } }
    pub fn scroll_right(&mut self) { if self.disasm_view == DisasmView::CfgView { self.cfg_scroll_x = self.cfg_scroll_x.saturating_add(6); } }

    pub fn go_top(&mut self) {
        match self.active_tab {
            Tab::Static => match self.disasm_view {
                DisasmView::FunctionList   => self.func_list_scroll   = 0,
                DisasmView::FunctionDetail => self.func_detail_scroll = 0,
                DisasmView::CfgView        => { self.cfg_scroll_x = 0; self.cfg_scroll_y = 0; }
            },
            Tab::Strings  => self.strings_scroll  = 0,
            Tab::Hex      => self.hex_scroll       = 0,
            Tab::Symbols  => self.symbols_scroll  = 0,
            Tab::Sections => self.sections_scroll = 0,
            Tab::Imports  => self.imports_scroll  = 0,
            Tab::Dynamic  => self.dynamic_scroll  = 0,
            _ => {}
        }
    }

    /// Open CFG view for the currently selected function (called with 'v').
    /// Builds the CFG immediately with a safe default canvas size.
    /// draw_cfg will rebuild with real terminal dimensions on first render.
    pub fn open_cfg(&mut self, _canvas_w: usize, _canvas_h: usize) {
        if let Some(idx) = self.selected_func {
            if let Some(func) = self.functions.get(idx) {
                let name = func.name.clone();
                let disasm = crate::analysis::disasm_for_function(&self.disassembly, func);
                let cfg = build_cfg(&disasm);

                // Build canvas NOW with a generous default so it's never None on first render.
                // draw_cfg will rebuild with actual terminal size if dimensions differ.
                let default_w = 220usize;
                let default_h = 80usize;
                let canvas = render_cfg(&cfg, default_w * 3, default_h * 3);

                self.cfg          = Some(cfg);
                self.cfg_canvas   = Some(canvas);
                self.cfg_scroll_x = 0;
                self.cfg_scroll_y = 0;
                self.cfg_canvas_w = default_w;  // will trigger resize on first real render
                self.cfg_canvas_h = default_h;
                self.disasm_view  = DisasmView::CfgView;
                self.status_msg   = format!(
                    "CFG: {}  |  h/l ←→ pan  j/k ↑↓ scroll  g:reset  v:rebuild  Esc:back",
                    name
                );
            }
        }
    }

    /// Called by draw_cfg when canvas needs rebuilding (first render or resize).
    pub fn rebuild_cfg_canvas(&mut self, canvas_w: usize, canvas_h: usize) {
        if let Some(ref cfg) = self.cfg {
            // Give the canvas 3× the viewport so there's room to pan
            let cw = (canvas_w * 3).max(400);
            let ch = (canvas_h * 3).max(120);
            self.cfg_canvas   = Some(render_cfg(cfg, cw, ch));
            self.cfg_canvas_w = canvas_w;
            self.cfg_canvas_h = canvas_h;
        }
    }

    /// Enter key: open selected function detail
    pub fn enter_func(&mut self) {
        if self.active_tab != Tab::Static { return; }
        if self.disasm_view == DisasmView::FunctionList {
            // Collect what we need before mutating self
            let maybe = {
                let filtered = self.filtered_functions();
                filtered.get(self.func_list_scroll).map(|(idx, _)| *idx)
            };
            if let Some(orig_idx) = maybe {
                let name = self.functions[orig_idx].name.clone();
                self.selected_func      = Some(orig_idx);
                self.func_detail_scroll = 0;
                self.disasm_view        = DisasmView::FunctionDetail;
                self.status_msg = format!("Viewing: {} | Esc → function list", name);
            }
        }
    }

    /// Esc key: back from detail/cfg to function list
    pub fn back_to_func_list(&mut self) {
        match self.disasm_view {
            DisasmView::FunctionDetail => {
                self.disasm_view = DisasmView::FunctionList;
                self.status_msg = "Functions | j/k:navigate | Enter:disasm | v:graph | /:filter".into();
            }
            DisasmView::CfgView => {
                // Esc from CFG goes back to FunctionDetail (or list if no func selected)
                if self.selected_func.is_some() {
                    self.disasm_view = DisasmView::FunctionDetail;
                    self.status_msg = "Disasm | Esc:back | v:graph view | j/k:scroll".into();
                } else {
                    self.disasm_view = DisasmView::FunctionList;
                }
                self.cfg = None;
                self.cfg_canvas = None;
            }
            _ => {}
        }
    }

    pub fn filtered_strings(&self) -> Vec<&ExtractedString> {
        if self.search_query.is_empty() { return self.strings.iter().collect(); }
        let q = self.search_query.to_lowercase();
        self.strings.iter().filter(|s| s.value.to_lowercase().contains(&q)).collect()
    }
    pub fn filtered_symbols(&self) -> Vec<&SymbolInfo> {
        if self.search_query.is_empty() { return self.symbols.iter().collect(); }
        let q = self.search_query.to_lowercase();
        self.symbols.iter().filter(|s| s.name.to_lowercase().contains(&q)).collect()
    }
    pub fn filtered_imports(&self) -> Vec<&ImportInfo> {
        if self.search_query.is_empty() { return self.imports.iter().collect(); }
        let q = self.search_query.to_lowercase();
        self.imports.iter().filter(|i| i.name.to_lowercase().contains(&q) || i.library.to_lowercase().contains(&q)).collect()
    }
}
