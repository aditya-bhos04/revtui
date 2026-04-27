mod app;
mod ui;
mod analysis;
mod cfg;
mod dynamic;
mod utils;
mod events;

use anyhow::Result;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let file_path = args.get(1).cloned();
    let dynamic_flag = args.iter().any(|a| a == "--dynamic" || a == "-d");

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("RevETUI — Advanced Reverse Engineering Terminal UI");
        println!("Usage: revetui [FILE] [--dynamic]");
        println!();
        println!("  FILE       Binary to analyze (ELF/PE)");
        println!("  --dynamic  Start in dynamic analysis tab");
        println!("  --help     Show this help");
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = app::App::new(file_path.clone());
    if let Some(ref f) = file_path {
        app.load_binary(f);
    }
    if dynamic_flag {
        app.active_tab = app::Tab::Dynamic;
    }

    let result = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {e}");
    }
    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut app::App,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, app))?;
        if events::handle_events(app)? {
            break;
        }
    }
    Ok(())
}
