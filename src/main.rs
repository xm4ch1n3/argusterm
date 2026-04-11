mod db;
mod doomflame;
mod feeds;
mod filters;
mod llm;
mod state;
mod tui;

use std::time::Duration;

use anyhow::Result;
use crossterm::event::KeyCode;
use tokio::sync::mpsc;

use crate::db::Db;
use crate::state::{AppState, Config, CveEntry, Pane};
use crate::tui::{AppEvent, Tui};

// NOTE: shared keybinding handler for actions available in both FeedList and Detail panes
fn handle_shared(
    code: KeyCode,
    state: &mut AppState,
    db: &Db,
    llm_tx: &mpsc::UnboundedSender<CveEntry>,
) -> bool {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => state.should_quit = true,
        KeyCode::Char('o') => {
            if let Some(url) = state
                .selected_entry_index()
                .and_then(|i| state.entries[i].url.as_deref())
            {
                let _ = std::process::Command::new("open").arg(url).spawn();
            }
        }
        KeyCode::Char('r') => {
            if let Some(i) = state.selected_entry_index() {
                let _ = db.clear_llm(&state.entries[i].id);
                let e = &mut state.entries[i];
                e.llm_summary = None;
                e.ascii_diagram = None;
                e.chokepoint_analysis = None;
                e.relevance_score = None;
                e.cve_ids.clear();
                e.scraped_content = None;
                let _ = llm_tx.send(state.entries[i].clone());
            }
        }
        KeyCode::Char('x') => {
            if let Some(i) = state.selected_entry_index() {
                let _ = db.delete_entry(&state.entries[i].id);
                state.entries.remove(i);
                state.refilter(false);
            }
        }
        KeyCode::Char('s') => {
            state.sort_mode = state.sort_mode.next();
            state.refilter(true);
        }
        KeyCode::Char('/') => state.active_pane = Pane::FilterBar,
        _ => return false,
    }
    true
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!(
            "argus — TUI security feed monitor\n\nUsage: argus [OPTIONS]\n\nOptions:\n  --nuke-db    Delete the SQLite cache and start fresh\n  -h, --help   Show this help"
        );
        return Ok(());
    }
    if args.iter().any(|a| a == "--nuke-db") {
        let path = ".argusterm/cache.db";
        println!(
            "{}",
            if std::path::Path::new(path).exists() {
                std::fs::remove_file(path)?;
                format!("Deleted {path}")
            } else {
                "No cache to delete".into()
            }
        );
        return Ok(());
    }

    let config = Config::load()?;
    let mut tui = Tui::new()?;
    tui.start(Duration::from_millis(config.tui.refresh_rate_ms));

    feeds::spawn(
        tui.event_tx(),
        config.feeds.urls,
        config.feeds.poll_interval_secs,
    );
    let llm_tx = llm::spawn(tui.event_tx(), config.llm, config.scraper, config.diagram);

    let db = db::Db::open()?;
    let days_lookback = config.filters.days_lookback;
    let ingest_cutoff = chrono::Utc::now() - chrono::Duration::days(days_lookback as i64);

    let mut state = AppState::default();
    for e in db.load_since(days_lookback)? {
        if e.llm_summary.is_none() {
            let _ = llm_tx.send(e.clone());
        }
        state.entries.push(e);
    }
    state.refilter(false);

    let mut needs_draw = true;
    while let Some(event) = tui.next().await {
        match event {
            AppEvent::Key(key) => {
                if state.active_pane == Pane::FilterBar {
                    match key.code {
                        KeyCode::Esc | KeyCode::Tab | KeyCode::Enter => {
                            state.active_pane = Pane::FeedList
                        }
                        KeyCode::Char(c) => {
                            state.filter_text.push(c);
                            state.refilter(true);
                        }
                        KeyCode::Backspace => {
                            state.filter_text.pop();
                            state.refilter(true);
                        }
                        _ => {}
                    }
                } else if state.active_pane == Pane::Detail && state.cve_bar_active {
                    match key.code {
                        KeyCode::Char('h') | KeyCode::Left => state.cve_bar_move(-1),
                        KeyCode::Char('l') | KeyCode::Right => state.cve_bar_move(1),
                        KeyCode::Char('o') => {
                            if let Some(cve_id) = state
                                .selected_entry_index()
                                .and_then(|i| state.entries[i].cve_ids.get(state.cve_bar_index))
                            {
                                let _ = std::process::Command::new("open")
                                    .arg(format!("https://nvd.nist.gov/vuln/detail/{cve_id}"))
                                    .spawn();
                            }
                        }
                        KeyCode::Esc | KeyCode::Char('c') => state.cve_bar_active = false,
                        _ => {}
                    }
                } else if state.active_pane == Pane::Detail {
                    if !handle_shared(key.code, &mut state, &db, &llm_tx) {
                        match key.code {
                            KeyCode::Down | KeyCode::Char('j') => state.scroll_detail(1, 0),
                            KeyCode::Up | KeyCode::Char('k') => state.scroll_detail(-1, 0),
                            KeyCode::Right | KeyCode::Char('l') => state.scroll_detail(0, 2),
                            KeyCode::Left | KeyCode::Char('h') => state.scroll_detail(0, -2),
                            KeyCode::Char('c') => {
                                if let Some(i) = state.selected_entry_index() {
                                    if !state.entries[i].cve_ids.is_empty() {
                                        state.cve_bar_active = true;
                                        state.cve_bar_index = 0;
                                    }
                                }
                            }
                            KeyCode::Tab => state.active_pane = Pane::FeedList,
                            _ => {}
                        }
                    }
                } else if state.pending_g {
                    state.pending_g = false;
                    if key.code == KeyCode::Char('g') {
                        state.select_first();
                    }
                } else if !handle_shared(key.code, &mut state, &db, &llm_tx) {
                    match key.code {
                        KeyCode::Down | KeyCode::Char('j') => state.select_delta(1),
                        KeyCode::Up | KeyCode::Char('k') => state.select_delta(-1),
                        KeyCode::Char('d') => state.select_delta(state.half()),
                        KeyCode::Char('u') => state.select_delta(-state.half()),
                        KeyCode::Char('g') => state.pending_g = true,
                        KeyCode::Char('G') => state.select_last(),
                        KeyCode::Tab => state.active_pane = Pane::Detail,
                        _ => {}
                    }
                }
                needs_draw = true;
            }
            AppEvent::Tick => {
                state.flame_left.tick_left();
                state.flame_right.tick_right();
                state.flame_top.tick_top();
                needs_draw = true;
            }
            AppEvent::NewEntries(entries) => {
                // NOTE: preserve selection by id — inserting in date-desc order shifts indices
                let selected_id = state
                    .selected_entry_index()
                    .map(|i| state.entries[i].id.clone());
                for e in entries {
                    if e.published < ingest_cutoff {
                        continue;
                    }
                    if db.is_deleted(&e.id) {
                        continue;
                    }
                    if !state.entries.iter().any(|x| x.id == e.id) {
                        let _ = db.upsert_entry(&e);
                        let _ = llm_tx.send(e.clone());
                        // NOTE: maintain published-desc invariant so new items appear at the top of the feed list
                        let pos = state.entries.partition_point(|x| x.published > e.published);
                        state.entries.insert(pos, e);
                    }
                }
                state.refilter(false);
                if let Some(id) = selected_id {
                    if let Some(pos) = state
                        .filtered
                        .iter()
                        .position(|&i| state.entries[i].id == id)
                    {
                        state.list_state.select(Some(pos));
                    }
                }
                needs_draw = true;
            }
            AppEvent::LlmResult(u) => {
                if let Some(entry) = state.entries.iter_mut().find(|e| e.id == u.entry_id) {
                    entry.content_type = Some(u.content_type);
                    entry.severity = if u.severity == "unknown" {
                        None
                    } else {
                        Some(u.severity)
                    };
                    entry.llm_summary = Some(u.summary);
                    entry.ascii_diagram = Some(u.ascii_diagram);
                    entry.chokepoint_analysis = Some(u.chokepoint_analysis);
                    entry.relevance_score = Some(u.relevance_score);
                    entry.cve_ids = u.cve_ids;
                    if u.scraped_content.is_some() {
                        entry.scraped_content = u.scraped_content;
                    }
                    let _ = db.upsert_entry(entry);
                }
                // NOTE: clamp CVE bar index if list shrank after re-triage
                if let Some(i) = state.selected_entry_index() {
                    let max = state.entries[i].cve_ids.len().saturating_sub(1);
                    state.cve_bar_index = state.cve_bar_index.min(max);
                }
                state.refilter(false);
                needs_draw = true;
            }
            AppEvent::Resize => needs_draw = true,
            AppEvent::Error => {}
        }
        if state.should_quit {
            break;
        }
        if needs_draw {
            tui.terminal_mut()
                .draw(|frame| crate::tui::render(frame, &mut state))?;
            needs_draw = false;
        }
    }
    tui.stop();
    Ok(())
}
