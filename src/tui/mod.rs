use std::time::Duration;

use crossterm::event::{EventStream, KeyEvent, KeyEventKind};
use futures::{FutureExt, StreamExt};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::{DefaultTerminal, Frame};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::state::{AppState, CveEntry, FeedSource, Pane};

#[derive(Debug)]
pub enum AppEvent {
    Key(KeyEvent),
    Tick,
    Resize,
    NewEntries(Vec<CveEntry>),
    LlmResult(LlmUpdate),
    Error,
}

#[derive(Debug)]
pub struct LlmUpdate {
    pub entry_id: String,
    pub content_type: String,
    pub severity: String,
    pub summary: String,
    pub ascii_diagram: String,
    pub relevance_score: f32,
    pub cve_ids: Vec<String>,
    pub scraped_content: Option<String>,
}

pub struct Tui {
    terminal: DefaultTerminal,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    event_rx: mpsc::UnboundedReceiver<AppEvent>,
    task: Option<JoinHandle<()>>,
    cancel: CancellationToken,
}

impl Tui {
    pub fn new() -> anyhow::Result<Self> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        Ok(Self {
            terminal: ratatui::init(),
            event_tx,
            event_rx,
            task: None,
            cancel: CancellationToken::new(),
        })
    }

    pub fn event_tx(&self) -> mpsc::UnboundedSender<AppEvent> {
        self.event_tx.clone()
    }
    pub fn terminal_mut(&mut self) -> &mut DefaultTerminal {
        &mut self.terminal
    }

    pub fn start(&mut self, tick_rate: Duration) {
        let tx = self.event_tx.clone();
        let cancel = self.cancel.clone();
        self.task = Some(tokio::spawn(async move {
            let mut reader = EventStream::new();
            let mut tick = tokio::time::interval(tick_rate);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let ct = reader.next().fuse();
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tick.tick() => { if tx.send(AppEvent::Tick).is_err() { break; } }
                    maybe = ct => match maybe {
                        Some(Ok(crossterm::event::Event::Key(key))) if key.kind == KeyEventKind::Press => {
                            if tx.send(AppEvent::Key(key)).is_err() { break; }
                        }
                        Some(Ok(crossterm::event::Event::Resize(_, _))) => {
                            if tx.send(AppEvent::Resize).is_err() { break; }
                        }
                        Some(Err(_)) => { if tx.send(AppEvent::Error).is_err() { break; } }
                        None => break,
                        _ => {}
                    }
                }
            }
        }));
    }

    pub async fn next(&mut self) -> Option<AppEvent> {
        self.event_rx.recv().await
    }
    pub fn stop(&mut self) {
        self.cancel.cancel();
        ratatui::restore();
    }
}

fn s(text: String, color: Color) -> Span<'static> {
    Span::styled(text, Style::default().fg(color))
}

fn source_color(s: FeedSource) -> Color {
    match s {
        FeedSource::Cisa => Color::Yellow,
        FeedSource::GitHub => Color::Cyan,
        FeedSource::Nvd => Color::Red,
        FeedSource::Microsoft => Color::Magenta,
        FeedSource::Cert => Color::LightYellow,
        FeedSource::Research => Color::LightGreen,
        FeedSource::Community => Color::LightCyan,
        FeedSource::Exploit => Color::LightRed,
        FeedSource::News => Color::Blue,
    }
}

fn severity_color(sev: Option<&str>) -> Color {
    match sev {
        Some("critical") => Color::Red,
        Some("high") => Color::LightRed,
        Some("medium") => Color::Yellow,
        Some("low") => Color::Green,
        _ => Color::DarkGray,
    }
}

fn score_color(score: f32) -> Color {
    let s = score.clamp(0.0, 1.0);
    Color::Rgb(((1.0 - s) * 255.0) as u8, (s * 255.0) as u8, 0)
}

fn word_wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.len() <= width {
            out.push(line.to_string());
            continue;
        }
        let mut cur = String::new();
        for word in line.split_whitespace() {
            if cur.is_empty() {
                cur = word.to_string();
            } else if cur.len() + 1 + word.len() <= width {
                cur.push(' ');
                cur.push_str(word);
            } else {
                out.push(cur);
                cur = word.to_string();
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
    }
    out
}

fn centered(area: Rect, h_pct: u16, v_pct: u16) -> Rect {
    let (hm, vm) = ((100 - h_pct) / 2, (100 - v_pct) / 2);
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(vm),
            Constraint::Percentage(v_pct),
            Constraint::Percentage(vm),
        ])
        .split(area)[1];
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(hm),
            Constraint::Percentage(h_pct),
            Constraint::Percentage(hm),
        ])
        .split(vert)[1]
}

fn border_block(title: &str, active: Pane, this: Pane, borders: Borders) -> Block<'_> {
    let color = if active == this {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    Block::default()
        .title(title)
        .borders(borders)
        .border_style(Style::default().fg(color))
}

pub fn render(frame: &mut Frame, state: &mut AppState) {
    let canvas = centered(frame.area(), 85, 90);
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(canvas);
    let outer = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(root[0]);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(outer[0]);

    // --- Feed list ---
    state.list_height = left[0].height.saturating_sub(2) as usize;
    let title_max = (outer[0].width as usize).saturating_sub(24);
    let left_borders = Borders::TOP | Borders::LEFT | Borders::BOTTOM;
    let feed_block = border_block(
        " CVE FEED ",
        state.active_pane,
        Pane::FeedList,
        left_borders,
    );

    let items: Vec<ListItem> = state
        .filtered
        .iter()
        .map(|&idx| &state.entries[idx])
        .map(|cve| {
            let score = if let Some(sc) = cve.relevance_score {
                s(format!("[{sc:.2}]"), score_color(sc))
            } else {
                s("[ -- ]".into(), Color::DarkGray)
            };
            let title: String = cve.title.chars().take(title_max).collect();
            ListItem::new(Line::from(vec![
                score,
                s(
                    format!(" {} ", cve.source.label()),
                    source_color(cve.source),
                ),
                s(
                    format!("{} ", cve.published.format("%m-%d")),
                    Color::DarkGray,
                ),
                Span::raw(title),
            ]))
        })
        .collect();

    if items.is_empty() {
        let empty = Paragraph::new("  No entries yet. Waiting for feeds...")
            .style(Style::default().fg(Color::DarkGray))
            .block(feed_block);
        frame.render_widget(empty, left[0]);
    } else {
        let list = List::new(items)
            .block(feed_block)
            .highlight_symbol("> ")
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Cyan),
            );
        frame.render_stateful_widget(list, left[0], &mut state.list_state);
    }

    // --- Filter bar ---
    let sort_label = state.sort_mode.label();
    let filter_title = if sort_label.is_empty() {
        format!(
            " FILTER ({}/{}) ",
            state.filtered.len(),
            state.entries.len()
        )
    } else {
        format!(
            " FILTER ({}/{}) [{}] ",
            state.filtered.len(),
            state.entries.len(),
            sort_label
        )
    };
    let filter_block = border_block(
        &filter_title,
        state.active_pane,
        Pane::FilterBar,
        left_borders,
    );
    let filter_display = match (
        state.filter_text.is_empty(),
        state.active_pane == Pane::FilterBar,
    ) {
        (true, true) => Span::styled("_", Style::default().fg(Color::Cyan)),
        (true, false) => Span::styled("/ to search...", Style::default().fg(Color::DarkGray)),
        (false, true) => Span::raw(format!("{}_", &state.filter_text)),
        (false, false) => Span::raw(&state.filter_text),
    };
    frame.render_widget(Paragraph::new(filter_display).block(filter_block), left[1]);

    // --- Detail pane ---
    let detail_block = border_block(" DETAIL ", state.active_pane, Pane::Detail, Borders::ALL);
    let dw = outer[1].width.saturating_sub(2) as usize;

    let detail_content = if let Some(cve) = state.selected_entry_index().map(|i| &state.entries[i])
    {
        if cve.llm_summary.is_some() {
            let sc = cve.relevance_score.unwrap_or(0.0);
            let mut lines = vec![Line::from(vec![
                Span::styled(
                    format!(" {sc:.2} "),
                    Style::default()
                        .fg(Color::Black)
                        .bg(score_color(sc))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                s(cve.source.label().into(), source_color(cve.source)),
                Span::raw(format!("  {}  ", cve.published.format("%Y-%m-%d"))),
                s(
                    cve.content_type.as_deref().unwrap_or("").into(),
                    Color::DarkGray,
                ),
                Span::raw("  "),
                s(
                    cve.severity.as_deref().unwrap_or("n/a").into(),
                    severity_color(cve.severity.as_deref()),
                ),
            ])];
            if !cve.cve_ids.is_empty() {
                lines.push(Line::from(
                    cve.cve_ids
                        .iter()
                        .enumerate()
                        .map(|(j, id)| {
                            if state.cve_bar_active && j == state.cve_bar_index {
                                Span::styled(
                                    format!(" {id} "),
                                    Style::default()
                                        .fg(Color::Black)
                                        .bg(Color::Cyan)
                                        .add_modifier(Modifier::BOLD),
                                )
                            } else {
                                s(format!(" {id} "), Color::DarkGray)
                            }
                        })
                        .collect::<Vec<_>>(),
                ));
            }
            lines.push(Line::from(""));
            for l in word_wrap(&cve.title, dw) {
                lines.push(Line::from(Span::styled(
                    l,
                    Style::default().add_modifier(Modifier::BOLD),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(s("── Summary ──".into(), Color::Yellow)));
            for l in word_wrap(cve.llm_summary.as_deref().unwrap_or(""), dw) {
                lines.push(Line::from(l));
            }
            if let Some(diagram) = &cve.ascii_diagram {
                lines.push(Line::from(""));
                lines.push(Line::from(s("── Diagram ──".into(), Color::Magenta)));
                for l in diagram.lines() {
                    lines.push(Line::from(l.to_string()));
                }
            }
            lines
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    &cve.title,
                    Style::default().add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(s("  Triaging...".into(), Color::DarkGray)),
            ]
        }
    } else {
        vec![
            Line::from(""),
            Line::from(s(
                "  Select an entry from the feed list".into(),
                Color::DarkGray,
            )),
        ]
    };

    frame.render_widget(
        Paragraph::new(detail_content)
            .block(detail_block)
            .scroll((state.detail_scroll, state.detail_hscroll)),
        outer[1],
    );

    // --- Status bar ---
    let nav = if state.cve_bar_active {
        "h/l: nav CVEs  o: open NVD  esc: back"
    } else if state.active_pane == Pane::Detail {
        "h/j/k/l: scroll  c: CVEs"
    } else {
        "j/k: navigate"
    };
    let (vis, total) = (state.filtered.len(), state.entries.len());
    let triaged = state
        .entries
        .iter()
        .filter(|e| e.llm_summary.is_some())
        .count();
    let llm = if triaged < total && total > 0 {
        format!(" | LLM: {triaged}/{total}")
    } else {
        String::new()
    };
    let esc_or_slash = if state.active_pane == Pane::FilterBar {
        "esc"
    } else {
        "/"
    };
    let status =
        format!(" {vis}/{total}{llm} | {nav} | s:sort o:open r:redo x:drop q tab {esc_or_slash}");
    frame.render_widget(Paragraph::new(s(status, Color::DarkGray)), root[1]);
}
