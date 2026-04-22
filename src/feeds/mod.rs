use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::Utc;
use tokio::sync::{Notify, mpsc};
use tokio::time;

use crate::state::{CveEntry, FeedSource};
use crate::tui::AppEvent;

fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    const ENT: &[(&str, &str)] = &[
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&nbsp;", " "),
        ("&quot;", "\""),
        ("&#39;", "'"),
        ("&apos;", "'"),
    ];
    ENT.iter().fold(out, |acc, (f, t)| acc.replace(f, t))
}

fn source_from_url(url: &str) -> FeedSource {
    const MAP: &[(&[&str], FeedSource)] = &[
        (&["nvd.nist.gov"], FeedSource::Nvd),
        (&["cisa.gov", "us-cert.gov"], FeedSource::Cisa),
        (&["github.com"], FeedSource::GitHub),
        (&["microsoft.com", "msrc.microsoft"], FeedSource::Microsoft),
        (&["cert.org", "cert.europa.eu"], FeedSource::Cert),
        (&["exploit-db.com"], FeedSource::Exploit),
        (
            &[
                "rapid7.com",
                "qualys.com",
                "sentinelone.com",
                "checkpoint.com",
                "securelist.com",
                "sophos.com",
            ],
            FeedSource::Research,
        ),
        (
            &[
                "schneier.com",
                "krebsonsecurity.com",
                "reddit.com",
                "isc.sans.edu",
                "nist.gov/blogs",
            ],
            FeedSource::Community,
        ),
    ];
    MAP.iter()
        .find(|(domains, _)| domains.iter().any(|d| url.contains(d)))
        .map(|(_, src)| *src)
        .unwrap_or(FeedSource::News)
}

fn entry_to_cve(entry: &feed_rs::model::Entry, source: FeedSource) -> CveEntry {
    let title = entry
        .title
        .as_ref()
        .map(|t| strip_html(&t.content))
        .unwrap_or_default();
    let description = entry
        .summary
        .as_ref()
        .map(|s| strip_html(&s.content))
        .or_else(|| {
            entry
                .content
                .as_ref()
                .and_then(|c| c.body.as_deref().map(strip_html))
        })
        .unwrap_or_default();
    CveEntry {
        id: entry.id.clone(),
        title,
        description,
        severity: None,
        // Many Atom feeds (and some RSS feeds) populate `updated` but not `published`.
        // Prefer `published`, fall back to `updated`, only use Utc::now() as last resort
        // so the in-memory and DB ordering reflects the real publication moment.
        published: entry.published.or(entry.updated).unwrap_or_else(Utc::now),
        // NOTE: provisional indexed_at — only the value attached to the first ingestion
        // (dedup in main.rs) is ever persisted or rendered; re-polls of the same id get
        // fresh values here but are discarded.
        indexed_at: Utc::now(),
        source,
        url: entry.links.first().map(|l| l.href.clone()),
        llm_summary: None,
        ascii_diagram: None,
        chokepoint_analysis: None,
        relevance_score: None,
        scraped_content: None,
        cve_ids: Vec::new(),
        content_type: None,
        mark: Default::default(),
    }
}

async fn fetch_and_parse(client: &reqwest::Client, url: &str) -> anyhow::Result<Vec<CveEntry>> {
    let bytes = client
        .get(url)
        .header(
            "Accept",
            "application/atom+xml, application/rss+xml, application/xml, text/xml",
        )
        .send()
        .await?
        .bytes()
        .await?;
    let feed = feed_rs::parser::parse(&bytes[..])?;
    let source = source_from_url(url);
    Ok(feed
        .entries
        .iter()
        .map(|e| entry_to_cve(e, source))
        .collect())
}

async fn poll_loop(
    tx: mpsc::UnboundedSender<AppEvent>,
    urls: Vec<String>,
    interval_secs: u64,
    paused: Arc<AtomicBool>,
    unpause: Arc<Notify>,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client");

    // NOTE: Initial fetch immediately, then on interval. Skip missed ticks so a slow
    // fetch pass (16 URLs × up to 30s timeout) doesn't queue back-to-back catch-up
    // polls once the loop outruns the interval.
    let mut ticker = time::interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        // NOTE: race the natural tick against an unpause wake so toggling `p` off triggers
        // an immediate poll instead of waiting up to `interval_secs` for the next tick.
        // When paused, a tick still fires — we skip it via the flag check below.
        tokio::select! {
            _ = ticker.tick() => {}
            _ = unpause.notified() => {}
        }
        if paused.load(Ordering::Relaxed) {
            continue;
        }
        for url in &urls {
            let evt = match fetch_and_parse(&client, url).await {
                Ok(entries) if !entries.is_empty() => AppEvent::NewEntries(entries),
                Ok(_) => continue,
                Err(_) => AppEvent::Error,
            };
            if tx.send(evt).is_err() {
                return;
            }
        }
    }
}

pub fn spawn(
    tx: mpsc::UnboundedSender<AppEvent>,
    urls: Vec<String>,
    interval_secs: u64,
    paused: Arc<AtomicBool>,
    unpause: Arc<Notify>,
) {
    tokio::spawn(poll_loop(tx, urls, interval_secs, paused, unpause));
}
