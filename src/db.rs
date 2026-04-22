use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

use crate::state::{CveEntry, FeedSource, Mark};

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open() -> anyhow::Result<Self> {
        std::fs::create_dir_all(".argusterm")?;
        let conn = Connection::open(".argusterm/cache.db")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'unknown', published TEXT NOT NULL,
                source TEXT NOT NULL, url TEXT, llm_summary TEXT, ascii_diagram TEXT,
                relevance_score REAL);
             CREATE TABLE IF NOT EXISTS cve_hop_cache (
                cve_id TEXT PRIMARY KEY, hop_url TEXT NOT NULL, hop_content TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS deleted_entries (id TEXT PRIMARY KEY)",
        )?;
        for col in [
            "scraped_content TEXT",
            "cve_ids TEXT DEFAULT '[]'",
            "content_type TEXT",
            "chokepoint_analysis TEXT",
            "indexed_at TEXT",
            "mark TEXT DEFAULT 'none'",
        ] {
            let _ = conn.execute(&format!("ALTER TABLE entries ADD COLUMN {col}"), []);
        }
        // NOTE: backfill legacy rows missing indexed_at by reusing `published` as a best-effort
        // proxy so pre-migration entries retain a coherent order instead of collapsing to a
        // single timestamp. A no-op once every row has a non-NULL indexed_at.
        let _ = conn.execute(
            "UPDATE entries SET indexed_at = published WHERE indexed_at IS NULL",
            [],
        );
        Ok(Self { conn })
    }

    // CVE-id-keyed cache of the Phase 4/5 hop result: the single reference URL the picker
    // chose for this CVE and the scraped content of that page. NVD is NOT cached (the record
    // matures over time) but the picked reference URL is stable once chosen. On cache hit,
    // triage_one skips the NVD scrape, the pick_ref call, and the hop scrape entirely.
    pub fn get_cve_hop(&self, cve_id: &str) -> Option<(String, String)> {
        self.conn
            .query_row(
                "SELECT hop_url, hop_content FROM cve_hop_cache WHERE cve_id = ?1",
                params![cve_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok()
    }

    pub fn put_cve_hop(
        &self,
        cve_id: &str,
        hop_url: &str,
        hop_content: &str,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO cve_hop_cache (cve_id, hop_url, hop_content) VALUES (?1, ?2, ?3)",
            params![cve_id, hop_url, hop_content],
        )?;
        Ok(())
    }

    pub fn load_since(&self, days: u64) -> anyhow::Result<Vec<CveEntry>> {
        let cutoff = (Utc::now() - chrono::Duration::days(days as i64)).to_rfc3339();
        let mut stmt = self.conn.prepare(
            "SELECT id, title, description, severity, published, source,
                    url, llm_summary, ascii_diagram, relevance_score,
                    scraped_content, cve_ids, content_type, chokepoint_analysis,
                    indexed_at, mark
             FROM entries WHERE published >= ?1 ORDER BY indexed_at DESC",
        )?;
        let rows = stmt.query_map(params![cutoff], |row| {
            let sev: String = row.get::<_, String>(3).unwrap_or_default();
            let cve_raw: String = row.get::<_, String>(11).unwrap_or_else(|_| "[]".into());
            let published = row
                .get::<_, String>(4)?
                .parse::<DateTime<Utc>>()
                .unwrap_or_else(|_| Utc::now());
            // NOTE: indexed_at is optional on legacy rows where the backfill may have failed;
            // fall back to `published` so the natural list order stays coherent.
            let indexed_at = row
                .get::<_, Option<String>>(14)?
                .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                .unwrap_or(published);
            Ok(CveEntry {
                id: row.get(0)?,
                title: row.get(1)?,
                description: row.get(2)?,
                severity: if sev.is_empty() || sev == "unknown" {
                    None
                } else {
                    Some(sev)
                },
                published,
                indexed_at,
                source: parse_source(&row.get::<_, String>(5)?),
                url: row.get(6)?,
                llm_summary: row.get(7)?,
                ascii_diagram: row.get(8)?,
                relevance_score: row.get(9)?,
                scraped_content: row.get(10)?,
                cve_ids: serde_json::from_str(&cve_raw).unwrap_or_default(),
                content_type: row.get(12)?,
                chokepoint_analysis: row.get(13)?,
                mark: parse_mark(&row.get::<_, String>(15).unwrap_or_else(|_| "none".into())),
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn upsert_entry(&self, e: &CveEntry) -> anyhow::Result<()> {
        // NOTE: `indexed_at` is deliberately omitted from the DO UPDATE clause so that
        // later upserts (LlmResult, refreshes) preserve the original first-ingest timestamp.
        self.conn.execute(
            "INSERT INTO entries (id, title, description, severity, published, source, url,
                                  llm_summary, ascii_diagram, relevance_score,
                                  scraped_content, cve_ids, content_type, chokepoint_analysis,
                                  indexed_at, mark)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
             ON CONFLICT(id) DO UPDATE SET
                title=excluded.title, description=excluded.description, severity=excluded.severity,
                published=excluded.published, source=excluded.source, url=excluded.url,
                llm_summary=excluded.llm_summary, ascii_diagram=excluded.ascii_diagram,
                relevance_score=excluded.relevance_score, scraped_content=excluded.scraped_content,
                cve_ids=excluded.cve_ids, content_type=excluded.content_type,
                chokepoint_analysis=excluded.chokepoint_analysis, mark=excluded.mark",
            params![
                e.id,
                e.title,
                e.description,
                e.severity.as_deref().unwrap_or("unknown"),
                e.published.to_rfc3339(),
                source_str(e.source),
                e.url,
                e.llm_summary,
                e.ascii_diagram,
                e.relevance_score,
                e.scraped_content,
                serde_json::to_string(&e.cve_ids)?,
                e.content_type,
                e.chokepoint_analysis,
                e.indexed_at.to_rfc3339(),
                mark_str(e.mark),
            ],
        )?;
        Ok(())
    }

    // Deleting an entry also writes a tombstone into `deleted_entries` so the next feed
    // poll's dedup check in main.rs can skip the id instead of re-ingesting it. Without the
    // tombstone, `x` would only stick until the next poll interval brought the item back.
    pub fn delete_entry(&self, id: &str) -> rusqlite::Result<usize> {
        self.conn
            .execute("DELETE FROM entries WHERE id=?1", params![id])?;
        self.conn.execute(
            "INSERT OR IGNORE INTO deleted_entries (id) VALUES (?1)",
            params![id],
        )
    }

    pub fn is_deleted(&self, id: &str) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM deleted_entries WHERE id=?1",
                params![id],
                |_| Ok(()),
            )
            .is_ok()
    }

    pub fn clear_llm(&self, id: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE entries SET llm_summary=NULL, ascii_diagram=NULL, relevance_score=NULL, cve_ids='[]', scraped_content=NULL, chokepoint_analysis=NULL WHERE id=?1",
            params![id],
        )?;
        Ok(())
    }
}

const MARKS: &[(Mark, &str)] = &[
    (Mark::None, "none"),
    (Mark::Read, "read"),
    (Mark::Bookmarked, "bookmarked"),
    (Mark::Skimmed, "skimmed"),
];
fn mark_str(m: Mark) -> &'static str {
    MARKS
        .iter()
        .find(|(v, _)| *v == m)
        .map(|(_, n)| *n)
        .unwrap_or("none")
}
fn parse_mark(s: &str) -> Mark {
    MARKS
        .iter()
        .find(|(_, n)| *n == s)
        .map(|(v, _)| *v)
        .unwrap_or(Mark::None)
}

const SOURCES: &[(FeedSource, &str)] = &[
    (FeedSource::Nvd, "nvd"),
    (FeedSource::Cisa, "cisa"),
    (FeedSource::GitHub, "github"),
    (FeedSource::Microsoft, "microsoft"),
    (FeedSource::Cert, "cert"),
    (FeedSource::Research, "research"),
    (FeedSource::Community, "community"),
    (FeedSource::Exploit, "exploit"),
    (FeedSource::News, "news"),
];
fn source_str(s: FeedSource) -> &'static str {
    SOURCES
        .iter()
        .find(|(f, _)| *f == s)
        .map(|(_, n)| *n)
        .unwrap_or("news")
}
fn parse_source(s: &str) -> FeedSource {
    SOURCES
        .iter()
        .find(|(_, n)| *n == s)
        .map(|(f, _)| *f)
        .unwrap_or(FeedSource::News)
}
