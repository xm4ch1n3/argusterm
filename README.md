# argusterm

<p align="center">
  <img src="artifacts/argus.jpg" height="249" alt="Argus — the all-seeing sentinel" />
  <img src="artifacts/cover.gif" height="249" alt="argusterm TUI" />
</p>

> **Disclaimer:** this is a personal project so some choices reflect that — e.g. using Anthropic / Parallel among others. Feel free to fork the project and adapt it to your needs.

Polls 16 RSS/Atom feeds, scrapes full article content, triages entries via a two-model LLM pipeline (Haiku for structured extraction, Sonnet for triage) with authoritative NVD enrichment for single-CVE entries, generates ASCII teaching diagrams that decompose each exploit into chokepoint dependencies (with `why` the catalyst works and `how` it operates in this case), and renders everything in a ratatui TUI with persistent SQLite caching.

## Architecture

```
RSS/Atom Feeds (16)
  → reqwest async polling · feed-rs parsing · HTML strip · dedup · date filter
    → Parallel.ai primary scrape of entry URL         (skipped for MSRC SPA pages)
      → Haiku llm_extract: extract_ids (structured JSON)
        → if exactly ONE CVE id, the hop chain fires:
            → Parallel.ai scrape nvd.nist.gov/vuln/detail/<id>
            → Haiku llm_extract: pick_ref               (one most-technical reference,
                                                         rationale-first structured JSON)
            → Parallel.ai scrape the chosen reference
        → Sonnet llm_summarize: triage (primary + nvd + hop concatenated)
          → content_type · relevance score · severity · summary · chokepoint_analysis
            · structured Diagram { nodes, edges } with why/how on each chokepoint
            → Rust builds DOT from the typed Diagram (word-wraps labels deterministically)
              → graph-easy: DOT → ASCII
                → SQLite cache → ratatui TUI
```

The pipeline is fail-open at every step: if any scrape, extraction, or hop fails, the summarize call still runs with whatever context is available (at minimum the RSS title + description). Multi-CVE entries (news roundups, patch bundles, research chains) skip the NVD hop chain entirely — enriching one CVE from a bundle would bias the summary — and summarize runs on the primary scrape alone.

## How Scoring Works

Each entry is scored 0.0–1.0 on how much it relates to **AI changing security**:

| Score Range | Meaning | Examples |
|---|---|---|
| **0.7–1.0** | Core AI-security | LLMs finding zero-days, AI-powered vuln research, attacks on ML systems, AI security tooling |
| **0.3–0.7** | Tangential | Traditional vulns in AI-adjacent software, AI policy/regulation |
| **0.0–0.3** | No AI connection | Standard CVEs, generic security news |

The LLM also classifies each entry as `cve`, `advisory`, `news`, `research`, `promotional`, or `irrelevant`. Entries classified as `promotional` or `irrelevant` are automatically hidden.

## Prerequisites

- **Rust** (edition 2024)
- **[Graph::Easy](https://metacpan.org/pod/Graph::Easy)** (Perl) — converts Graphviz DOT to ASCII diagrams
- **Anthropic API key** — used by both `llm_extract` (Haiku) and `llm_summarize` (Sonnet)
- **Parallel.ai API key** — strongly recommended; drives primary page scraping, NVD enrichment, and the reference hop. Without it the pipeline degrades to RSS-summary-only triage and diagrams will be thin.

### Install Graph::Easy

```bash
# via cpanm
cpanm Graph::Easy

# or via cpan
cpan Graph::Easy
```

## Build & Run

```bash
cargo install --path .
argus            # launch TUI
argus --nuke-db  # wipe SQLite cache and start fresh
argus --help     # show usage
```

## Configuration

```bash
cp config/argusterm.eg.toml config/argusterm.toml
```

Edit `config/argusterm.toml`:

```toml
[feeds]
poll_interval_secs = 300       # feed poll interval (seconds)

[llm]
model_extract = "claude-haiku-4-5-20251001"  # Haiku: fast structured extraction (CVE ids, ref URL picking)
model_summarize = "claude-sonnet-4-6"         # Sonnet: main triage — summary, chokepoint analysis, teaching diagram, scoring
api_key = "your-anthropic-api-key"
max_concurrent = 20                           # concurrent triage tasks

[scraper]
api_key = "your-parallel-ai-key"  # Parallel.ai key — recommended; the multi-hop enrichment
                                  # path and all NVD/reference scraping require it. Without
                                  # it, triage falls back to the RSS summary only.

[diagram]
graph_easy_bin = "/usr/local/bin/graph-easy"  # path to graph-easy binary
perl5lib = "/usr/local/lib/perl5"             # Perl5 lib path for Graph::Easy

[filters]
days_lookback = 7              # only show entries from the last N days

[tui]
refresh_rate_ms = 250          # TUI redraw interval (milliseconds)
```

The `days_lookback` setting controls both which cached entries are loaded on startup and which new feed entries are ingested. The DB retains all entries permanently — widening the window instantly surfaces older cached data.

## Keybindings

| Context | Keys |
|---|---|
| **Feed List** | `j`/`k` nav · `d`/`u` half-page · `gg`/`G` top/bottom |
| **Detail** | `j`/`k` vscroll · `h`/`l` hscroll · `c` enter CVE bar |
| **CVE Bar** | `h`/`l` nav · `o` open on NVD · `Esc` exit |
| **Filter Bar** | type to filter · `Backspace` delete · `Esc`/`Enter` exit |
| **Global** | `o` open URL · `r` re-triage · `x` delete (permanent) · `s` cycle sort · `/` filter · `Tab` cycle panes · `q`/`Esc` quit |

## Data Persistence

All state lives in `.argusterm/cache.db` (SQLite) across three tables:

- **`entries`** — every ingested feed item with its LLM triage output (summary, chokepoint analysis, ASCII diagram, score, CVE ids, scraped content). On restart, rows within `days_lookback` load instantly; only entries missing LLM results are re-triaged.
- **`cve_hop_cache`** — CVE-id-keyed cache of the reference URL the picker chose for each CVE and the scraped content of that page. When a single-CVE entry is triaged and the same CVE id has been seen before, the pipeline reuses the cached hop content and skips the NVD scrape, the `pick_ref` Haiku call, and the reference scrape entirely. Cross-feed CVE duplicates (e.g. the same kernel CVE showing up in MSRC *and* CISA) become cheap. NVD itself is intentionally not cached — the record matures over time — but the picked reference URL is stable once chosen.
- **`deleted_entries`** — tombstone table. Pressing `x` inserts the entry's id here in addition to removing it from `entries`, so the next feed poll's dedup check skips the id instead of re-ingesting it. Deletion is **permanent** across feed polls and app restarts. Recovery requires a manual `DELETE FROM deleted_entries WHERE id = '...'` if you hit `x` by mistake.

Pressing `r` on an entry clears all cached LLM output (summary, chokepoint analysis, diagram, score, CVE ids) **and** the scraped content used as input, so re-triage truly restarts the pipeline from scratch. The hop cache in `cve_hop_cache` is *not* cleared by `r` — if the entry has a single CVE id that's already in the cache, re-triage still reuses the cached hop. Nuke the DB with `argus --nuke-db` if you want a clean slate.

