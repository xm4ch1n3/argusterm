use std::sync::Arc;
use std::time::Duration;

use minijinja::Environment;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Semaphore};

use crate::db::Db;
use crate::state::{CveEntry, DiagramConfig, FeedSource, LlmConfig, ScraperConfig};
use crate::tui::{AppEvent, LlmUpdate};



fn load_templates() -> Environment<'static> {
    let mut env = Environment::new();
    for (name, src) in [
        ("triage_system", include_str!("../../prompts/triage_system.j2")),
        ("triage_user", include_str!("../../prompts/triage_user.j2")),
        ("extract_ids", include_str!("../../prompts/extract_ids.j2")),
        ("pick_ref", include_str!("../../prompts/pick_ref.j2")),
    ] { env.add_template(name, src).unwrap_or_else(|_| panic!("failed to load {name}")); }
    env
}

const TRIAGE_SCHEMA: &str = include_str!("../../prompts/triage_schema.json");
const EXTRACT_IDS_SCHEMA: &str = include_str!("../../prompts/extract_ids_schema.json");
const PICK_REF_SCHEMA: &str = include_str!("../../prompts/pick_ref_schema.json");

#[derive(Deserialize)]
struct ApiResponse { content: Vec<ContentBlock> }

#[derive(Deserialize)]
struct ContentBlock { text: Option<String> }

#[derive(Deserialize)]
struct TriageResult {
    content_type: String,
    relevance_score: f32,
    severity: String,
    summary: String,
    dot_diagram: String,
    cve_ids: Vec<String>,
}

#[derive(Deserialize)]
struct ExtractIds { cve_ids: Vec<String> }

// NOTE: rationale is declared BEFORE url in the schema so that the decoder emits reasoning
// tokens first and the url field is conditioned on them. Do not reorder.
#[derive(Deserialize)]
struct PickRef { rationale: String, url: Option<String> }

// Shared runtime deps for the triage pipeline. Bundled so every function takes `&LlmDeps`
// instead of 6-9 loose parameters. Held in `Arc<LlmDeps>` by `triage_loop` so each spawned
// task only clones one pointer per entry. `db` is a separate SQLite connection (not shared
// with main's handle) wrapped in a std Mutex for the CVE-hop cache lookups; SQLite queries
// are fast enough that a blocking mutex over the sync Connection is fine inside tokio tasks
// as long as we don't hold the guard across await points.
struct LlmDeps {
    client: reqwest::Client,
    env: Environment<'static>,
    api_key: String,
    scraper_key: Option<String>,
    model_extract: String,
    model_summarize: String,
    graph_easy_bin: String,
    perl5lib: String,
    db: std::sync::Mutex<Db>,
}

// NOTE: append-only per-phase log at .argusterm/triage.log so you can `tail -f` it to watch
// the 5-phase pipeline live. Silent if the file can't be opened; never blocks triage.
fn tlog(entry_id: &str, phase: &str, detail: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(".argusterm/triage.log") {
        let _ = writeln!(f, "{} {} {:8} {}", chrono::Utc::now().format("%H:%M:%S"), entry_id, phase, detail);
    }
}

async fn scrape_url(client: &reqwest::Client, api_key: &str, url: &str) -> anyhow::Result<String> {
    // NOTE: 10000 chars per result is the SINGLE truncation point in the entire pipeline —
    // downstream LLM calls pass the scraped content through unmodified. Keeping the cap at
    // Parallel.ai bounds cost/memory/backend work in one place. The 90s per-request timeout
    // tolerates Parallel.ai's per-URL stochastic slowness (some URLs reproducibly take 30-60s).
    let resp = client
        .post("https://api.parallel.ai/v1beta/extract")
        .timeout(Duration::from_secs(90))
        .header("x-api-key", api_key)
        .json(&json!({
            "urls": [url],
            "objective": "Extract the full text of this security advisory, vulnerability report, or cybersecurity news article. Include any CVE numbers, affected products, and technical details.",
            "full_content": {"max_chars_per_result": 10000},
        }))
        .send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Parallel.ai {}", resp.status());
    }
    let body: Value = resp.json().await?;
    body["results"].get(0)
        .and_then(|r| r["full_content"].as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("no content from Parallel.ai"))
}

async fn render_dot(dot: &str, graph_easy_bin: &str, perl5lib: &str) -> anyhow::Result<String> {
    let mut child = tokio::process::Command::new(graph_easy_bin)
        .args(["--from=dot", "--as=ascii"]).env("PERL5LIB", perl5lib)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(dot.as_bytes()).await?;
    }
    let output = child.wait_with_output().await?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        anyhow::bail!("graph-easy: {}", String::from_utf8_lossy(&output.stderr))
    }
}

async fn call_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client, api_key: &str, model: &str,
    system: &str, user: &str, schema_src: &str, max_tokens: u32,
) -> anyhow::Result<T> {
    let mut body = json!({
        "model": model, "max_tokens": max_tokens, "system": system,
        "messages": [{"role": "user", "content": user}],
        "output_config": {"format": {"type": "json_schema", "schema": serde_json::from_str::<Value>(schema_src)?}},
    });
    // Adaptive thinking is only supported on Sonnet/Opus 4.6 — Haiku 4.5 hard-rejects it.
    if !model.contains("haiku") { body["thinking"] = json!({"type": "adaptive"}); }
    let resp = client.post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&body).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("API {}: {}", resp.status(), resp.text().await?);
    }
    let api: ApiResponse = resp.json().await?;
    // NOTE: use find_map not first() — when thinking fires, content[0] is a thinking block
    // with no text field, and the JSON payload lives in a later text block.
    let text = api.content.iter().find_map(|b| b.text.as_deref()).unwrap_or("{}");
    Ok(serde_json::from_str(text)?)
}

fn nvd_url(cve_id: &str) -> String { format!("https://nvd.nist.gov/vuln/detail/{cve_id}") }

async fn extract_ids(
    deps: &LlmDeps, entry_id: &str, title: &str, description: &str, content: Option<&str>,
) -> Vec<String> {
    let user = deps.env.get_template("extract_ids").expect("missing extract_ids")
        .render(minijinja::context! { title => title, description => description, content => content })
        .expect("failed to render extract_ids");
    match call_json::<ExtractIds>(&deps.client, &deps.api_key, &deps.model_extract, "", &user, EXTRACT_IDS_SCHEMA, 256).await {
        Ok(o) => o.cve_ids,
        Err(e) => { tlog(entry_id, "ids_err", &format!("{e:#}")); Vec::new() }
    }
}

async fn pick_ref(deps: &LlmDeps, entry_id: &str, nvd_content: &str) -> Option<PickRef> {
    let user = deps.env.get_template("pick_ref").expect("missing pick_ref")
        .render(minijinja::context! { nvd_content => nvd_content })
        .expect("failed to render pick_ref");
    match call_json::<PickRef>(&deps.client, &deps.api_key, &deps.model_extract, "", &user, PICK_REF_SCHEMA, 512).await {
        Ok(p) => Some(p),
        Err(e) => { tlog(entry_id, "pick_err", &format!("{e:#}")); None }
    }
}

async fn summarize(deps: &LlmDeps, entry: &CveEntry, content: &str) -> anyhow::Result<TriageResult> {
    let system_prompt = deps.env.get_template("triage_system").expect("missing triage_system")
        .render(minijinja::context!()).expect("failed to render triage_system");
    let user_msg = deps.env.get_template("triage_user").expect("missing triage_user")
        .render(minijinja::context! {
            entry_id => &entry.id, entry_title => &entry.title, entry_content => content,
        }).expect("failed to render triage_user");
    call_json::<TriageResult>(&deps.client, &deps.api_key, &deps.model_summarize, &system_prompt, &user_msg, TRIAGE_SCHEMA, 8192).await
}

async fn triage_one(deps: &LlmDeps, entry: &CveEntry) -> anyhow::Result<(TriageResult, String, Option<String>)> {
    tlog(&entry.id, "start", entry.url.as_deref().unwrap_or("(no url)"));
    let scraper_key = deps.scraper_key.as_deref();

    // Phase 1: primary scrape of the RSS entry's URL.
    // - Cached:    reuse whatever we already stored in the DB.
    // - MSRC:      skip the scrape. Microsoft's update-guide pages are a client-rendered
    //              SPA that returns only navigation wrapper boilerplate (header, breadcrumbs,
    //              footer) with a "Not found" message in the body — no actual advisory text.
    //              The RSS title already carries the CVE id, and the NVD hop in phase 3
    //              supplies the real content.
    // - Fresh:     call Parallel.ai to scrape the URL.
    // - Otherwise: no URL or no scraper key — leave primary empty and let later phases run
    //              on whatever context is available.
    let (primary, note) = if let Some(cached) = entry.scraped_content.as_deref() {
        (Some(cached.to_string()), "cached")
    } else if matches!(entry.source, FeedSource::Microsoft) {
        (None, "skipped (MSRC SPA)")
    } else if let (Some(url), Some(key)) = (entry.url.as_deref(), scraper_key) {
        (scrape_url(&deps.client, key, url).await.ok(), "fresh")
    } else {
        (None, "unavailable")
    };
    tlog(&entry.id, "primary", &format!("{} chars ({note})", primary.as_ref().map(|s| s.len()).unwrap_or(0)));
    let primary_ref = primary.as_deref().unwrap_or(&entry.description);

    // Phase 2: Haiku extracts CVE ids from the entry + primary content.
    let cve_ids = extract_ids(deps, &entry.id, &entry.title, &entry.description, Some(primary_ref)).await;
    tlog(&entry.id, "ids", &format!("{cve_ids:?}"));

    // Phase 3-5: hop chain — only runs for EXACTLY one CVE id. Multi-CVE entries (news
    // roundups, patch bundles, research chains) skip the chain since no single NVD page is
    // authoritative. Cached per CVE id: if a previous triage already picked + scraped a
    // reference URL for this CVE, reuse the cached content and skip the NVD scrape, pick_ref
    // call, and hop scrape entirely. NVD itself is NOT cached because CVE records mature
    // over time (Received → Awaiting Analysis → enriched), but the picked reference URL
    // is stable once chosen.
    let (nvd, hop) = match (cve_ids.as_slice(), scraper_key) {
        ([id], Some(key)) => {
            let cached = deps.db.lock().unwrap().get_cve_hop(id);
            if let Some((cached_url, cached_content)) = cached {
                tlog(&entry.id, "cache", &format!("hit cve={id} url={cached_url} ({} chars)", cached_content.len()));
                (None, Some(cached_content))
            } else {
                tlog(&entry.id, "cache", &format!("miss cve={id}"));
                let nvd = scrape_url(&deps.client, key, &nvd_url(id)).await.ok();
                tlog(&entry.id, "nvd", &format!("{} chars", nvd.as_ref().map(|s| s.len()).unwrap_or(0)));
                let pick = match nvd.as_deref() {
                    Some(md) => pick_ref(deps, &entry.id, md).await,
                    None => None,
                };
                tlog(&entry.id, "pick", &format!("url={:?} rationale={:?}",
                    pick.as_ref().and_then(|p| p.url.as_deref()),
                    pick.as_ref().map(|p| p.rationale.as_str())));
                let hop_url = pick.as_ref().and_then(|p| p.url.as_deref());
                let hop = match hop_url {
                    Some(u) => scrape_url(&deps.client, key, u).await.ok(),
                    None => None,
                };
                tlog(&entry.id, "hop", &format!("{} chars", hop.as_ref().map(|s| s.len()).unwrap_or(0)));
                if let (Some(u), Some(c)) = (hop_url, hop.as_deref()) {
                    let _ = deps.db.lock().unwrap().put_cve_hop(id, u, c);
                }
                (nvd, hop)
            }
        }
        _ => (None, None),
    };

    // Phase 5: concatenate all context and summarize.
    let ctx = [primary.as_deref(), nvd.as_deref(), hop.as_deref()]
        .into_iter().flatten().collect::<Vec<_>>().join("\n\n---\n\n");
    let ctx_final = if ctx.is_empty() { entry.description.clone() } else { ctx };
    tlog(&entry.id, "ctx", &format!("{} chars (primary+nvd+hop)", ctx_final.len()));

    let result = summarize(deps, entry, &ctx_final).await?;
    tlog(&entry.id, "done", &format!("type={} score={:.2} sev={}", result.content_type, result.relevance_score, result.severity));
    let diagram = render_dot(&result.dot_diagram, &deps.graph_easy_bin, &deps.perl5lib).await
        .unwrap_or_else(|e| format!("(diagram render failed: {e})"));
    let cached = (!ctx_final.is_empty() && ctx_final != entry.description).then_some(ctx_final);
    Ok((result, diagram, cached))
}

async fn triage_loop(
    tx: mpsc::UnboundedSender<AppEvent>,
    mut rx: mpsc::UnboundedReceiver<CveEntry>,
    deps: Arc<LlmDeps>,
    semaphore: Arc<Semaphore>,
) {
    while let Some(entry) = rx.recv().await {
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let deps = deps.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let evt = match triage_one(&deps, &entry).await {
                Ok((r, diagram, scraped)) => AppEvent::LlmResult(LlmUpdate {
                    entry_id: entry.id.clone(), content_type: r.content_type,
                    severity: r.severity, summary: r.summary, ascii_diagram: diagram,
                    relevance_score: r.relevance_score, cve_ids: r.cve_ids, scraped_content: scraped,
                }),
                Err(_) => AppEvent::Error,
            };
            let _ = tx.send(evt);
            drop(permit);
        });
    }
}

pub fn spawn(
    event_tx: mpsc::UnboundedSender<AppEvent>,
    llm: LlmConfig,
    scraper: Option<ScraperConfig>,
    diagram: DiagramConfig,
) -> mpsc::UnboundedSender<CveEntry> {
    let (entry_tx, entry_rx) = mpsc::unbounded_channel();
    let semaphore = Arc::new(Semaphore::new(llm.max_concurrent));
    let deps = Arc::new(LlmDeps {
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(60)).build().expect("failed to build HTTP client"),
        env: load_templates(),
        api_key: llm.api_key,
        scraper_key: scraper.map(|s| s.api_key),
        model_extract: llm.model_extract,
        model_summarize: llm.model_summarize,
        graph_easy_bin: diagram.graph_easy_bin,
        perl5lib: diagram.perl5lib,
        db: std::sync::Mutex::new(Db::open().expect("failed to open cache.db for llm")),
    });
    tokio::spawn(triage_loop(event_tx, entry_rx, deps, semaphore));
    entry_tx
}
