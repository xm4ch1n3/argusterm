use crate::state::{CveEntry, SortMode};

fn matches(entry: &CveEntry, query: &str) -> bool {
    if matches!(
        entry.content_type.as_deref(),
        Some("promotional" | "irrelevant")
    ) {
        return false;
    }
    if query.is_empty() {
        return true;
    }
    let q = query.to_lowercase();
    entry.id.to_lowercase().contains(&q)
        || entry.title.to_lowercase().contains(&q)
        || entry.description.to_lowercase().contains(&q)
        || entry.source.label().to_lowercase().contains(&q)
}

pub fn apply(entries: &[CveEntry], query: &str, sort: SortMode) -> Vec<usize> {
    let mut idx: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| matches(e, query))
        .map(|(i, _)| i)
        .collect();
    match sort {
        SortMode::None => {}
        SortMode::ScoreDesc | SortMode::ScoreAsc => {
            idx.sort_by(|&a, &b| {
                let cmp = entries[a]
                    .relevance_score
                    .unwrap_or(-1.0)
                    .partial_cmp(&entries[b].relevance_score.unwrap_or(-1.0))
                    .unwrap_or(std::cmp::Ordering::Equal);
                if matches!(sort, SortMode::ScoreDesc) {
                    cmp.reverse()
                } else {
                    cmp
                }
            });
        }
        SortMode::DateDesc => idx.sort_by(|&a, &b| entries[b].published.cmp(&entries[a].published)),
        SortMode::DateAsc => idx.sort_by(|&a, &b| entries[a].published.cmp(&entries[b].published)),
    }
    idx
}
