//! Merge benchmark corpus and runner (decision 042; design P5 and N6 scale benchmarks).
//!
//! The corpus is generated, deterministic from a seed and synthetic: each case is a
//! base document of `nodes` nodes (sections with a label, a rich-text paragraph list
//! and page setup, and one identified bullet list) and two sides that each edit, insert
//! and delete a few nodes, fields and list items at random, so some cases overlap and
//! some do not. [`run`] merges every case under a policy with `converge_with_policy`
//! and measures the wall time per case. Numbers depend on the machine; record them with
//! the machine and the command, and claim nothing beyond what was measured.
use crate::{
    materializer::{DocumentState, MaterializedNode},
    merge_policy::{review, MergePolicy},
    repository::convergence::converge_with_policy,
    shared_checkpoint::Address,
};
use engine_shared::NodeId;
use serde::Serialize;
use serde_json::{json, Value};
use std::time::Instant;

/// SplitMix64: a small deterministic generator, enough for a synthetic corpus.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

fn id(n: u64) -> NodeId {
    // Crockford base32 accepts the hexadecimal digits, so this is ULID-shaped.
    NodeId(format!("01{n:024X}"))
}

fn paragraphs(words: &[String]) -> Value {
    json!({"type":"doc","content": words.iter().map(|w| json!({"type":"paragraph","content":[{"type":"text","text":w}]})).collect::<Vec<_>>()})
}

fn items(list: &[(u64, String)]) -> Value {
    json!({"type":"bulletList","content": list.iter().map(|(n, t)| json!({"type":"listItem","attrs":{"itemId":format!("i{n}")},"content":[{"type":"paragraph","content":[{"type":"text","text":t}]}]})).collect::<Vec<_>>()})
}

/// One three-way case.
pub struct Case {
    pub base: DocumentState,
    pub left: DocumentState,
    pub right: DocumentState,
}

fn base_state(rng: &mut Rng, nodes: u64) -> DocumentState {
    let mut state = DocumentState::default();
    let root = MaterializedNode {
        id: id(0),
        parent_id: None,
        node_type: "form".into(),
        pos: "a0".into(),
        var_name: None,
        deleted: false,
        current_fields: json!({"label":"Report","page_setup":{"size":"A4","margin":25}}),
    };
    state.nodes.insert(root.id.clone(), root);
    for n in 1..nodes.max(2) {
        let words: Vec<String> = (0..1 + rng.below(3))
            .map(|k| format!("Paragraph {k} of section {n}"))
            .collect();
        let mut fields = json!({"label": format!("Section {n}"), "content": paragraphs(&words)});
        if n == 1 {
            let list: Vec<(u64, String)> = (0..6).map(|k| (k, format!("Item {k}"))).collect();
            fields["content"] = items(&list);
        }
        let node = MaterializedNode {
            id: id(n),
            parent_id: Some(id(0)),
            node_type: "section".into(),
            pos: format!("a{n:06}"),
            var_name: None,
            deleted: false,
            current_fields: fields,
        };
        state.nodes.insert(node.id.clone(), node);
    }
    state
}

/// A side: a few edits of labels, paragraphs, list items, page setup, inserts, deletes.
fn edit(
    rng: &mut Rng,
    base: &DocumentState,
    nodes: u64,
    side: &str,
    next: &mut u64,
) -> DocumentState {
    let mut state = base.clone();
    let edits = 1 + rng.below(4);
    for _ in 0..edits {
        let target = id(1 + rng.below(nodes.max(2) - 1));
        let Some(node) = state.nodes.get_mut(&target) else {
            continue;
        };
        match rng.below(6) {
            0 => {
                node.current_fields["label"] = json!(format!(
                    "{} ({side})",
                    node.current_fields["label"].as_str().unwrap_or("")
                ))
            }
            1 | 2 => {
                if let Some(list) = node.current_fields["content"]["content"].as_array_mut() {
                    let k = rng.below(list.len() as u64) as usize;
                    if let Some(text) = list[k]["content"][0]["text"].as_str().map(str::to_owned) {
                        list[k]["content"][0]["text"] = json!(format!("{text}, edited on {side}"));
                    } else if let Some(text) = list[k]["content"][0]["content"][0]["text"]
                        .as_str()
                        .map(str::to_owned)
                    {
                        list[k]["content"][0]["content"][0]["text"] =
                            json!(format!("{text} ({side})"));
                    }
                    if node.current_fields["content"]["type"] == "bulletList" && rng.chance(50) {
                        *next += 1;
                        let item = json!({"type":"listItem","attrs":{"itemId":format!("{side}{next}")},"content":[{"type":"paragraph","content":[{"type":"text","text":format!("New on {side}")}]}]});
                        if let Some(list) = node.current_fields["content"]["content"].as_array_mut()
                        {
                            let at = rng.below(list.len() as u64 + 1) as usize;
                            list.insert(at, item);
                        }
                    }
                }
            }
            3 => {
                if let Some(root) = state.nodes.get_mut(&id(0)) {
                    let key = if side == "left" {
                        "margin"
                    } else {
                        "landscape"
                    };
                    root.current_fields["page_setup"][key] = json!(20 + rng.below(10));
                }
            }
            4 => {
                *next += 1;
                let new = MaterializedNode {
                    id: id(1_000_000 + *next),
                    parent_id: Some(id(0)),
                    node_type: "section".into(),
                    pos: format!("a{:06}x{side}{next}", rng.below(nodes)),
                    var_name: None,
                    deleted: false,
                    current_fields: json!({"label": format!("Added on {side}")}),
                };
                state.nodes.insert(new.id.clone(), new);
            }
            _ => node.deleted = true,
        }
    }
    state
}

/// `cases` deterministic cases of `nodes` nodes each.
pub fn corpus(seed: u64, cases: u64, nodes: u64) -> Vec<Case> {
    let mut rng = Rng(seed);
    let mut next = 0;
    (0..cases)
        .map(|_| {
            let base = base_state(&mut rng, nodes);
            let left = edit(&mut rng, &base, nodes, "left", &mut next);
            let right = edit(&mut rng, &base, nodes, "right", &mut next);
            Case { base, left, right }
        })
        .collect()
}

/// What one run measured.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub format: &'static str,
    pub seed: u64,
    pub cases: u64,
    pub nodes_per_document: u64,
    pub policy: String,
    pub merged: u64,
    pub conflicted: u64,
    pub decisions: u64,
    pub needs_review: u64,
    pub total_ms: f64,
    pub per_case_us_p50: f64,
    pub per_case_us_p95: f64,
    pub per_case_us_max: f64,
    pub nodes_per_second: f64,
}

/// Merge every case once under `policy` and measure each merge.
pub fn run(seed: u64, cases: u64, nodes: u64, policy: &MergePolicy) -> Report {
    let corpus = corpus(seed, cases, nodes);
    let (left_root, right_root) = (
        Address::try_from("aa".repeat(32)).unwrap_or_else(|_| unreachable!("valid hex")),
        Address::try_from("bb".repeat(32)).unwrap_or_else(|_| unreachable!("valid hex")),
    );
    let (mut merged, mut conflicted, mut decisions, mut needs_review) = (0, 0, 0, 0);
    let mut times: Vec<f64> = Vec::with_capacity(corpus.len());
    let started = Instant::now();
    for case in &corpus {
        let at = Instant::now();
        let (result, evidence) = converge_with_policy(
            &case.base,
            &case.left,
            &case.right,
            &left_root,
            &right_root,
            policy,
        );
        times.push(at.elapsed().as_secs_f64() * 1e6);
        let entries = review::entries(&evidence.evidence, evidence.team, None);
        decisions += entries.len() as u64;
        needs_review += u64::from(review::needs_review(&entries));
        if result.merged.is_some() {
            merged += 1;
        } else {
            conflicted += 1;
        }
    }
    let total = started.elapsed().as_secs_f64();
    times.sort_by(f64::total_cmp);
    let pick = |q: f64| {
        times
            .get(((times.len() as f64 - 1.0) * q).round() as usize)
            .copied()
            .unwrap_or(0.0)
    };
    Report {
        format: "dynodoc.merge-bench.v1",
        seed,
        cases,
        nodes_per_document: nodes,
        policy: policy.id.clone(),
        merged,
        conflicted,
        decisions,
        needs_review,
        total_ms: total * 1e3,
        per_case_us_p50: pick(0.5),
        per_case_us_p95: pick(0.95),
        per_case_us_max: times.last().copied().unwrap_or(0.0),
        nodes_per_second: if total > 0.0 {
            (cases * nodes) as f64 / total
        } else {
            0.0
        },
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_corpus_is_deterministic_and_the_runner_counts_every_case() {
        let a = super::corpus(7, 3, 20);
        let b = super::corpus(7, 3, 20);
        assert!(a
            .iter()
            .zip(&b)
            .all(|(x, y)| x.left == y.left && x.right == y.right));
        let report = super::run(7, 5, 20, crate::merge_policy::default::policy());
        assert_eq!(report.merged + report.conflicted, 5);
    }
}
