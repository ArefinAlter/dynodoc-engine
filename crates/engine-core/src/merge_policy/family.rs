//! The text, spreadsheet and presentation invariants of design 5.2 to 5.4, checked
//! on a merged state beside INV-G1 to INV-G8 (same report, same `flag`/`conflict`
//! mode, same "introduced by the merge" rule).
//!
//! | ID | Checked |
//! |---|---|
//! | INV-T1 | no run boundary of an inline container falls inside a grapheme cluster |
//! | INV-T3 | inline containers hold text and leaf nodes only, no empty text runs, adjacent runs with equal metadata coalesced |
//! | INV-T4 | at most 100,000 scalars per value; nesting depth at most 64 |
//! | INV-T5 | table rows have equal cell counts (by colspan); lists hold list items only |
//! | INV-S2 | formula references inside 100 columns and 3,000 rows |
//! | INV-S4 | a sheet's `columns` exceeds every used `cell_<n>` index |
//! | INV-P2 | `x`, `y`, `w`, `h` are finite numbers when present |
//! | INV-P3 | an image `src` is at most 1 MiB |
//!
//! Holding by construction and not checked: INV-T2 (a `serde_json` string is always
//! valid Unicode), INV-S1 (formulas are stored verbatim; [`super::sheet::tokens`]
//! tells unparsed ones apart), INV-P1 (node identifiers are map keys), INV-P4 (ties
//! in `pos` are broken by node id when ordering). Not built: INV-S3, S5, S6 (merged
//! ranges, date-only cells and validation ranges have no engine model yet).

use super::invariants::Violation;
use crate::materializer::DocumentState;
use serde_json::Value;
use std::collections::BTreeSet;

pub const IDS: [&str; 8] = [
    "INV-T1", "INV-T3", "INV-T4", "INV-T5", "INV-S2", "INV-S4", "INV-P2", "INV-P3",
];
const MAX_IMAGE_BYTES: usize = 1 << 20;

fn depth(v: &Value) -> usize {
    match v {
        Value::Array(a) => 1 + a.iter().map(depth).max().unwrap_or(0),
        Value::Object(o) => 1 + o.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn walk<'a>(v: &'a Value, out: &mut Vec<&'a Value>) {
    if v.is_object() {
        out.push(v);
    }
    if let Some(children) = v["content"].as_array() {
        for c in children {
            walk(c, out);
        }
    }
}

fn rich(node: &str, field: &str, v: &Value, push: &mut dyn FnMut(&'static str, String)) {
    if depth(v) > 64 {
        push("INV-T4", format!("{node}.{field} nests deeper than 64"));
        return;
    }
    if crate::richtext::plain_text(v).chars().count() > super::text::MAX_SCALARS {
        push("INV-T4", format!("{node}.{field} exceeds 100,000 scalars"));
    }
    let mut nodes = Vec::new();
    walk(v, &mut nodes);
    for n in nodes {
        let kind = n["type"].as_str().unwrap_or("");
        let kids = n["content"].as_array();
        if matches!(kind, "paragraph" | "heading" | "codeBlock") {
            if super::text::split_clusters(n) > 0 {
                push(
                    "INV-T1",
                    format!("{node}.{field}: a run boundary splits a grapheme cluster"),
                );
            }
            let runs = kids.map(Vec::as_slice).unwrap_or_default();
            for (k, run) in runs.iter().enumerate() {
                if run.get("content").is_some() {
                    push(
                        "INV-T3",
                        format!("{node}.{field}: an inline container holds a block"),
                    );
                }
                if run["type"] == "text" {
                    if run["text"].as_str().is_none_or(str::is_empty) {
                        push("INV-T3", format!("{node}.{field}: an empty text run"));
                    }
                    if let Some(prev) = k.checked_sub(1).map(|p| &runs[p]) {
                        let meta = |r: &Value| {
                            let mut m = r.as_object().cloned().unwrap_or_default();
                            m.remove("text");
                            m
                        };
                        if prev["type"] == "text" && meta(prev) == meta(run) {
                            push(
                                "INV-T3",
                                format!("{node}.{field}: adjacent runs are not coalesced"),
                            );
                        }
                    }
                }
            }
        }
        if matches!(kind, "bulletList" | "orderedList" | "taskList") {
            let ok = kids.is_none_or(|k| {
                k.iter()
                    .all(|c| matches!(c["type"].as_str(), Some("listItem" | "taskItem")))
            });
            if !ok {
                push("INV-T5", format!("{node}.{field}: a list holds a non-item"));
            }
        }
        if kind == "table" {
            let widths: BTreeSet<u64> = kids
                .into_iter()
                .flatten()
                .map(|row| {
                    row["content"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|cell| cell["attrs"]["colspan"].as_u64().unwrap_or(1))
                        .sum()
                })
                .collect();
            if widths.len() > 1 {
                push(
                    "INV-T5",
                    format!("{node}.{field}: table rows differ in width"),
                );
            }
        }
    }
}

/// Every family violation of `state`.
pub(crate) fn check(state: &DocumentState, found: &mut BTreeSet<Violation>) {
    let sheets: BTreeSet<&str> = state
        .nodes
        .values()
        .filter(|n| !n.deleted && n.current_fields["kind"] == "sheet")
        .map(|n| n.id.0.as_str())
        .collect();
    for node in state.nodes.values().filter(|n| !n.deleted) {
        let id = node.id.0.as_str();
        let mut push = |inv: &'static str, detail: String| {
            found.insert(Violation {
                invariant: inv,
                subject: id.to_string(),
                detail,
                participants: vec![node.id.clone()],
            });
        };
        let Some(fields) = node.current_fields.as_object() else {
            continue;
        };
        for (field, v) in fields {
            if v.is_object() && v["type"].is_string() {
                rich(id, field, v, &mut push);
            }
            if let Some(f) = v
                .as_str()
                .filter(|s| field.starts_with("cell_") && s.starts_with('='))
            {
                let refs = super::sheet::tokens(f).unwrap_or_default();
                let out = refs.iter().any(|t| match &t.token {
                    super::sheet::Token::Ref(r) => {
                        r.col.is_some_and(|(_, c)| c >= super::sheet::MAX_COLUMNS)
                            || r.row.is_some_and(|(_, row)| row >= super::sheet::MAX_ROWS)
                    }
                    _ => false,
                });
                if out {
                    push(
                        "INV-S2",
                        format!("{field} references a cell outside the sheet bounds"),
                    );
                }
            }
            if matches!(field.as_str(), "x" | "y" | "w" | "h") && !(v.is_number() || v.is_null()) {
                push("INV-P2", format!("{field} is not a number"));
            }
            if field == "src"
                && v.as_str()
                    .is_some_and(|s| s.len() > MAX_IMAGE_BYTES * 4 / 3 + 64)
            {
                push("INV-P3", "image data exceeds 1 MiB".into());
            }
        }
        if node
            .parent_id
            .as_ref()
            .is_some_and(|p| sheets.contains(p.0.as_str()))
        {
            let columns = state
                .nodes
                .get(node.parent_id.as_ref().unwrap_or(&node.id))
                .and_then(|s| s.current_fields["columns"].as_u64())
                .unwrap_or(12);
            let used = fields
                .iter()
                .filter(|(_, v)| !(v.is_null() || v.as_str() == Some("")))
                .filter_map(|(k, _)| k.strip_prefix("cell_")?.parse::<u64>().ok())
                .max();
            if used.is_some_and(|u| u >= columns) {
                push(
                    "INV-S4",
                    format!("cell {} is beyond `columns` {columns}", used.unwrap_or(0)),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::materializer::MaterializedNode;
    use engine_shared::NodeId;
    use serde_json::json;

    fn state(fields: Value, sheet: bool) -> DocumentState {
        let mut s = DocumentState::default();
        let parent = NodeId("01J0000000000000000000SHT0".into());
        if sheet {
            s.nodes.insert(
                parent.clone(),
                MaterializedNode {
                    id: parent.clone(),
                    parent_id: None,
                    node_type: "section".into(),
                    pos: "a0".into(),
                    current_fields: json!({"kind":"sheet","columns":2}),
                    var_name: None,
                    deleted: false,
                },
            );
        }
        let id = NodeId("01J0000000000000000000ROW0".into());
        s.nodes.insert(
            id.clone(),
            MaterializedNode {
                id,
                parent_id: sheet.then_some(parent),
                node_type: "item".into(),
                pos: "a1".into(),
                current_fields: fields,
                var_name: None,
                deleted: false,
            },
        );
        s
    }

    fn ids(s: &DocumentState) -> Vec<&'static str> {
        let mut found = BTreeSet::new();
        check(s, &mut found);
        found.into_iter().map(|v| v.invariant).collect()
    }

    #[test]
    fn each_family_check_fires_on_its_case() {
        let para = json!({"type":"paragraph","content":[
            {"type":"text","text":"a"},{"type":"text","text":"b"},{"type":"text","text":""}]});
        // An empty run and two runs that should be one.
        assert_eq!(
            ids(&state(json!({"content": para}), false)),
            ["INV-T3", "INV-T3"]
        );
        let table = json!({"type":"table","content":[
            {"type":"tableRow","content":[{"type":"tableCell"},{"type":"tableCell"}]},
            {"type":"tableRow","content":[{"type":"tableCell"}]}]});
        assert_eq!(ids(&state(json!({"content": table}), false)), ["INV-T5"]);
        assert_eq!(ids(&state(json!({"cell_0":"=CW1"}), true)), ["INV-S2"]);
        assert_eq!(ids(&state(json!({"cell_5":"x"}), true)), ["INV-S4"]);
        assert_eq!(ids(&state(json!({"x":"left"}), false)), ["INV-P2"]);
        assert!(ids(&state(json!({"cell_1":"=A1","x":10}), true)).is_empty());
    }
}
