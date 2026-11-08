//! Phases N2 to N4 of the node-conflict design: every new strategy is held to the
//! laws of section 4.1 by the shared harness (determinism, symmetry, idempotence,
//! identity, totality, bounds, invariants, a preferred side's loser carried), and
//! loser preservation is checked end to end: whatever an automatic outcome does not
//! use is in the merged state as a suggestion.

use engine_core::{
    materializer::{DocumentState, MaterializedNode},
    merge_policy::{
        block::SameShape,
        laws::{check, Rng, Setup, Triple},
        marks::MarkSet,
        policy::Role,
        sheet::{Grid, SheetCell, SheetShift},
        slide::SlideShape,
        strategy::{Context, Inputs, Outcome, Strategy},
        text::{split_clusters, Diff3Grapheme},
        Aspect, Family, MergePolicy, Registry,
    },
    workspace_merge,
};
use engine_shared::NodeId;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use unicode_segmentation::UnicodeSegmentation;

const CASES: usize = 1500;
const ATOMS: [&str; 10] = ["a", "b", "c", " ", "ক্ষ", "👩‍💻", "e\u{301}", "ম", "z", "."];

fn pick<'a>(rng: &mut Rng, items: &[&'a str]) -> &'a str {
    items[rng.below(items.len())]
}

fn word(rng: &mut Rng, max: usize) -> Vec<String> {
    (0..rng.below(max) + 1)
        .map(|_| pick(rng, &ATOMS).to_string())
        .collect()
}

/// A random edit of a grapheme sequence: insert, delete or replace a short span.
fn edit(rng: &mut Rng, base: &[String]) -> Vec<String> {
    let mut out = base.to_vec();
    for _ in 0..rng.below(3) + 1 {
        let at = rng.below(out.len() + 1);
        match rng.below(3) {
            0 => {
                let w = word(rng, 3);
                out.splice(at..at, w);
            }
            1 if at < out.len() => {
                let end = (at + rng.below(3) + 1).min(out.len());
                out.drain(at..end);
            }
            _ if at < out.len() => {
                let end = (at + rng.below(2) + 1).min(out.len());
                let w = word(rng, 2);
                out.splice(at..end, w);
            }
            _ => {}
        }
    }
    out
}

fn text_triple(rng: &mut Rng) -> Triple {
    let base = word(rng, 10);
    let team = if rng.below(5) == 0 {
        base.clone()
    } else {
        edit(rng, &base)
    };
    let draft = if rng.below(5) == 0 {
        team.clone()
    } else {
        edit(rng, &base)
    };
    let s = |v: &[String]| Value::String(v.concat());
    Triple {
        base: s(&base),
        team: s(&team),
        draft: s(&draft),
    }
}

const MARKS: [&str; 4] = ["bold", "italic", "link", "textStyle"];

fn mark(rng: &mut Rng, kind: &str) -> Value {
    match kind {
        "link" => json!({"type":"link","attrs":{"href": pick(rng, &["a", "b"])}}),
        "textStyle" => json!({"type":"textStyle","attrs":{"color": pick(rng, &["red", "blue"])}}),
        k => json!({"type": k}),
    }
}

fn marks(rng: &mut Rng) -> Vec<Value> {
    let mut out = Vec::new();
    for k in MARKS {
        if rng.below(3) == 0 {
            out.push(mark(rng, k));
        }
    }
    out
}

/// Runs of text with marks, coalesced as an editor writes them.
fn para(runs: &[(String, Vec<Value>)]) -> Value {
    let mut content: Vec<Value> = Vec::new();
    for (text, m) in runs.iter().filter(|(t, _)| !t.is_empty()) {
        let mut run = json!({"type":"text","text":text});
        if !m.is_empty() {
            run["marks"] = json!(m);
        }
        let same = content
            .last()
            .is_some_and(|last: &Value| last.get("marks") == run.get("marks"));
        if same {
            let last = content.last_mut().unwrap();
            let joined = format!("{}{}", last["text"].as_str().unwrap(), text);
            last["text"] = json!(joined);
        } else {
            content.push(run);
        }
    }
    json!({"type":"paragraph","content":content})
}

fn para_triple(rng: &mut Rng) -> Triple {
    let base: Vec<(String, Vec<Value>)> = (0..rng.below(3) + 1)
        .map(|_| (word(rng, 4).concat(), marks(rng)))
        .collect();
    let side = |rng: &mut Rng| -> Vec<(String, Vec<Value>)> {
        base.iter()
            .map(|(t, m)| {
                let g: Vec<String> = t.graphemes(true).map(str::to_string).collect();
                let t = if rng.below(2) == 0 {
                    edit(rng, &g).concat()
                } else {
                    t.clone()
                };
                let m = if rng.below(3) == 0 {
                    marks(rng)
                } else {
                    m.clone()
                };
                (t, m)
            })
            .collect()
    };
    let (team, draft) = (side(rng), side(rng));
    Triple {
        base: para(&base),
        team: para(&team),
        draft: para(&draft),
    }
}

fn canonical_text(v: &Value) -> bool {
    if v.is_string() {
        return true;
    }
    let runs = v["content"].as_array().cloned().unwrap_or_default();
    let meta = |r: &Value| r.get("marks").cloned();
    split_clusters(v) == 0
        && runs
            .iter()
            .all(|r| r["text"].as_str().is_some_and(|t| !t.is_empty()))
        && runs.windows(2).all(|w| meta(&w[0]) != meta(&w[1]))
}

fn setup(field: &'static str, params: &[(&str, &str)]) -> Setup<'static> {
    let mut s = Setup::field(field);
    s.params = params
        .iter()
        .map(|(k, v)| (k.to_string(), json!(v)))
        .collect();
    s.roles = Some((Role::Editor, Role::Owner));
    s.rank = vec![Role::Owner, Role::Manager, Role::Editor];
    s
}

fn cases(seed: u64, gen: fn(&mut Rng) -> Triple) -> impl Iterator<Item = Triple> {
    let mut rng = Rng(seed);
    (0..CASES).map(move |_| gen(&mut rng))
}

#[test]
fn grapheme_text_keeps_every_law_on_plain_strings_and_rich_paragraphs() {
    let valid = canonical_text;
    for params in [
        &[][..],
        &[
            ("replace_conflict", "prefer-role"),
            ("delete_vs_insert", "manual"),
        ][..],
    ] {
        let mut s = setup("content", params);
        s.valid = Some(&valid);
        let report = check(&Diff3Grapheme, &s, cases(0x7e57_0001, text_triple)).unwrap();
        assert!(
            report.merged > 600 && report.conflicts + report.preferred > 50,
            "{report:?}"
        );
        assert!(
            report.checked.contains(&"L1 symmetry") && report.checked.contains(&"L6 invariants")
        );
        let report = check(&Diff3Grapheme, &s, cases(0x7e57_0002, para_triple)).unwrap();
        assert!(report.merged > 600, "{report:?}");
    }
    // With a marks rule that prefers by role, mark clashes become preferences.
    let mut s = setup("content", &[("replace_conflict", "prefer-role")]);
    s.marks = Some(BTreeMap::from([(
        "attribute_conflict".into(),
        json!("prefer-role"),
    )]));
    let report = check(&Diff3Grapheme, &s, cases(0x7e57_0003, para_triple)).unwrap();
    assert!(report.preferred > 0, "{report:?}");
}

/// P5: every grapheme a side inserted is in the result or in a lost value.
#[test]
fn grapheme_text_never_drops_inserted_text_silently() {
    let s = setup("content", &[]);
    let ctx = Context {
        node: None,
        node_type: "item",
        field: "content",
        aspect: None,
        family: Family::Document,
        params: &s.params,
        roles: None,
        rank: &s.rank,
        marks: None,
    };
    let count = |v: &Value| -> BTreeMap<String, i64> {
        let mut m = BTreeMap::new();
        for g in v.as_str().unwrap_or("").graphemes(true) {
            *m.entry(g.to_string()).or_default() += 1;
        }
        m
    };
    let mut rng = Rng(0x7e57_0004);
    let mut lossy = 0;
    for _ in 0..CASES * 2 {
        let t = text_triple(&mut rng);
        let r = Diff3Grapheme.resolve(
            &Inputs {
                base: &t.base,
                team: &t.team,
                draft: &t.draft,
            },
            &ctx,
        );
        let Outcome::Merged(out) = &r.outcome else {
            continue;
        };
        lossy += usize::from(!r.used.lost.is_empty());
        let (b, o) = (count(&t.base), count(out));
        let lost: Vec<_> = r.used.lost.iter().map(count).collect();
        for side in [&t.team, &t.draft] {
            for (g, n) in count(side) {
                let inserted = n - b.get(&g).copied().unwrap_or(0);
                let kept = o.get(&g).copied().unwrap_or(0)
                    + lost
                        .iter()
                        .map(|l| l.get(&g).copied().unwrap_or(0))
                        .sum::<i64>();
                assert!(
                    inserted <= kept,
                    "{g:?} inserted {inserted}, kept {kept}: {t:?} -> {out}"
                );
            }
        }
    }
    assert!(lossy > 0, "the generator reaches delete-versus-insert");
}

/// P6: where the frozen hunk merge succeeds, the new strategy gives the same text.
#[test]
fn grapheme_text_agrees_with_the_hunk_merge_where_that_merges() {
    let s = setup("content", &[]);
    let ctx = Context {
        node: None,
        node_type: "item",
        field: "content",
        aspect: None,
        family: Family::Document,
        params: &s.params,
        roles: None,
        rank: &s.rank,
        marks: None,
    };
    let mut rng = Rng(0x7e57_0005);
    let mut agreed = 0;
    for _ in 0..CASES * 2 {
        let t = para_triple(&mut rng);
        let Some(old) = engine_core::richtext::merge(&t.base, &t.team, &t.draft) else {
            continue;
        };
        let new = Diff3Grapheme.resolve(
            &Inputs {
                base: &t.base,
                team: &t.team,
                draft: &t.draft,
            },
            &ctx,
        );
        let Outcome::Merged(new) = new.outcome else {
            panic!("the hunk merge merged {t:?} and the grapheme merge did not");
        };
        assert_eq!(
            engine_core::richtext::plain_text(&new),
            engine_core::richtext::plain_text(&old),
            "{t:?}"
        );
        agreed += 1;
    }
    assert!(agreed > 500, "{agreed}");
}

fn mark_triple(rng: &mut Rng) -> Triple {
    let base = Value::Array(marks(rng));
    let side = |rng: &mut Rng| {
        if rng.below(4) == 0 {
            base.clone()
        } else {
            Value::Array(marks(rng))
        }
    };
    Triple {
        team: side(rng),
        draft: side(rng),
        base,
    }
}

#[test]
fn marks_keep_every_law_with_and_without_role_preference() {
    for params in [
        &[][..],
        &[
            ("attribute_conflict", "prefer-role"),
            ("add_remove", "prefer-role"),
        ][..],
    ] {
        let mut s = setup("marks", params);
        s.aspect = Some(Aspect::Marks);
        let report = check(&MarkSet, &s, cases(0x7e57_0006, mark_triple)).unwrap();
        assert!(report.merged > 300, "{report:?}");
        assert!(report.checked.contains(&"L8 bounded"));
    }
}

fn list_triple(rng: &mut Rng) -> Triple {
    let items = rng.below(3) + 1;
    let base: Vec<Vec<String>> = (0..items).map(|_| word(rng, 4)).collect();
    let list = |items: &[Vec<String>]| {
        json!({"type":"bulletList","content": items.iter().map(|t| json!({
            "type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":t.concat()}]}]
        })).collect::<Vec<_>>()})
    };
    let side = |rng: &mut Rng| -> Vec<Vec<String>> {
        let mut s: Vec<Vec<String>> = base
            .iter()
            .map(|t| {
                if rng.below(2) == 0 {
                    edit(rng, t)
                } else {
                    t.clone()
                }
            })
            .map(|t| {
                if t.is_empty() {
                    vec!["x".to_string()]
                } else {
                    t
                }
            })
            .collect();
        if rng.below(6) == 0 {
            s.push(word(rng, 3));
        }
        s
    };
    let (t, d) = (side(rng), side(rng));
    Triple {
        base: list(&base),
        team: list(&t),
        draft: list(&d),
    }
}

#[test]
fn same_shape_lists_keep_every_law() {
    let report = check(
        &SameShape,
        &setup("content", &[]),
        cases(0x7e57_0007, list_triple),
    )
    .unwrap();
    assert!(report.merged > 500 && report.conflicts > 50, "{report:?}");
}

fn cell_triple(rng: &mut Rng) -> Triple {
    let values = [
        "1",
        "2",
        "x",
        "=A1",
        "=a1",
        "=SUM(A1:B2)",
        "=sum( a1:b2 )",
        "=B1+1",
        "=\"q",
        "",
    ];
    let v = |rng: &mut Rng| json!(pick(rng, &values));
    Triple {
        base: v(rng),
        team: v(rng),
        draft: v(rng),
    }
}

#[test]
fn sheet_cells_and_slide_fields_keep_every_law() {
    for params in [&[][..], &[("value_conflict", "prefer-role")][..]] {
        let mut s = setup("cell_3", params);
        s.family = Family::Spreadsheet;
        let report = check(&SheetCell, &s, cases(0x7e57_0008, cell_triple)).unwrap();
        assert!(report.merged > 300, "{report:?}");
    }
    let geometry = |rng: &mut Rng| Triple {
        base: json!(rng.below(4) * 10),
        team: json!(rng.below(4) * 10),
        draft: json!(rng.below(4) * 10),
    };
    for (field, gen) in [
        ("x", geometry as fn(&mut Rng) -> Triple),
        ("text", text_triple),
    ] {
        let mut s = setup(field, &[("geometry_conflict", "prefer-role")]);
        s.family = Family::Presentation;
        let report = check(&SlideShape, &s, cases(0x7e57_0009, gen)).unwrap();
        assert!(report.merged > 300, "{field} {report:?}");
    }
}

fn grid_triple(rng: &mut Rng) -> Triple {
    let mut base = Grid {
        columns: 4,
        label: None,
        rows: BTreeMap::new(),
    };
    for r in 0..6 {
        base.rows.insert(
            format!("r{r}"),
            (0..4)
                .map(|c| (c, (json!(format!("v{r}{c}")), Value::Null)))
                .collect(),
        );
    }
    let side = |rng: &mut Rng| {
        let mut g = base.clone();
        if rng.below(3) == 0 {
            g = g.shifted(engine_core::merge_policy::sheet::Shift {
                insert: rng.below(2) == 0,
                at: rng.below(4) as u32,
            });
        }
        if rng.below(2) == 0 {
            let row = format!("r{}", rng.below(6));
            g.rows
                .get_mut(&row)
                .unwrap()
                .insert(0, (json!(format!("edit{}", rng.below(3))), Value::Null));
        }
        g
    };
    let (t, d) = (side(rng), side(rng));
    Triple {
        base: base.to_json(),
        team: t.to_json(),
        draft: d.to_json(),
    }
}

#[test]
fn sheet_shift_certificates_keep_every_law() {
    let mut s = setup("$structure", &[]);
    s.aspect = Some(Aspect::Structure);
    s.family = Family::Spreadsheet;
    let report = check(&SheetShift, &s, cases(0x7e57_000a, grid_triple)).unwrap();
    assert!(report.merged > 300, "{report:?}");
}

fn node(id: &str, parent: Option<&str>, fields: Value) -> MaterializedNode {
    MaterializedNode {
        id: NodeId(id.into()),
        parent_id: parent.map(|p| NodeId(p.into())),
        node_type: if parent.is_some() { "item" } else { "form" }.into(),
        pos: id.into(),
        current_fields: fields,
        var_name: None,
        deleted: false,
    }
}

fn doc(cells: &[(&str, &str)]) -> DocumentState {
    let mut s = DocumentState::default();
    let root = "01J00000000000000000000R00";
    s.nodes.insert(
        NodeId(root.into()),
        node(root, None, json!({"label":"Book"})),
    );
    let sheet = "01J00000000000000000000S00";
    let mut sh = node(
        sheet,
        Some(root),
        json!({"kind":"sheet","label":"Sheet1","columns":4}),
    );
    sh.node_type = "section".into();
    s.nodes.insert(NodeId(sheet.into()), sh);
    let mut row = json!({});
    for (k, v) in cells {
        row[*k] = json!(v);
    }
    let r = "01J00000000000000000000W00";
    s.nodes.insert(NodeId(r.into()), node(r, Some(sheet), row));
    s
}

const POLICY: &str = r#"{
  "version": 1, "id": "test-prefer",
  "defaults": {"unknown": "manual", "loser": "suggestion"},
  "rules": [
    {"id": "cells", "match": {"field": "cell_*"}, "strategy": "dynodoc.sheet.cell.v1",
     "params": {"value_conflict": "prefer-role"}, "gate": "auto"},
    {"id": "rest", "match": {}, "strategy": "dynodoc.default.whole-value.v1", "gate": "auto"}
  ]
}"#;

/// Loser preservation end to end, deterministic and orientation independent: a
/// preferred cell keeps the other value as a pending suggestion in the merged state.
#[test]
fn a_preferred_value_is_kept_as_a_suggestion_in_either_orientation() {
    let registry = Registry::builtin();
    let policy = MergePolicy::from_json(POLICY.as_bytes(), &registry).unwrap();
    let base = doc(&[("cell_0", "1"), ("cell_1", "a")]);
    let team = doc(&[("cell_0", "2"), ("cell_1", "a")]);
    let draft = doc(&[("cell_0", "3"), ("cell_1", "b")]);
    let run = |t: &DocumentState, d: &DocumentState, roles| {
        workspace_merge::merge_with_roles(&base, t, d, &BTreeMap::new(), &policy, &registry, roles)
    };
    let (plan, evidence) = run(&team, &draft, Some((Role::Owner, Role::Editor)));
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    let row = &plan.state.nodes[&NodeId("01J00000000000000000000W00".into())];
    assert_eq!(row.current_fields["cell_0"], json!("2"));
    assert_eq!(row.current_fields["cell_1"], json!("b"));
    let kept: Vec<&Value> = plan
        .state
        .suggestions
        .values()
        .map(|s| &s.detail["change"]["value"])
        .collect();
    assert_eq!(kept, [&json!("3")]);
    assert!(evidence.decisions.iter().any(|d| d.needs_review));
    // The same roles with the sides swapped give the same state, twice over.
    let (swapped, _) = run(&draft, &team, Some((Role::Editor, Role::Owner)));
    assert_eq!(swapped.state.suggestions, plan.state.suggestions);
    assert_eq!(
        swapped.state.nodes[&NodeId("01J00000000000000000000W00".into())].current_fields,
        row.current_fields
    );
    let (again, _) = run(&team, &draft, Some((Role::Owner, Role::Editor)));
    assert_eq!(again.state, plan.state);
    // Without roles nothing decides, so it stays a conflict; with `loser: none` a
    // preference is refused.
    let (unknown, _) = run(&team, &draft, None);
    assert_eq!(unknown.conflicts.len(), 1);
    let none = MergePolicy::from_json(
        POLICY.replace("\"suggestion\"", "\"none\"").as_bytes(),
        &registry,
    )
    .unwrap();
    let (refused, ev) = workspace_merge::merge_with_roles(
        &base,
        &team,
        &draft,
        &BTreeMap::new(),
        &none,
        &registry,
        Some((Role::Owner, Role::Editor)),
    );
    assert_eq!(refused.conflicts.len(), 1);
    assert!(ev
        .decisions
        .iter()
        .any(|d| d.reason == "loser-not-preserved"));
    assert!(refused.state.suggestions.is_empty());
}
