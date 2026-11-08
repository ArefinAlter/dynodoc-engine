//! `dynodoc.text.diff3-grapheme.v1` (design 4.2): three-way text merge whose atoms
//! are extended grapheme clusters (UAX #29 as implemented by `unicode-segmentation`
//! 1.13.3, Unicode 17.0.0, including the Indic conjunct rule GB9c), so a hunk
//! boundary never falls inside a Bengali conjunct or an emoji sequence.
//!
//! It decides plain strings and inline containers (`paragraph`, `heading`,
//! `codeBlock`). Hunks of base to team and base to draft that do not interact are
//! applied together, as `richtext::merge` does. Where they interact:
//!
//! | Case | Outcome |
//! |---|---|
//! | the same edit on both sides | applied once (`identical_insert: dedupe`, or a conflict with `manual` for two equal insertions at one gap) |
//! | different insertions at one gap | both, in bytewise order of their text; review |
//! | overlapping deletions | their union |
//! | a deletion with an insertion strictly inside it | `delete_vs_insert: keep-insert` (the default) deletes the range and keeps the insertion; the inserting side's value is preserved as a loser; review |
//! | a deletion of text the other side only reformatted | the deletion (formatting on deleted text is moot) |
//! | overlapping replacements | `replace_conflict: manual` (the default) is a conflict, `prefer-role` prefers the higher role and preserves the other value |
//! | insertion next to text the other side reformatted | Peritext-style growth: a mark added (or removed) on both neighbours applies to the insertion, on the left neighbour only when the mark grows at its end; review |
//!
//! Marks of text kept by both sides merge through [`super::marks`], with the
//! policy's marks rule when there is one. The result's mark order is symmetric, so
//! unlike `dynodoc.default.richtext.v1` this strategy keeps law L1.

use super::{
    marks,
    strategy::{
        Context, Inputs, Laws, Outcome, ParamSpec, ParamType, Reason, Resolved, Side, Strategy,
        Used,
    },
    Gate,
};
use serde_json::{json, Map, Value};
use similar::{capture_diff_slices, Algorithm, DiffTag};
use std::collections::BTreeMap;
use unicode_segmentation::UnicodeSegmentation;

pub const ID: &str = "dynodoc.text.diff3-grapheme.v1";
/// Unicode scalars per value, as `richtext` bounds them.
pub const MAX_SCALARS: usize = 100_000;
/// Default bound on hunks per side (design 4.2).
pub const MAX_HUNKS: i64 = 200;
/// Changed spans longer than this become one replacement, as in `richtext`: a size,
/// unlike a clock, gives every machine the same merge.
const DIFF_LIMIT: usize = 4_000;
const LEAF: &str = "\u{FFFC}";

pub struct Diff3Grapheme;

const PARAMS: &[ParamSpec] = &[
    ParamSpec {
        name: "identical_insert",
        ty: ParamType::OneOf(&["dedupe", "manual"]),
    },
    ParamSpec {
        name: "delete_vs_insert",
        ty: ParamType::OneOf(&["keep-insert", "manual"]),
    },
    ParamSpec {
        name: "replace_conflict",
        ty: ParamType::OneOf(&["manual", "prefer-role"]),
    },
    ParamSpec {
        name: "max_hunks",
        ty: ParamType::Int {
            min: 1,
            max: 10_000,
        },
    },
];

impl Strategy for Diff3Grapheme {
    fn id(&self) -> &'static str {
        ID
    }
    fn params(&self) -> &'static [ParamSpec] {
        PARAMS
    }
    fn promises(&self) -> Laws {
        Laws::ALL
    }
    fn max_input_bytes(&self) -> Option<usize> {
        Some(4 * MAX_SCALARS)
    }
    fn resolve(&self, i: &Inputs<'_>, ctx: &Context<'_>) -> Resolved {
        if i.draft == i.base || i.draft == i.team {
            return Resolved::merged(i.team.clone(), "unchanged-or-team-only");
        }
        if i.team == i.base {
            return Resolved::merged(i.draft.clone(), "draft-only");
        }
        if [i.base, i.team, i.draft]
            .iter()
            .any(|v| serde_json::to_vec(v).map_or(usize::MAX, |b| b.len()) > 4 * MAX_SCALARS)
        {
            return Resolved::conflict(Reason::TOO_LARGE, "bound");
        }
        merge_value(i, ctx)
    }
}

/// One alignment unit: a grapheme cluster of one run, or a leaf inline node.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Atom {
    key: String,
    style: usize,
}

#[derive(Default)]
struct Styles {
    values: Vec<Value>,
    lookup: BTreeMap<Vec<u8>, usize>,
}

impl Styles {
    fn intern(&mut self, value: Value) -> usize {
        let key = crate::hashing::canonical_json(&value);
        if let Some(i) = self.lookup.get(&key) {
            return *i;
        }
        self.values.push(value);
        self.lookup.insert(key, self.values.len() - 1);
        self.values.len() - 1
    }
}

fn is_inline(v: &Value) -> bool {
    matches!(
        v["type"].as_str(),
        Some("paragraph" | "heading" | "codeBlock")
    )
}

/// The atoms of a value, or `None` when it is not text this strategy reads.
fn atoms(value: &Value, styles: &mut Styles) -> Option<Vec<Atom>> {
    let mut out = Vec::new();
    let mut scalars = 0usize;
    let mut push_text = |text: &str, style: usize, out: &mut Vec<Atom>| -> Option<()> {
        scalars += text.chars().count();
        if scalars > MAX_SCALARS {
            return None;
        }
        out.extend(text.graphemes(true).map(|g| Atom {
            key: g.to_string(),
            style,
        }));
        Some(())
    };
    match value {
        Value::Null => Some(out),
        Value::String(text) => {
            let style = styles.intern(Value::Null);
            push_text(text, style, &mut out)?;
            Some(out)
        }
        Value::Object(_) if is_inline(value) => {
            let empty = vec![];
            let children = match value.get("content") {
                None => &empty,
                Some(v) => v.as_array()?,
            };
            for child in children {
                if child["type"] == "text" && child.get("content").is_none() {
                    let text = child["text"].as_str()?;
                    let mut meta = child.as_object()?.clone();
                    meta.remove("text");
                    let style = styles.intern(Value::Object(meta));
                    push_text(text, style, &mut out)?;
                } else if child["type"].is_string() && child.get("content").is_none() {
                    let key = format!(
                        "{LEAF}{}",
                        String::from_utf8_lossy(&crate::hashing::canonical_json(child))
                    );
                    out.push(Atom {
                        key,
                        style: styles.intern(child.clone()),
                    });
                } else {
                    return None;
                }
            }
            Some(out)
        }
        _ => None,
    }
}

fn is_leaf(atom: &Atom) -> bool {
    atom.key.starts_with(LEAF) && atom.key.len() > LEAF.len()
}

/// Rebuild runs: adjacent atoms with one style coalesce into one text node.
fn children(atoms: &[Atom], styles: &Styles) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut i = 0;
    while i < atoms.len() {
        if is_leaf(&atoms[i]) {
            out.push(styles.values[atoms[i].style].clone());
            i += 1;
            continue;
        }
        let style = atoms[i].style;
        let mut text = String::new();
        while i < atoms.len() && atoms[i].style == style && !is_leaf(&atoms[i]) {
            text.push_str(&atoms[i].key);
            i += 1;
        }
        let mut meta = styles.values[style]
            .as_object()
            .cloned()
            .unwrap_or_default();
        meta.insert("text".into(), Value::String(text));
        out.push(Value::Object(meta));
    }
    out
}

#[derive(Clone, Debug)]
struct Hunk {
    start: usize,
    end: usize,
    insert: Vec<Atom>,
    side: Side,
}

impl Hunk {
    fn pure_insert(&self) -> bool {
        self.start == self.end
    }
    fn pure_delete(&self) -> bool {
        self.insert.is_empty()
    }
    fn same_edit(&self, other: &Hunk) -> bool {
        self.start == other.start && self.end == other.end && self.insert == other.insert
    }
}

/// Base index to side index for unchanged atoms, and the side's hunks with
/// adjacent changes coalesced.
fn align(base: &[Atom], side: &[Atom], tag: Side) -> (Vec<Option<usize>>, Vec<Hunk>) {
    let a: Vec<&str> = base.iter().map(|t| t.key.as_str()).collect();
    let b: Vec<&str> = side.iter().map(|t| t.key.as_str()).collect();
    let prefix = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (old_len, new_len) = (a.len() - prefix - suffix, b.len() - prefix - suffix);
    let mut map = vec![None; base.len()];
    let mut hunks: Vec<Hunk> = Vec::new();
    let push = |start: usize, end: usize, insert: &[Atom], hunks: &mut Vec<Hunk>| {
        if let Some(last) = hunks.last_mut().filter(|h| h.end == start) {
            last.end = end;
            last.insert.extend_from_slice(insert);
        } else {
            hunks.push(Hunk {
                start,
                end,
                insert: insert.to_vec(),
                side: tag,
            });
        }
    };
    if old_len == 0 || new_len == 0 || old_len + new_len <= DIFF_LIMIT {
        for op in capture_diff_slices(Algorithm::Myers, &a, &b) {
            let (tag, old, new) = op.as_tag_tuple();
            if tag == DiffTag::Equal {
                for k in 0..old.len() {
                    map[old.start + k] = Some(new.start + k);
                }
            } else {
                push(old.start, old.end, &side[new.start..new.end], &mut hunks);
            }
        }
    } else {
        for (k, slot) in map.iter_mut().enumerate().take(prefix) {
            *slot = Some(k);
        }
        push(
            prefix,
            prefix + old_len,
            &side[prefix..prefix + new_len],
            &mut hunks,
        );
        for k in 0..suffix {
            map[prefix + old_len + k] = Some(prefix + new_len + k);
        }
    }
    (map, hunks)
}

/// Two hunks of different sides that cannot both apply as they are.
fn interact(x: &Hunk, y: &Hunk) -> bool {
    match (x.pure_insert(), y.pure_insert()) {
        (true, true) => x.start == y.start,
        (true, false) => y.start < x.start && x.start < y.end,
        (false, true) => x.start < y.start && y.start < x.end,
        (false, false) => x.start < y.end && y.start < x.end,
    }
}

/// An edit to apply to the base: replace `start..end` with `insert`. `side` is the
/// side whose insertion it carries, for mark growth; `None` when both or neither.
struct Edit {
    start: usize,
    end: usize,
    insert: Vec<Atom>,
    side: Option<Side>,
}

/// What [`merge_value`] needs to know besides the inputs, so nested callers (lists
/// and tables, slides) can run it with their own parameters.
pub(crate) struct Acc {
    pub lost: Vec<Value>,
    pub review: bool,
    pub notes: Vec<String>,
}

/// The text three-way merge of one value, for this strategy and for strategies that
/// contain text (`block.same-shape`, `slide.shape`).
pub(crate) fn merge_value(i: &Inputs<'_>, ctx: &Context<'_>) -> Resolved {
    let mut acc = Acc {
        lost: Vec::new(),
        review: false,
        notes: Vec::new(),
    };
    match merge_inner(i, ctx, &mut acc) {
        Ok(value) => Resolved {
            outcome: Outcome::Merged(value),
            used: Used {
                basis: "grapheme-diff3",
                lost: acc.lost,
                notes: acc.notes,
                review: acc.review,
            },
        },
        Err(resolved) => resolved,
    }
}

#[allow(clippy::too_many_lines)]
fn merge_inner(i: &Inputs<'_>, ctx: &Context<'_>, acc: &mut Acc) -> Result<Value, Resolved> {
    let unsupported = || Resolved::conflict(Reason::UNSUPPORTED_SHAPE, "shape");
    // A missing base is an empty value of the sides' kind: two additions.
    let strings = i.team.is_string() && i.draft.is_string();
    let containers = is_inline(i.team) && is_inline(i.draft);
    if !(strings && (i.base.is_string() || i.base.is_null())
        || containers && (is_inline(i.base) || i.base.is_null()))
    {
        return Err(unsupported());
    }
    let mut styles = Styles::default();
    let (Some(b), Some(t), Some(d)) = (
        atoms(i.base, &mut styles),
        atoms(i.team, &mut styles),
        atoms(i.draft, &mut styles),
    ) else {
        return Err(Resolved::conflict(Reason::TOO_LARGE, "bound"));
    };
    let mut props = Value::Null;
    if containers {
        let strip = |v: &Value| {
            let mut m = v.as_object().cloned().unwrap_or_default();
            m.remove("content");
            Value::Object(m)
        };
        let base_props = (!i.base.is_null()).then(|| strip(i.base));
        match crate::richtext::merge_property(
            base_props.as_ref(),
            Some(&strip(i.team)),
            Some(&strip(i.draft)),
        ) {
            Ok(Some(p)) => props = p,
            _ => {
                return Err(Resolved::prefer_role_or(
                    ctx,
                    "replace_conflict",
                    i,
                    Reason::OVERLAP,
                    "container-attributes",
                ))
            }
        }
    }
    let (tm, th) = align(&b, &t, Side::Team);
    let (dm, dh) = align(&b, &d, Side::Draft);
    let max = ctx
        .params
        .get("max_hunks")
        .and_then(Value::as_i64)
        .unwrap_or(MAX_HUNKS) as usize;
    if th.len() > max || dh.len() > max {
        return Err(Resolved::conflict(Reason::TOO_MANY_HUNKS, "bound"));
    }
    // Clusters of interacting hunks, in base order (see the module notes).
    let mut all: Vec<Hunk> = th.into_iter().chain(dh).collect();
    all.sort_by_key(|h| (h.start, h.end, h.side));
    let mut clusters: Vec<Vec<Hunk>> = Vec::new();
    for h in all {
        match clusters.last_mut() {
            Some(c) if c.iter().any(|m| m.side != h.side && interact(m, &h)) => c.push(h),
            _ => clusters.push(vec![h]),
        }
    }
    let side_of = |s: Side| -> &[Atom] {
        match s {
            Side::Team => &t,
            Side::Draft => &d,
        }
    };
    let mut edits: Vec<Edit> = Vec::new();
    for cluster in clusters {
        let (team, draft): (Vec<&Hunk>, Vec<&Hunk>) =
            cluster.iter().partition(|h| h.side == Side::Team);
        if team.is_empty() || draft.is_empty() {
            edits.extend(cluster.iter().map(|h| Edit {
                start: h.start,
                end: h.end,
                insert: h.insert.clone(),
                side: Some(h.side),
            }));
            continue;
        }
        let start = cluster.iter().map(|h| h.start).min().unwrap_or(0);
        let end = cluster.iter().map(|h| h.end).max().unwrap_or(0);
        if team.len() == draft.len() && team.iter().zip(&draft).all(|(x, y)| x.same_edit(y)) {
            if team.iter().all(|h| h.pure_insert())
                && ctx.param("identical_insert", "dedupe") == "manual"
            {
                return Err(Resolved::conflict(Reason::OVERLAP, "identical-insert"));
            }
            edits.extend(team.iter().map(|h| Edit {
                start: h.start,
                end: h.end,
                insert: h.insert.clone(),
                side: None,
            }));
            continue;
        }
        if let ([x], [y]) = (team.as_slice(), draft.as_slice()) {
            if x.pure_insert() && y.pure_insert() {
                // Content order, never side order (law L1, NC-Q2).
                let text = |h: &Hunk| -> (String, Vec<u8>) {
                    let s: String = h.insert.iter().map(|a| a.key.as_str()).collect();
                    let style: Vec<u8> = h
                        .insert
                        .iter()
                        .flat_map(|a| crate::hashing::canonical_json(&styles.values[a.style]))
                        .collect();
                    (s, style)
                };
                let (first, second) = if text(x) <= text(y) { (x, y) } else { (y, x) };
                let mut insert = first.insert.clone();
                insert.extend(second.insert.iter().cloned());
                acc.review = true;
                acc.notes.push(format!(
                    "two different insertions at atom {start}, ordered by their text"
                ));
                edits.push(Edit {
                    start,
                    end,
                    insert,
                    side: None,
                });
                continue;
            }
        }
        if cluster.iter().all(Hunk::pure_delete) {
            edits.push(Edit {
                start,
                end,
                insert: Vec::new(),
                side: None,
            });
            continue;
        }
        // One side only deletes; every insertion of the other is a pure insertion.
        let deleter = [Side::Team, Side::Draft].into_iter().find(|s| {
            let (mine, theirs) = if *s == Side::Team {
                (&team, &draft)
            } else {
                (&draft, &team)
            };
            mine.iter().all(|h| h.pure_delete())
                && theirs.iter().all(|h| h.pure_delete() || h.pure_insert())
        });
        if let Some(deleter) = deleter {
            if ctx.param("delete_vs_insert", "keep-insert") != "keep-insert" {
                return Err(Resolved::conflict(Reason::OVERLAP, "delete-vs-insert"));
            }
            let inserter = deleter.other();
            let mut insert = Vec::new();
            for h in cluster.iter().filter(|h| h.side == inserter) {
                insert.extend(h.insert.iter().cloned());
            }
            acc.lost.push(i.side(inserter).clone());
            acc.review = true;
            acc.notes.push(format!(
                "text deleted on one side had an insertion on the other at atoms {start}..{end}; the insertion was kept"
            ));
            edits.push(Edit {
                start,
                end,
                insert,
                side: Some(inserter),
            });
            continue;
        }
        return Err(Resolved::prefer_role_or(
            ctx,
            "replace_conflict",
            i,
            Reason::OVERLAP,
            "replace-replace",
        ));
    }
    edits.sort_by_key(|e| (e.start, e.end));
    let mut covered = vec![false; b.len()];
    for e in &edits {
        for c in &mut covered[e.start..e.end] {
            *c = true;
        }
    }
    let marks_rule = ctx.marks;
    let marks_params = marks_rule.map(|r| r.params);
    let empty = BTreeMap::new();
    let marks_ctx = Context {
        params: marks_params.unwrap_or(&empty),
        marks: None,
        ..*ctx
    };
    let mut out: Vec<Atom> = Vec::new();
    let mut cursor = 0;
    let sentinel = Edit {
        start: b.len(),
        end: b.len(),
        insert: Vec::new(),
        side: None,
    };
    for e in edits.iter().chain(std::iter::once(&sentinel)) {
        for k in cursor..e.start {
            let (Some(ti), Some(di)) = (tm[k], dm[k]) else {
                return Err(Resolved::conflict(Reason::OVERLAP, "alignment"));
            };
            let (bs, ts, ds) = (b[k].style, t[ti].style, d[di].style);
            let style = if ts == ds || ds == bs {
                ts
            } else if ts == bs {
                ds
            } else {
                // Both sides changed this atom's formatting differently.
                match marks_rule.map(|r| r.gate) {
                    Some(Gate::Manual | Gate::Blocked) => {
                        return Err(Resolved::conflict(Reason::OVERLAP, "marks-gate"));
                    }
                    Some(Gate::AutoWithReview) => acc.review = true,
                    _ => {}
                }
                let meta = |s: usize| styles.values[s].clone();
                let (bm, tmeta, dmeta) = (meta(bs), meta(ts), meta(ds));
                let sub = Inputs {
                    base: &bm,
                    team: &tmeta,
                    draft: &dmeta,
                };
                let r = marks::merge_meta(&sub, &marks_ctx);
                match r.outcome {
                    Outcome::Merged(v) => styles.intern(v),
                    Outcome::Prefer(side) => {
                        acc.lost.push(i.side(side.other()).clone());
                        acc.review = true;
                        styles.intern(sub.side(side).clone())
                    }
                    Outcome::Conflict(reason) => {
                        return Err(Resolved::prefer_role_or(
                            ctx,
                            "replace_conflict",
                            i,
                            reason,
                            "marks",
                        ));
                    }
                }
            };
            out.push(Atom {
                key: b[k].key.clone(),
                style,
            });
        }
        let mut insert = e.insert.clone();
        if let Some(side) = e.side {
            let other = side_of(side.other());
            let other_map = if side == Side::Team { &dm } else { &tm };
            let neighbour = |k: Option<usize>| -> Option<(Value, Value)> {
                let k = k.filter(|k| *k < b.len() && !covered[*k])?;
                let o = other_map[k]?;
                Some((
                    styles.values[b[k].style].clone(),
                    styles.values[other[o].style].clone(),
                ))
            };
            let prev = neighbour(e.start.checked_sub(1));
            let next = neighbour(Some(e.end));
            if grow(&mut insert, prev, next, &mut styles) {
                acc.review = true;
            }
        }
        out.extend(insert);
        cursor = e.end;
    }
    if strings {
        return Ok(Value::String(out.iter().map(|a| a.key.as_str()).collect()));
    }
    let mut value = props.as_object().cloned().unwrap_or_else(Map::new);
    let kids = children(&out, &styles);
    if !kids.is_empty()
        || [i.base, i.team, i.draft]
            .iter()
            .any(|v| v.get("content").is_some())
    {
        value.insert("content".into(), json!(kids));
    }
    Ok(Value::Object(value))
}

/// The marks of a metadata object, by type.
fn mark_map(meta: &Value) -> BTreeMap<String, Value> {
    meta["marks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| Some((m["type"].as_str()?.to_string(), m.clone())))
        .collect()
}

/// Peritext-style growth (design 4.3): whether an inserted atom takes a mark the
/// other side added on (or drops one it removed from) the text around the gap.
fn grows_at_end(mark: &str) -> bool {
    matches!(
        mark,
        "bold" | "italic" | "underline" | "strike" | "code" | "textStyle"
    )
}

/// Apply growth to `insert`; true when any inserted atom changed.
fn grow(
    insert: &mut [Atom],
    prev: Option<(Value, Value)>,
    next: Option<(Value, Value)>,
    styles: &mut Styles,
) -> bool {
    // (mark type, Some(value) for added, None for removed) on a neighbour.
    let changes = |n: &Option<(Value, Value)>| -> BTreeMap<String, Option<Value>> {
        let Some((base, other)) = n else {
            return BTreeMap::new();
        };
        let (b, o) = (mark_map(base), mark_map(other));
        let mut out = BTreeMap::new();
        for (k, v) in &o {
            if b.get(k) != Some(v) {
                out.insert(k.clone(), Some(v.clone()));
            }
        }
        for k in b.keys() {
            if !o.contains_key(k) {
                out.insert(k.clone(), None);
            }
        }
        out
    };
    let (before, after) = (changes(&prev), changes(&next));
    let mut apply: BTreeMap<String, Option<Value>> = BTreeMap::new();
    for (k, v) in &before {
        if after.get(k) == Some(v) || grows_at_end(k) {
            apply.insert(k.clone(), v.clone());
        }
    }
    if apply.is_empty() {
        return false;
    }
    let mut changed = false;
    for atom in insert.iter_mut().filter(|a| !is_leaf(a)) {
        let meta = styles.values[atom.style].clone();
        let Some(obj) = meta.as_object() else {
            continue;
        };
        let mut marks = mark_map(&meta);
        for (k, v) in &apply {
            match v {
                Some(mark) => {
                    marks.insert(k.clone(), mark.clone());
                }
                None => {
                    marks.remove(k);
                }
            }
        }
        let mut obj = obj.clone();
        // Existing marks keep their order; new ones follow in type order.
        let mut list: Vec<Value> = meta["marks"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| marks.remove(m["type"].as_str()?))
            .collect();
        list.extend(marks.into_values());
        if list.is_empty() {
            obj.remove("marks");
        } else {
            obj.insert("marks".into(), Value::Array(list));
        }
        let style = styles.intern(Value::Object(obj));
        if style != atom.style {
            atom.style = style;
            changed = true;
        }
    }
    changed
}

/// The run boundaries of an inline container that fall inside a grapheme cluster of
/// its plain text (INV-T1). A value without runs has none.
pub fn split_clusters(value: &Value) -> usize {
    let Some(children) = value["content"].as_array().filter(|_| is_inline(value)) else {
        return 0;
    };
    let mut text = String::new();
    let mut boundaries = Vec::new();
    for child in children {
        if let Some(s) = child["text"].as_str() {
            text.push_str(s);
        } else {
            text.push_str(LEAF);
        }
        boundaries.push(text.len());
    }
    boundaries.pop();
    let cluster_ends: std::collections::BTreeSet<usize> = text
        .grapheme_indices(true)
        .map(|(i, g)| i + g.len())
        .collect();
    boundaries
        .iter()
        .filter(|b| **b > 0 && !cluster_ends.contains(b))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge_policy::{policy::Role, Family};

    fn run(b: Value, t: Value, d: Value, params: &[(&str, &str)]) -> Resolved {
        let params: BTreeMap<String, Value> = params
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect();
        let rank = [Role::Owner, Role::Editor];
        let ctx = Context {
            node: None,
            node_type: "item",
            field: "content",
            aspect: None,
            family: Family::Document,
            params: &params,
            roles: Some((Role::Editor, Role::Owner)),
            rank: &rank,
            marks: None,
        };
        Diff3Grapheme.resolve(
            &Inputs {
                base: &b,
                team: &t,
                draft: &d,
            },
            &ctx,
        )
    }

    fn para(runs: &[(&str, &[&str])]) -> Value {
        let content: Vec<Value> = runs
            .iter()
            .map(|(text, marks)| {
                let mut v = json!({"type":"text","text":text});
                if !marks.is_empty() {
                    v["marks"] =
                        json!(marks.iter().map(|m| json!({"type": m})).collect::<Vec<_>>());
                }
                v
            })
            .collect();
        json!({"type":"paragraph","content":content})
    }

    #[test]
    fn same_gap_insertions_are_both_kept_in_text_order_in_either_orientation() {
        let b = json!("The cat sat.");
        let t = json!("The black cat sat.");
        let d = json!("The fat cat sat.");
        for (x, y) in [(&t, &d), (&d, &t)] {
            let r = run(b.clone(), x.clone(), y.clone(), &[]);
            assert_eq!(r.outcome, Outcome::Merged(json!("The black fat cat sat.")));
            assert!(r.used.review);
            assert!(r.used.lost.is_empty());
        }
    }

    #[test]
    fn identical_insertions_dedupe_unless_manual() {
        let b = json!("ab");
        // The equal insertion `X` is applied once; the two different ones at the end
        // follow in bytewise order (`!` before `c`).
        assert_eq!(
            run(b.clone(), json!("aXbc"), json!("aXb!"), &[]).outcome,
            Outcome::Merged(json!("aXb!c"))
        );
        assert_eq!(
            run(
                b,
                json!("aXbc"),
                json!("aXb!"),
                &[("identical_insert", "manual")]
            )
            .outcome,
            Outcome::Conflict(Reason::OVERLAP)
        );
    }

    #[test]
    fn overlapping_deletions_take_the_union() {
        let r = run(json!("abcdef"), json!("af"), json!("abef"), &[]);
        assert_eq!(r.outcome, Outcome::Merged(json!("af")));
    }

    #[test]
    fn delete_versus_insert_keeps_the_insert_and_preserves_the_loser() {
        let t = json!("ae");
        let d = json!("abXcde");
        let r = run(json!("abcde"), t.clone(), d.clone(), &[]);
        assert_eq!(r.outcome, Outcome::Merged(json!("aXe")));
        assert_eq!(r.used.lost, vec![d.clone()]);
        assert!(r.used.review);
        let manual = run(json!("abcde"), t, d, &[("delete_vs_insert", "manual")]);
        assert_eq!(manual.outcome, Outcome::Conflict(Reason::OVERLAP));
    }

    #[test]
    fn replace_replace_is_manual_or_prefers_the_higher_role_with_the_loser_kept() {
        let (b, t, d) = (json!("one two"), json!("one 2"), json!("one II"));
        assert_eq!(
            run(b.clone(), t.clone(), d.clone(), &[]).outcome,
            Outcome::Conflict(Reason::OVERLAP)
        );
        // The draft author is the owner, who ranks above the editor.
        let r = run(b, t.clone(), d, &[("replace_conflict", "prefer-role")]);
        assert_eq!(r.outcome, Outcome::Prefer(Side::Draft));
        assert_eq!(r.used.lost, vec![t]);
    }

    #[test]
    fn a_bengali_conjunct_is_one_atom_and_never_split() {
        // ক্ষ (U+0995 U+09CD U+09B7) is one cluster under GB9c.
        let b = json!("ক্ষমা");
        assert_eq!("ক্ষমা".graphemes(true).count(), 2);
        let t = json!("ক্ষমাX");
        let d = json!("Yক্ষমা");
        let r = run(b, t, d, &[]);
        assert_eq!(r.outcome, Outcome::Merged(json!("Yক্ষমাX")));
    }

    #[test]
    fn deletion_wins_over_formatting_of_the_deleted_text() {
        let b = para(&[("keep this gone", &[])]);
        let t = para(&[("keep ", &[]), ("this", &["bold"]), (" gone", &[])]);
        let d = para(&[("keep gone", &[])]);
        let r = run(b, t, d, &[]);
        assert_eq!(r.outcome, Outcome::Merged(para(&[("keep gone", &[])])));
    }

    #[test]
    fn an_insertion_inside_bold_text_becomes_bold() {
        let b = para(&[("ab", &[])]);
        let t = para(&[("ab", &["bold"])]);
        let d = para(&[("aXb", &[])]);
        let r = run(b, t, d, &[]);
        assert_eq!(r.outcome, Outcome::Merged(para(&[("aXb", &["bold"])])));
        assert!(r.used.review);
    }

    #[test]
    fn run_boundaries_inside_a_cluster_are_counted() {
        let split = json!({"type":"paragraph","content":[
            {"type":"text","text":"ক্"},{"type":"text","text":"ষ","marks":[{"type":"bold"}]}]});
        assert_eq!(split_clusters(&split), 1);
        assert_eq!(split_clusters(&para(&[("ক্ষ", &[]), ("মা", &["bold"])])), 0);
    }
}
