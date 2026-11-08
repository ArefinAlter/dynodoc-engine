//! `dynodoc.block.same-shape.v1` (design 4.4): lists and tables merged child by child
//! when neither side changed their shape.
//!
//! Nested content has no identity, so position is identity only when nothing moved:
//! the same node types at every level and the same number of children in all three
//! versions. Then each inline container merges with the text strategy
//! ([`super::text`]), every other node's attributes merge as properties and its
//! children recursively.
//!
//! Decision 042 adds two structural cases:
//!
//! - **Nested identifiers (N4b).** When every child of a container in all three
//!   versions carries `attrs.itemId` (list items), `attrs.rowId` (table rows) or
//!   `attrs.cellId` (cells), unique within its list, children are matched by
//!   identifier: inserted, deleted and reordered items merge. An item deleted on one
//!   side and edited on the other, the same new identifier with two different values,
//!   and both sides reordering are conflicts. Insertions at one gap from both sides are
//!   kept, ordered by their first identifier bytewise (side-independent), and marked
//!   for review.
//! - **Row shifts.** Without identifiers, one side that inserted or deleted exactly
//!   one child and changed nothing else (a unique shift certificate) and another side
//!   that kept the shape are merged by moving the other side's positional edits through
//!   the shift. A deleted child the other side edited, an ambiguous certificate and a
//!   shift on both sides are conflicts; any other change of shape stays
//!   `shape-changed`.

use super::{
    strategy::{Context, Inputs, Laws, Outcome, Reason, Resolved, Strategy, Used},
    text,
};
use serde_json::{Map, Value};

pub const ID: &str = "dynodoc.block.same-shape.v1";
const MAX_DEPTH: usize = 64;
const MAX_BYTES: usize = 1 << 20;

pub struct SameShape;

impl Strategy for SameShape {
    fn id(&self) -> &'static str {
        ID
    }
    fn params(&self) -> &'static [super::strategy::ParamSpec] {
        // The text strategy's parameters apply to the cells and items.
        super::text::Diff3Grapheme.params()
    }
    fn max_input_bytes(&self) -> Option<usize> {
        Some(MAX_BYTES)
    }
    fn promises(&self) -> Laws {
        Laws::ALL
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
            .any(|v| serde_json::to_vec(v).map_or(usize::MAX, |b| b.len()) > MAX_BYTES)
        {
            return Resolved::conflict(Reason::TOO_LARGE, "bound");
        }
        let mut used = Used {
            basis: "same-shape",
            ..Used::default()
        };
        match node(i, ctx, 0, &mut used) {
            Ok(v) => Resolved {
                outcome: Outcome::Merged(v),
                used,
            },
            // A preference inside a cell is a preference for the whole value, so
            // the whole other value is the loser.
            Err(Resolved {
                outcome: Outcome::Prefer(side),
                used: inner,
            }) => Resolved::prefer(side, i, inner.basis),
            Err(r) => r,
        }
    }
}

fn props(v: &Value) -> Value {
    let mut m = v.as_object().cloned().unwrap_or_else(Map::new);
    m.remove("content");
    Value::Object(m)
}

fn node(
    i: &Inputs<'_>,
    ctx: &Context<'_>,
    depth: usize,
    used: &mut Used,
) -> Result<Value, Resolved> {
    if i.draft == i.base || i.draft == i.team {
        return Ok(i.team.clone());
    }
    if i.team == i.base {
        return Ok(i.draft.clone());
    }
    if depth > MAX_DEPTH {
        return Err(Resolved::conflict(Reason::TOO_LARGE, "depth"));
    }
    let inline = |v: &Value| {
        matches!(
            v["type"].as_str(),
            Some("paragraph" | "heading" | "codeBlock")
        )
    };
    if inline(i.base) && inline(i.team) && inline(i.draft) {
        let r = text::merge_value(i, ctx);
        return match r.outcome {
            Outcome::Merged(v) => {
                used.lost.extend(r.used.lost);
                used.notes.extend(r.used.notes);
                used.review |= r.used.review;
                Ok(v)
            }
            _ => Err(r),
        };
    }
    let shape = || Resolved::conflict(Reason::SHAPE_CHANGED, "same-shape");
    if i.base["type"] != i.team["type"] || i.base["type"] != i.draft["type"] {
        return Err(shape());
    }
    let kids = |v: &Value| v.get("content").map(|c| c.as_array().map(Vec::len));
    let (bk, tk, dk) = (kids(i.base), kids(i.team), kids(i.draft));
    if bk.is_some() != tk.is_some()
        || bk.is_some() != dk.is_some()
        || [bk, tk, dk].contains(&Some(None))
    {
        return Err(shape());
    }
    let (bp, tp, dp) = (props(i.base), props(i.team), props(i.draft));
    let mut out = match crate::richtext::merge_property(Some(&bp), Some(&tp), Some(&dp)) {
        Ok(Some(Value::Object(m))) => m,
        _ => {
            return Err(Resolved::prefer_role_or(
                ctx,
                "replace_conflict",
                i,
                Reason::OVERLAP,
                "node-attributes",
            ))
        }
    };
    if bk.is_some() {
        let empty = Vec::new();
        let list =
            |v: &'_ Value| -> Vec<Value> { v["content"].as_array().unwrap_or(&empty).clone() };
        let (b, t, d) = (list(i.base), list(i.team), list(i.draft));
        let merged = if let Some(merged) = by_identity(&b, &t, &d, ctx, depth, used)? {
            merged
        } else if b.len() == t.len() && b.len() == d.len() {
            positional(&b, &t, &d, ctx, depth, used)?
        } else {
            shifted(&b, &t, &d, ctx, depth, used)?
        };
        out.insert("content".into(), Value::Array(merged));
    }
    // A leaf (image, rule) without children is its merged attributes.
    Ok(Value::Object(out))
}

fn positional(
    b: &[Value],
    t: &[Value],
    d: &[Value],
    ctx: &Context<'_>,
    depth: usize,
    used: &mut Used,
) -> Result<Vec<Value>, Resolved> {
    let mut merged = Vec::with_capacity(b.len());
    for k in 0..b.len() {
        let sub = Inputs {
            base: &b[k],
            team: &t[k],
            draft: &d[k],
        };
        merged.push(node(&sub, ctx, depth + 1, used)?);
    }
    Ok(merged)
}

/// The identifier of a list item, table row or cell.
fn child_id(v: &Value) -> Option<&str> {
    ["itemId", "rowId", "cellId"]
        .iter()
        .find_map(|k| v["attrs"][k].as_str())
}

/// Identifiers of every child in order, when all have one and none repeats.
fn ids(list: &[Value]) -> Option<Vec<&str>> {
    let ids: Vec<&str> = list.iter().map(child_id).collect::<Option<_>>()?;
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    (unique.len() == ids.len()).then_some(ids)
}

/// Children merged by identifier (module notes); `None` when any child lacks one.
fn by_identity(
    b: &[Value],
    t: &[Value],
    d: &[Value],
    ctx: &Context<'_>,
    depth: usize,
    used: &mut Used,
) -> Result<Option<Vec<Value>>, Resolved> {
    let (Some(bi), Some(ti), Some(di)) = (ids(b), ids(t), ids(d)) else {
        return Ok(None);
    };
    // An empty list has nothing to identify: positional rules apply.
    if bi.is_empty() && (ti.is_empty() || di.is_empty()) {
        return Ok(None);
    }
    let find = |ids: &[&str], list: &'_ [Value], id: &str| -> Option<Value> {
        ids.iter().position(|x| *x == id).map(|k| list[k].clone())
    };
    let conflict = || Resolved::conflict(Reason::ELEMENT_DIFFERS, "identity");
    // Deletions: a child gone on one side must be unchanged on the other.
    for (k, id) in bi.iter().enumerate() {
        match (find(&ti, t, id), find(&di, d, id)) {
            (None, Some(other)) | (Some(other), None) if other != b[k] => return Err(conflict()),
            _ => {}
        }
    }
    // Order: at most one side reordered the children both kept.
    let survivors = |side: &[&str]| -> Vec<String> {
        side.iter()
            .filter(|id| bi.contains(id))
            .map(|id| id.to_string())
            .collect()
    };
    let in_base_order = |side: &[&str]| -> Vec<String> {
        bi.iter()
            .filter(|id| side.contains(id))
            .map(|id| id.to_string())
            .collect()
    };
    let t_moved = survivors(&ti) != in_base_order(&ti);
    let d_moved = survivors(&di) != in_base_order(&di);
    if t_moved && d_moved && survivors(&ti) != survivors(&di) {
        return Err(Resolved::conflict(Reason::SHAPE_CHANGED, "both-reordered"));
    }
    let reference: Vec<&str> = if d_moved { di.clone() } else { ti.clone() };
    let alive: Vec<&str> = reference
        .iter()
        .copied()
        .filter(|id| bi.contains(id) && ti.contains(id) && di.contains(id))
        .collect();
    let (tr, dr) = (runs(&ti, &alive, &bi), runs(&di, &alive, &bi));
    let mut merged = Vec::new();
    let place = |anchor: Option<&str>, merged: &mut Vec<Value>, used: &mut Used| {
        let mine = tr
            .iter()
            .find(|(a, _)| *a == anchor)
            .map(|(_, r)| r.clone());
        let theirs = dr
            .iter()
            .find(|(a, _)| *a == anchor)
            .map(|(_, r)| r.clone());
        let mut groups: Vec<(Vec<&str>, &[&str], &[Value])> = Vec::new();
        if let Some(r) = mine {
            groups.push((r, &ti, t));
        }
        if let Some(r) = theirs {
            if groups.first().is_none_or(|g| g.0 != r) {
                groups.push((r, &di, d));
            }
        }
        if groups.len() == 2 {
            used.review = true;
            used.notes.push("both sides inserted at one place".into());
            groups.sort_by(|a, b| a.0[0].cmp(b.0[0]));
        }
        for (run, side_ids, side) in groups {
            for id in run {
                if let Some(v) = find(side_ids, side, id) {
                    merged.push(v);
                }
            }
        }
    };
    place(None, &mut merged, used);
    for id in &alive {
        let (Some(base), Some(team), Some(draft)) =
            (find(&bi, b, id), find(&ti, t, id), find(&di, d, id))
        else {
            continue;
        };
        let sub = Inputs {
            base: &base,
            team: &team,
            draft: &draft,
        };
        merged.push(node(&sub, ctx, depth + 1, used)?);
        place(Some(id), &mut merged, used);
    }
    // The same new identifier inserted on both sides must be one value.
    let mut seen: std::collections::BTreeMap<&str, &Value> = std::collections::BTreeMap::new();
    for v in &merged {
        if let Some(id) = child_id(v) {
            if seen.insert(id, v).is_some_and(|other| other != v) {
                return Err(conflict());
            }
        }
    }
    let mut unique = std::collections::BTreeSet::new();
    merged.retain(|v| child_id(v).is_none_or(|id| unique.insert(id.to_string())));
    used.notes.push("children matched by identifier".into());
    Ok(Some(merged))
}

/// Insertion runs after each alive child (`None`: at the start) on one side.
fn runs<'a>(
    side: &[&'a str],
    alive: &[&str],
    base: &[&str],
) -> Vec<(Option<&'a str>, Vec<&'a str>)> {
    let mut out: Vec<(Option<&'a str>, Vec<&'a str>)> = Vec::new();
    let mut anchor: Option<&'a str> = None;
    for id in side {
        if alive.contains(id) {
            anchor = Some(id);
        } else if !base.contains(id) {
            match out.last_mut() {
                Some((a, run)) if *a == anchor => run.push(id),
                _ => out.push((anchor, vec![id])),
            }
        }
    }
    out
}

/// The unique position where `longer` has one extra child and is otherwise `shorter`.
fn one_extra(shorter: &[Value], longer: &[Value]) -> Result<Option<usize>, ()> {
    if longer.len() != shorter.len() + 1 {
        return Ok(None);
    }
    let fits = |k: usize| longer[..k] == shorter[..k] && longer[k + 1..] == shorter[k..];
    let found: Vec<usize> = (0..longer.len()).filter(|k| fits(*k)).collect();
    match found.as_slice() {
        [] => Ok(None),
        [k] => Ok(Some(*k)),
        // Equal neighbours: the shift could be at either; edits would map differently.
        _ => Err(()),
    }
}

/// One side inserted or deleted one child and changed nothing else; the other kept
/// the shape: move the other side's edits through the shift (module notes).
fn shifted(
    b: &[Value],
    t: &[Value],
    d: &[Value],
    ctx: &Context<'_>,
    depth: usize,
    used: &mut Used,
) -> Result<Vec<Value>, Resolved> {
    let shape = || Resolved::conflict(Reason::SHAPE_CHANGED, "same-shape");
    let ambiguous = || Resolved::conflict(Reason::AMBIGUOUS_SHIFT, "shift");
    // (the shifting side, the other side)
    let (s, o) = if t.len() != b.len() && d.len() == b.len() {
        (t, d)
    } else if d.len() != b.len() && t.len() == b.len() {
        (d, t)
    } else {
        return Err(shape());
    };
    if let Some(k) = one_extra(b, s).map_err(|_| ambiguous())? {
        // Inserted at k: the other side's children keep their places around it.
        let mut merged = positional(b, b, o, ctx, depth, used)?;
        merged.insert(k, s[k].clone());
        used.notes
            .push(format!("one child inserted at {k} on one side"));
        return Ok(merged);
    }
    if let Some(k) = one_extra(s, b).map_err(|_| ambiguous())? {
        if o[k] != b[k] {
            return Err(Resolved::conflict(Reason::ELEMENT_DIFFERS, "shift"));
        }
        let mut merged = positional(b, b, o, ctx, depth, used)?;
        merged.remove(k);
        used.notes
            .push(format!("one child deleted at {k} on one side"));
        return Ok(merged);
    }
    Err(shape())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge_policy::Family;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn run(b: Value, t: Value, d: Value) -> Outcome {
        let params = BTreeMap::new();
        let ctx = Context {
            node: None,
            node_type: "item",
            field: "content",
            aspect: None,
            family: Family::Document,
            params: &params,
            roles: None,
            rank: &[],
            marks: None,
        };
        SameShape
            .resolve(
                &Inputs {
                    base: &b,
                    team: &t,
                    draft: &d,
                },
                &ctx,
            )
            .outcome
    }

    fn list(items: &[&str]) -> Value {
        json!({"type":"bulletList","content": items.iter().map(|t| json!({
            "type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":t}]}]
        })).collect::<Vec<_>>()})
    }

    #[test]
    fn edits_to_different_items_merge_when_the_shape_is_unchanged() {
        let r = run(
            list(&["one", "two"]),
            list(&["one!", "two"]),
            list(&["one", "two?"]),
        );
        assert_eq!(r, Outcome::Merged(list(&["one!", "two?"])));
    }

    #[test]
    fn an_inserted_item_without_identifiers_shifts_the_other_sides_edits() {
        let r = run(
            list(&["one", "two"]),
            list(&["one", "new", "two"]),
            list(&["one", "two?"]),
        );
        assert_eq!(r, Outcome::Merged(list(&["one", "new", "two?"])));
        // A deleted item the other side edited, and an insertion that also edits, are not.
        let r = run(
            list(&["one", "two"]),
            list(&["two"]),
            list(&["one!", "two"]),
        );
        assert_eq!(r, Outcome::Conflict(Reason::ELEMENT_DIFFERS));
        let r = run(
            list(&["one", "two"]),
            list(&["one!", "new", "two"]),
            list(&["one", "two?"]),
        );
        assert_eq!(r, Outcome::Conflict(Reason::SHAPE_CHANGED));
        // Equal neighbours make the shift ambiguous.
        let r = run(list(&["x", "x"]), list(&["x", "x", "x"]), list(&["x", "y"]));
        assert_eq!(r, Outcome::Conflict(Reason::AMBIGUOUS_SHIFT));
    }

    fn rows(items: &[(&str, &str)]) -> Value {
        json!({"type":"bulletList","content": items.iter().map(|(id, t)| json!({
            "type":"listItem","attrs":{"itemId":id},"content":[{"type":"paragraph","content":[{"type":"text","text":t}]}]
        })).collect::<Vec<_>>()})
    }

    #[test]
    fn identified_items_merge_inserts_deletes_and_moves_in_either_orientation() {
        let base = rows(&[("a", "one"), ("b", "two"), ("c", "three")]);
        let team = rows(&[("a", "one"), ("x", "new"), ("b", "two"), ("c", "three!")]);
        let draft = rows(&[("c", "three"), ("a", "one?"), ("b", "two")]);
        let want = rows(&[("c", "three!"), ("a", "one?"), ("x", "new"), ("b", "two")]);
        assert_eq!(
            run(base.clone(), team.clone(), draft.clone()),
            Outcome::Merged(want.clone())
        );
        assert_eq!(run(base.clone(), draft, team), Outcome::Merged(want));
        // Deleted on one side, edited on the other.
        let r = run(
            base.clone(),
            rows(&[("a", "one"), ("c", "three")]),
            rows(&[("a", "one"), ("b", "two!"), ("c", "three")]),
        );
        assert_eq!(r, Outcome::Conflict(Reason::ELEMENT_DIFFERS));
        // Both inserted at one gap: kept in identifier order whichever side is which.
        let one = rows(&[("a", "one"), ("q", "Q"), ("b", "two"), ("c", "three")]);
        let two = rows(&[("a", "one"), ("p", "P"), ("b", "two"), ("c", "three")]);
        let both = rows(&[
            ("a", "one"),
            ("p", "P"),
            ("q", "Q"),
            ("b", "two"),
            ("c", "three"),
        ]);
        assert_eq!(
            run(base.clone(), one.clone(), two.clone()),
            Outcome::Merged(both.clone())
        );
        assert_eq!(run(base, two, one), Outcome::Merged(both));
    }
}
