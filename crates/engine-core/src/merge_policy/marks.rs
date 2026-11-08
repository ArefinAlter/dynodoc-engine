//! `dynodoc.marks.set.v1` (design 4.3): formatting marks of one run of text merged
//! as a set keyed by mark type.
//!
//! * Mark types added or kept independently on the two sides: their union.
//! * One mark type changed on both sides in disjoint properties: merged property by
//!   property (as `richtext::merge_property` does).
//! * The same property set to different values (`color` red against blue):
//!   `attribute_conflict: manual` (the default) is a conflict, `prefer-role`
//!   prefers the side of the higher role and preserves the other.
//! * A mark removed on one side and changed on the other: `add_remove`, the same two
//!   choices.
//! * Order: a mark keeps its place relative to the marks around it on each side
//!   (schema order from the branches); marks whose relative order no side fixes
//!   follow in type order. The order is the same with the sides swapped, which
//!   `richtext::merge_marks` (team order first) does not promise.
//! * Unknown mark kinds are kept verbatim and compared by their JSON.
//!
//! As a strategy it decides an array of marks (rule `match.aspect: marks`). Text
//! strategies call `merge_meta` for each run of text both sides kept.

use super::{
    strategy::{Context, Inputs, Laws, ParamSpec, ParamType, Reason, Resolved, Strategy},
    Aspect,
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const ID: &str = "dynodoc.marks.set.v1";
const MAX_MARKS: usize = 64;

pub struct MarkSet;

const PARAMS: &[ParamSpec] = &[
    ParamSpec {
        name: "attribute_conflict",
        ty: ParamType::OneOf(&["manual", "prefer-role"]),
    },
    ParamSpec {
        name: "add_remove",
        ty: ParamType::OneOf(&["manual", "prefer-role"]),
    },
];

impl Strategy for MarkSet {
    fn id(&self) -> &'static str {
        ID
    }
    fn params(&self) -> &'static [ParamSpec] {
        PARAMS
    }
    fn aspects(&self) -> &'static [Aspect] {
        &[Aspect::Marks]
    }
    fn promises(&self) -> Laws {
        Laws::ALL
    }
    fn max_input_bytes(&self) -> Option<usize> {
        Some(1 << 16)
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
            .any(|v| serde_json::to_vec(v).map_or(usize::MAX, |b| b.len()) > 1 << 16)
        {
            return Resolved::conflict(Reason::TOO_LARGE, "bound");
        }
        match merge_list(i, ctx) {
            Ok(list) => Resolved::merged(Value::Array(list), "mark-set"),
            Err(r) => r,
        }
    }
}

/// The marks by type; `None` for a list this strategy cannot read (not a list, a
/// mark without a type, a type listed twice).
fn by_type(v: &Value) -> Option<(Vec<String>, BTreeMap<String, Value>)> {
    let list = match v {
        Value::Null => return Some((Vec::new(), BTreeMap::new())),
        Value::Array(list) if list.len() <= MAX_MARKS => list,
        _ => return None,
    };
    let mut order = Vec::new();
    let mut map = BTreeMap::new();
    for mark in list {
        let kind = mark["type"].as_str()?.to_string();
        if map.insert(kind.clone(), mark.clone()).is_some() {
            return None;
        }
        order.push(kind);
    }
    Some((order, map))
}

/// A merged order that respects each side's relative order where it can, and is
/// otherwise by type name: the same result with the sides swapped.
fn order(names: &BTreeSet<String>, a: &[String], b: &[String]) -> Vec<String> {
    let mut placed: Vec<String> = Vec::new();
    let mut rest: BTreeSet<String> = names.clone();
    while !rest.is_empty() {
        let ready = |n: &String| {
            [a, b]
                .iter()
                .all(|side| match side.iter().position(|x| x == n) {
                    Some(at) => side[..at].iter().all(|p| !rest.contains(p) || p == n),
                    None => true,
                })
        };
        let next = rest
            .iter()
            .find(|n| ready(n))
            .or_else(|| rest.iter().next())
            .cloned();
        let Some(next) = next else { break };
        rest.remove(&next);
        placed.push(next);
    }
    placed
}

fn merge_list(i: &Inputs<'_>, ctx: &Context<'_>) -> Result<Vec<Value>, Resolved> {
    let shape = || Resolved::conflict(Reason::UNSUPPORTED_SHAPE, "marks-shape");
    let (Some((_, b)), Some((to, t)), Some((do_, d))) =
        (by_type(i.base), by_type(i.team), by_type(i.draft))
    else {
        return Err(shape());
    };
    let names: BTreeSet<String> = b.keys().chain(t.keys()).chain(d.keys()).cloned().collect();
    let mut merged: BTreeMap<String, Value> = BTreeMap::new();
    for name in &names {
        let (bm, tm, dm) = (b.get(name), t.get(name), d.get(name));
        let value = if dm == bm || dm == tm {
            tm.cloned()
        } else if tm == bm {
            dm.cloned()
        } else if let (Some(tv), Some(dv)) = (tm, dm) {
            match crate::richtext::merge_property(bm, Some(tv), Some(dv)) {
                Ok(v) => v,
                Err(()) => {
                    return Err(Resolved::prefer_role_or(
                        ctx,
                        "attribute_conflict",
                        i,
                        Reason::OVERLAP,
                        "mark-attribute",
                    ))
                }
            }
        } else {
            return Err(Resolved::prefer_role_or(
                ctx,
                "add_remove",
                i,
                Reason::OVERLAP,
                "mark-added-removed",
            ));
        };
        if let Some(v) = value {
            merged.insert(name.clone(), v);
        }
    }
    let kept: BTreeSet<String> = merged.keys().cloned().collect();
    Ok(order(&kept, &to, &do_)
        .into_iter()
        .filter_map(|n| merged.remove(&n))
        .collect())
}

/// Merge the metadata of one run kept by both sides: `marks` as a mark set, every
/// other key property by property.
pub(crate) fn merge_meta(i: &Inputs<'_>, ctx: &Context<'_>) -> Resolved {
    let empty = Map::new();
    let obj = |v: &Value| v.as_object().cloned().unwrap_or_else(|| empty.clone());
    let (b, t, d) = (obj(i.base), obj(i.team), obj(i.draft));
    let keys: BTreeSet<&String> = b.keys().chain(t.keys()).chain(d.keys()).collect();
    let mut out = Map::new();
    for key in keys {
        let (bv, tv, dv) = (b.get(key), t.get(key), d.get(key));
        if key == "marks" {
            let null = Value::Null;
            let sub = Inputs {
                base: bv.unwrap_or(&null),
                team: tv.unwrap_or(&null),
                draft: dv.unwrap_or(&null),
            };
            let r = MarkSet.resolve(&sub, ctx);
            match r.outcome {
                super::Outcome::Merged(Value::Array(list)) if list.is_empty() => {}
                super::Outcome::Merged(v) if !v.is_null() => {
                    out.insert(key.clone(), v);
                }
                super::Outcome::Merged(_) => {}
                // A preference or conflict over the marks is one over the run.
                super::Outcome::Prefer(side) => return Resolved::prefer(side, i, r.used.basis),
                super::Outcome::Conflict(reason) => {
                    return Resolved::conflict(reason, r.used.basis)
                }
            }
            continue;
        }
        match crate::richtext::merge_property(bv, tv, dv) {
            Ok(Some(v)) => {
                out.insert(key.clone(), v);
            }
            Ok(None) => {}
            Err(()) => return Resolved::conflict(Reason::OVERLAP, "run-attribute"),
        }
    }
    Resolved::merged(Value::Object(out), "run-metadata")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge_policy::{policy::Role, strategy::Side, Family, Outcome};
    use serde_json::json;

    fn run(b: Value, t: Value, d: Value, params: &[(&str, &str)]) -> Resolved {
        let params: BTreeMap<String, Value> = params
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect();
        let rank = [Role::Owner, Role::Editor];
        let ctx = Context {
            node: None,
            node_type: "item",
            field: "marks",
            aspect: Some(Aspect::Marks),
            family: Family::Document,
            params: &params,
            roles: Some((Role::Owner, Role::Editor)),
            rank: &rank,
            marks: None,
        };
        MarkSet.resolve(
            &Inputs {
                base: &b,
                team: &t,
                draft: &d,
            },
            &ctx,
        )
    }

    #[test]
    fn independent_marks_union_in_the_same_order_either_way() {
        let b = json!([{"type":"bold"}]);
        let t = json!([{"type":"bold"},{"type":"italic"}]);
        let d = json!([{"type":"underline"},{"type":"bold"}]);
        let expected = json!([{"type":"underline"},{"type":"bold"},{"type":"italic"}]);
        assert_eq!(
            run(b.clone(), t.clone(), d.clone(), &[]).outcome,
            Outcome::Merged(expected.clone())
        );
        assert_eq!(run(b, d, t, &[]).outcome, Outcome::Merged(expected));
    }

    #[test]
    fn colour_against_colour_is_manual_or_prefers_the_higher_role() {
        let b = json!([{"type":"textStyle","attrs":{"color":"black"}}]);
        let t = json!([{"type":"textStyle","attrs":{"color":"red"}}]);
        let d = json!([{"type":"textStyle","attrs":{"color":"blue"}}]);
        assert_eq!(
            run(b.clone(), t.clone(), d.clone(), &[]).outcome,
            Outcome::Conflict(Reason::OVERLAP)
        );
        let r = run(b, t, d.clone(), &[("attribute_conflict", "prefer-role")]);
        assert_eq!(r.outcome, Outcome::Prefer(Side::Team));
        assert_eq!(r.used.lost, vec![d]);
    }

    #[test]
    fn removed_against_changed_is_manual_by_default() {
        let b = json!([{"type":"link","attrs":{"href":"a"}}]);
        let t = json!([]);
        let d = json!([{"type":"link","attrs":{"href":"b"}}]);
        assert_eq!(
            run(b, t, d, &[]).outcome,
            Outcome::Conflict(Reason::OVERLAP)
        );
    }
}
