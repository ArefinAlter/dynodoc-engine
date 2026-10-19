//! State-based three-way merge for document blocks and spreadsheet cells.
//! Deletion versus editing is a conflict, including structural edits. Canonical
//! history is never replaced: `diff` emits new semantic operations only.
use crate::materializer::{DocumentState, MaterializedNode};
use engine_shared::{EventPayload, NodeId};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub key: String,
    pub node_id: NodeId,
    pub field: String,
    pub ancestor: Value,
    pub team: Value,
    pub draft: Value,
}
#[derive(Debug, Serialize)]
pub struct MergePlan {
    pub state: DocumentState,
    pub conflicts: Vec<Conflict>,
    pub ops: Vec<EventPayload>,
}
fn canonical(s: &DocumentState) -> Cow<'_, DocumentState> {
    if s.removed_choices.is_empty() {
        return Cow::Borrowed(s);
    }
    let mut s = s.clone();
    for id in &s.removed_choices {
        if let Some(n) = s.nodes.get_mut(id) {
            n.deleted = true;
        }
    }
    Cow::Owned(s)
}
fn location(n: &MaterializedNode) -> Value {
    json!({"parent_id":n.parent_id,"pos":n.pos})
}
fn value(n: Option<&MaterializedNode>) -> Value {
    n.map_or(Value::Null, |n| json!(n))
}
fn select(
    id: &NodeId,
    field: &str,
    base: Value,
    team: Value,
    draft: Value,
    resolutions: &BTreeMap<String, String>,
    conflicts: &mut Vec<Conflict>,
) -> Value {
    if draft == base || draft == team {
        return team;
    }
    if team == base {
        return draft;
    }
    if field == "content" {
        if let Some(merged) = crate::richtext::merge(&base, &team, &draft) {
            return merged;
        }
    }
    let key = format!("{}:{field}", id.0);
    match resolutions.get(&key).map(String::as_str) {
        Some("draft") => draft,
        Some("team") => team,
        _ => {
            conflicts.push(Conflict {
                key,
                node_id: id.clone(),
                field: field.into(),
                ancestor: base,
                team: team.clone(),
                draft,
            });
            team
        }
    }
}
pub fn merge(
    base: &DocumentState,
    team: &DocumentState,
    draft: &DocumentState,
    resolutions: &BTreeMap<String, String>,
) -> MergePlan {
    let base = canonical(base);
    let team = canonical(team);
    let draft = canonical(draft);
    let mut out = team.clone().into_owned();
    let mut conflicts = Vec::new();
    for (id, d) in &draft.nodes {
        let b = base.nodes.get(id);
        let t = team.nodes.get(id);
        if b == Some(d) {
            continue;
        }
        // Existence or a tombstone crosses the entire node, so delete/edit cannot
        // be silently merged by treating the deleted flag as an independent field.
        if b.is_none()
            || t.is_none()
            || b.is_some_and(|b| b.deleted != d.deleted)
            || t.zip(b).is_some_and(|(t, b)| t.deleted != b.deleted)
        {
            let picked = select(
                id,
                "$node",
                value(b),
                value(t),
                value(Some(d)),
                resolutions,
                &mut conflicts,
            );
            if let Ok(node) = serde_json::from_value(picked) {
                out.nodes.insert(id.clone(), node);
            }
            continue;
        }
        let b = b.unwrap();
        let t = t.unwrap();
        let mut n = t.clone();
        let loc = select(
            id,
            "$location",
            location(b),
            location(t),
            location(d),
            resolutions,
            &mut conflicts,
        );
        n.parent_id = serde_json::from_value(loc["parent_id"].clone()).unwrap_or(None);
        n.pos = loc["pos"].as_str().unwrap_or(&t.pos).into();
        n.var_name = serde_json::from_value(select(
            id,
            "var_name",
            json!(b.var_name),
            json!(t.var_name),
            json!(d.var_name),
            resolutions,
            &mut conflicts,
        ))
        .unwrap_or(None);
        let keys: BTreeSet<_> = b
            .current_fields
            .as_object()
            .into_iter()
            .flat_map(|o| o.keys())
            .chain(
                d.current_fields
                    .as_object()
                    .into_iter()
                    .flat_map(|o| o.keys()),
            )
            .collect();
        for key in keys {
            if key == "label"
                && b.current_fields["content"].is_object()
                && t.current_fields["content"].is_object()
                && d.current_fields["content"].is_object()
            {
                continue;
            }
            let v = select(
                id,
                key,
                b.current_fields[key].clone(),
                t.current_fields[key].clone(),
                d.current_fields[key].clone(),
                resolutions,
                &mut conflicts,
            );
            if !v.is_null() || n.current_fields.get(key).is_some() {
                n.current_fields[key] = v;
            }
        }
        if b.current_fields["content"].is_object()
            && t.current_fields["content"].is_object()
            && d.current_fields["content"].is_object()
        {
            n.current_fields["label"] =
                json!(crate::richtext::plain_text(&n.current_fields["content"]));
        }
        out.nodes.insert(id.clone(), n);
    }
    out.removed_choices
        .retain(|id| out.nodes.get(id).is_some_and(|n| n.deleted));
    validate_merged_tree(&base, &team, &draft, &mut out, &mut conflicts, resolutions);
    let ops = diff(&team, &out);
    MergePlan {
        state: out,
        conflicts,
        ops,
    }
}
/// Merge for content that does not share history with the team version, such as a
/// different file uploaded under the same name. Besides ordinary overlaps, every
/// change to a block that already exists in the team version needs an explicit
/// choice (`"<node>:$block"` → `"team"` or `"draft"`), as Git asks for both sides of
/// an add/add conflict. New blocks merge without a choice.
pub fn merge_strict(
    base: &DocumentState,
    team: &DocumentState,
    draft: &DocumentState,
    resolutions: &BTreeMap<String, String>,
) -> MergePlan {
    let mut plan = merge(base, team, draft, resolutions);
    let canonical_team = canonical(team);
    let canonical_draft = canonical(draft);
    let touched: BTreeSet<NodeId> = diff(base, draft)
        .iter()
        .filter_map(|op| op.target_node_id().cloned())
        .collect();
    let already: BTreeSet<NodeId> = plan.conflicts.iter().map(|c| c.node_id.clone()).collect();
    for id in touched.difference(&already) {
        let Some(t) = canonical_team.nodes.get(id).filter(|t| !t.deleted) else {
            continue;
        };
        let d = canonical_draft.nodes.get(id);
        if d == Some(t) || t.parent_id.is_none() {
            continue;
        }
        let key = format!("{}:$block", id.0);
        match resolutions.get(&key).map(String::as_str) {
            Some("draft") => {}
            choice => {
                if choice != Some("team") {
                    plan.conflicts.push(Conflict {
                        key,
                        node_id: id.clone(),
                        field: "$block".into(),
                        ancestor: value(base.nodes.get(id)),
                        team: value(Some(t)),
                        draft: value(d),
                    });
                }
                plan.state.nodes.insert(id.clone(), t.clone());
            }
        }
    }
    plan.state
        .removed_choices
        .retain(|id| plan.state.nodes.get(id).is_some_and(|n| n.deleted));
    validate_merged_tree(
        base,
        team,
        draft,
        &mut plan.state,
        &mut plan.conflicts,
        resolutions,
    );
    plan.ops = diff(team, &plan.state);
    plan
}

fn find_parent_cycles(state: &DocumentState) -> Vec<Vec<NodeId>> {
    let mut cycles = Vec::new();
    let mut visited: BTreeSet<NodeId> = BTreeSet::new();

    for id in state.nodes.keys() {
        if visited.contains(id) {
            continue;
        }

        let mut path: Vec<NodeId> = Vec::new();
        let mut on_path: BTreeSet<NodeId> = BTreeSet::new();
        let mut curr = Some(id.clone());

        while let Some(current_id) = curr {
            if visited.contains(&current_id) {
                break;
            }
            if on_path.contains(&current_id) {
                if let Some(pos) = path.iter().position(|x| x == &current_id) {
                    cycles.push(path[pos..].to_vec());
                }
                break;
            }
            on_path.insert(current_id.clone());
            path.push(current_id.clone());
            curr = state
                .nodes
                .get(&current_id)
                .and_then(|n| n.parent_id.clone());
        }

        visited.extend(path);
    }
    cycles
}

fn validate_merged_tree(
    base: &DocumentState,
    team: &DocumentState,
    draft: &DocumentState,
    out: &mut DocumentState,
    conflicts: &mut Vec<Conflict>,
    resolutions: &BTreeMap<String, String>,
) {
    // Resolving an orphan can undo a move and create a cycle; resolving a
    // cycle can move a block back beneath a deleted container. Recheck both.
    for _ in 0..=out.nodes.len() {
        if !resolve_parent_cycles(base, team, draft, out, conflicts, resolutions) {
            break;
        }
        resolve_orphans(base, team, draft, out, conflicts, resolutions);
        if find_parent_cycles(out).is_empty() && find_direct_orphan(out).is_none() {
            return;
        }
    }

    // Incompatible choices must remain conflicts, never a successful plan with
    // an invalid tree. Fall back to team's structure while retaining merged
    // fields on its live nodes. This is a preview; callers reject conflicts.
    for (id, node) in &mut out.nodes {
        let team_node = team.nodes.get(id);
        if team_node.is_none_or(|t| location(t) != location(node) || t.deleted != node.deleted) {
            let key = format!("{}:$location", id.0);
            if !conflicts.iter().any(|c| c.key == key) {
                conflicts.push(Conflict {
                    key,
                    node_id: id.clone(),
                    field: "$location".into(),
                    ancestor: base.nodes.get(id).map(location).unwrap_or(Value::Null),
                    team: team_node.map(location).unwrap_or(Value::Null),
                    draft: draft.nodes.get(id).map(location).unwrap_or(Value::Null),
                });
            }
        }
        if let Some(team_node) = team_node {
            node.parent_id = team_node.parent_id.clone();
            node.pos = team_node.pos.clone();
            node.deleted = !is_node_live(id, team);
        } else {
            node.deleted = true;
        }
    }
    out.removed_choices = team.removed_choices.clone();
}

fn resolve_parent_cycles(
    base: &DocumentState,
    team: &DocumentState,
    draft: &DocumentState,
    out: &mut DocumentState,
    conflicts: &mut Vec<Conflict>,
    resolutions: &BTreeMap<String, String>,
) -> bool {
    let max_passes = out.nodes.len() + 1;
    let mut passes = 0;
    while let Some(cycle) = find_parent_cycles(out).into_iter().next() {
        passes += 1;
        if passes > max_passes {
            return false;
        }

        // Pick a node in the loop whose merged location came from the draft (out_loc != team_loc).
        // Since team's own tree has no loops, every loop has such a node, and restoring
        // its location to team's location strictly makes progress toward team's acyclic tree.
        let mut draft_moved: Vec<NodeId> = cycle
            .iter()
            .filter(|id| {
                let out_loc = out.nodes.get(id).map(location);
                let t_loc = team.nodes.get(id).map(location);
                out_loc != t_loc
            })
            .cloned()
            .collect();

        if draft_moved.is_empty() {
            draft_moved = cycle.to_vec();
        }

        let Some(d_id) = draft_moved.into_iter().next() else {
            break;
        };

        let key = format!("{}:$location", d_id.0);
        let b_loc = base.nodes.get(&d_id).map(location).unwrap_or(Value::Null);
        let t_loc = team.nodes.get(&d_id).map(location).unwrap_or(Value::Null);
        let d_loc = draft.nodes.get(&d_id).map(location).unwrap_or(Value::Null);

        match resolutions.get(&key).map(String::as_str) {
            Some("draft") => {
                if let Some(d_node) = draft.nodes.get(&d_id) {
                    if let Some(out_node) = out.nodes.get_mut(&d_id) {
                        out_node.parent_id = d_node.parent_id.clone();
                        out_node.pos = d_node.pos.clone();
                    }
                }
                for other_id in &cycle {
                    if other_id != &d_id {
                        if let Some(b_node) = base.nodes.get(other_id) {
                            if let Some(out_node) = out.nodes.get_mut(other_id) {
                                out_node.parent_id = b_node.parent_id.clone();
                                out_node.pos = b_node.pos.clone();
                            }
                        }
                    }
                }
            }
            Some("team") => {
                if let Some(t_node) = team.nodes.get(&d_id) {
                    if let Some(out_node) = out.nodes.get_mut(&d_id) {
                        out_node.parent_id = t_node.parent_id.clone();
                        out_node.pos = t_node.pos.clone();
                    }
                }
            }
            _ => {
                if !conflicts.iter().any(|c| c.key == key) {
                    conflicts.push(Conflict {
                        key,
                        node_id: d_id.clone(),
                        field: "$location".into(),
                        ancestor: b_loc,
                        team: t_loc,
                        draft: d_loc,
                    });
                }
                if let Some(t_node) = team.nodes.get(&d_id) {
                    if let Some(out_node) = out.nodes.get_mut(&d_id) {
                        out_node.parent_id = t_node.parent_id.clone();
                        out_node.pos = t_node.pos.clone();
                    }
                }
            }
        }
    }

    true
}

fn resolve_orphans(
    base: &DocumentState,
    team: &DocumentState,
    draft: &DocumentState,
    out: &mut DocumentState,
    conflicts: &mut Vec<Conflict>,
    resolutions: &BTreeMap<String, String>,
) {
    while let Some((child_id, parent_id)) = find_direct_orphan(out) {
        let key = format!("{}:$location", child_id.0);
        let choice = resolutions.get(&key).map(String::as_str);
        let team_deleted_parent = !is_node_live(&parent_id, team);
        let restore = match choice {
            Some("restore container") => true,
            Some("drop block") => false,
            Some("draft") => team_deleted_parent,
            _ => !team_deleted_parent,
        };
        let resolved = matches!(
            choice,
            Some("team" | "draft" | "restore container" | "drop block")
        );
        let repaired = if restore {
            restore_ancestor_chain(&parent_id, base, team, draft, out)
        } else {
            // Choosing a side that removed the container can still keep a block
            // that side moved elsewhere. The explicit drop choice deletes it.
            let side = if team_deleted_parent { team } else { draft };
            let moved = side.nodes.get(&child_id).filter(|node| {
                choice != Some("drop block")
                    && is_node_live(&child_id, side)
                    && node.parent_id.as_ref() != Some(&parent_id)
            });
            if let Some(node) = moved {
                let target = out.nodes.get_mut(&child_id).unwrap();
                target.parent_id = node.parent_id.clone();
                target.pos = node.pos.clone();
            } else {
                delete_subtree(&child_id, out);
            }
            true
        };
        if (!resolved || !repaired) && !conflicts.iter().any(|c| c.key == key) {
            conflicts.push(Conflict {
                key,
                node_id: child_id.clone(),
                field: "$location".into(),
                ancestor: base
                    .nodes
                    .get(&child_id)
                    .map(location)
                    .unwrap_or(Value::Null),
                team: team
                    .nodes
                    .get(&child_id)
                    .map(location)
                    .unwrap_or(Value::Null),
                draft: draft
                    .nodes
                    .get(&child_id)
                    .map(location)
                    .unwrap_or(Value::Null),
            });
        }
        if !repaired {
            // Missing ancestry cannot be restored. Keep the conflict visible and
            // provide a safe preview instead of silently exhausting a pass limit.
            delete_subtree(&child_id, out);
        }
    }
    out.removed_choices
        .retain(|id| out.nodes.get(id).is_some_and(|n| n.deleted));
}

fn is_node_live(id: &NodeId, state: &DocumentState) -> bool {
    state
        .nodes
        .get(id)
        .is_some_and(|n| !n.deleted && !state.removed_choices.contains(id))
}

fn find_direct_orphan(state: &DocumentState) -> Option<(NodeId, NodeId)> {
    for (id, node) in &state.nodes {
        if !is_node_live(id, state) {
            continue;
        }
        if let Some(parent_id) = &node.parent_id {
            if !is_node_live(parent_id, state) {
                return Some((id.clone(), parent_id.clone()));
            }
        }
    }
    None
}

fn delete_subtree(root: &NodeId, out: &mut DocumentState) {
    let mut children: BTreeMap<NodeId, Vec<NodeId>> = BTreeMap::new();
    for (id, node) in &out.nodes {
        if let Some(parent) = &node.parent_id {
            children.entry(parent.clone()).or_default().push(id.clone());
        }
    }
    let mut pending = vec![root.clone()];
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id.clone()) {
            continue;
        }
        if let Some(node) = out.nodes.get_mut(&id) {
            node.deleted = true;
        }
        pending.extend(children.remove(&id).unwrap_or_default());
    }
}

fn restore_ancestor_chain(
    start_id: &NodeId,
    base: &DocumentState,
    team: &DocumentState,
    draft: &DocumentState,
    out: &mut DocumentState,
) -> bool {
    // Collect first so an unavailable ancestor cannot partially restore a chain.
    let mut cursor = Some(start_id.clone());
    let mut visited = BTreeSet::new();
    let mut restore = Vec::new();
    while let Some(id) = cursor {
        if !visited.insert(id.clone()) {
            return false;
        }
        if is_node_live(&id, out) {
            break;
        }
        let Some(node) = out
            .nodes
            .get(&id)
            .or_else(|| base.nodes.get(&id))
            .or_else(|| draft.nodes.get(&id))
            .or_else(|| team.nodes.get(&id))
        else {
            return false;
        };
        cursor = node.parent_id.clone();
        restore.push(node.clone());
    }
    for mut node in restore {
        node.deleted = false;
        out.removed_choices.remove(&node.id);
        out.nodes.insert(node.id.clone(), node);
    }
    true
}
// Each parent chain is traversed once. Iterative traversal avoids stack growth
// for deeply nested imports; malformed cycles retain the old capped sort depth.
fn depths(state: &DocumentState) -> BTreeMap<NodeId, usize> {
    let mut depths = BTreeMap::new();
    let cap = state.nodes.len() + 1;
    for id in state.nodes.keys() {
        if depths.contains_key(id) {
            continue;
        }
        let mut path = Vec::new();
        let mut seen = BTreeSet::new();
        let mut cursor = id;
        let mut depth = loop {
            if let Some(depth) = depths.get(cursor) {
                break *depth;
            }
            let Some(node) = state.nodes.get(cursor) else {
                break 0;
            };
            let Some(parent) = &node.parent_id else {
                depths.insert(cursor.clone(), 0);
                break 0;
            };
            if !seen.insert(cursor) {
                break cap;
            }
            path.push(cursor.clone());
            cursor = parent;
        };
        for id in path.into_iter().rev() {
            depth = (depth + 1).min(cap);
            depths.insert(id, depth);
        }
    }
    depths
}
pub fn diff(from: &DocumentState, to: &DocumentState) -> Vec<EventPayload> {
    let from = canonical(from);
    let to = canonical(to);
    let mut result = Vec::new();
    let to_depths = depths(&to);
    let mut nodes: Vec<_> = to.nodes.values().collect();
    nodes.sort_by_cached_key(|n| (to_depths[&n.id], &n.id));
    for n in nodes.into_iter().filter(|n| !n.deleted) {
        let prior = from.nodes.get(&n.id);
        if prior.is_none() {
            if let Ok(node_type) = n.node_type.parse() {
                result.push(EventPayload::NodeCreated {
                    node_id: n.id.clone(),
                    node_type,
                    parent_id: n.parent_id.clone(),
                    pos: n.pos.clone(),
                    fields: n.current_fields.clone(),
                    var_name: n.var_name.clone(),
                });
            }
            continue;
        }
        let p = prior.unwrap();
        if p.deleted {
            result.push(EventPayload::NodeRestored {
                node_id: n.id.clone(),
            });
        }
        if p.parent_id != n.parent_id || p.pos != n.pos {
            result.push(EventPayload::NodeMoved {
                node_id: n.id.clone(),
                new_parent_id: n.parent_id.clone(),
                new_pos: n.pos.clone(),
            });
        }
        let keys: BTreeSet<_> = p
            .current_fields
            .as_object()
            .into_iter()
            .flat_map(|o| o.keys())
            .chain(
                n.current_fields
                    .as_object()
                    .into_iter()
                    .flat_map(|o| o.keys()),
            )
            .collect();
        let mut derived_label = None;
        for field in keys {
            let before = if field == "label" {
                derived_label.as_ref().unwrap_or(&p.current_fields[field])
            } else {
                &p.current_fields[field]
            };
            if *before != n.current_fields[field] {
                let op = EventPayload::FieldEdited {
                    node_id: n.id.clone(),
                    field: field.clone(),
                    value: n.current_fields[field].clone(),
                };
                let compact = crate::richtext::compact_event(&from, &op);
                if matches!(compact, EventPayload::RichTextPatched { .. }) {
                    derived_label = Some(json!(crate::richtext::plain_text(
                        &n.current_fields["content"]
                    )));
                }
                result.push(compact);
            }
        }
        if p.var_name != n.var_name {
            result.push(EventPayload::FieldEdited {
                node_id: n.id.clone(),
                field: "var_name".into(),
                value: json!(n.var_name.as_deref().unwrap_or("")),
            });
        }
    }
    let mut removed: Vec<_> = from
        .nodes
        .values()
        .filter(|n| !n.deleted && to.nodes.get(&n.id).is_none_or(|n| n.deleted))
        .collect();
    if !removed.is_empty() {
        let from_depths = depths(&from);
        removed.sort_by_cached_key(|n| std::cmp::Reverse(from_depths[&n.id]));
    }
    for n in removed {
        result.push(EventPayload::NodeDeleted {
            node_id: n.id.clone(),
        });
    }
    // A snapshot can enable protection together with content changes. Apply that
    // flag last; explicit unprotection of an existing live sheet must happen first.
    // Never implicitly unprotect an already-protected worksheet.
    let mut unlocks = Vec::new();
    let mut content = Vec::new();
    let mut locks = Vec::new();
    for mut op in result {
        match &mut op {
            EventPayload::NodeCreated {
                node_id, fields, ..
            } if fields["kind"] == "sheet" && fields["sheet_protected"] == true => {
                fields["sheet_protected"] = json!(false);
                locks.push(EventPayload::FieldEdited {
                    node_id: node_id.clone(),
                    field: "sheet_protected".into(),
                    value: json!(true),
                });
            }
            EventPayload::FieldEdited {
                node_id,
                field,
                value,
            } if field == "sheet_protected" => {
                if *value == true {
                    locks.push(op);
                    continue;
                }
                if (value.is_null() || *value == false)
                    && from.nodes.get(node_id).is_some_and(|n| !n.deleted)
                {
                    unlocks.push(op);
                    continue;
                }
            }
            _ => {}
        }
        content.push(op);
    }
    unlocks.extend(content);
    unlocks.extend(locks);
    unlocks
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cached_depths_match_legacy_order_for_cycles_missing_parents_and_deep_trees() {
        fn legacy(state: &DocumentState, node: &MaterializedNode) -> usize {
            let mut count = 0;
            let mut parent = node.parent_id.as_ref();
            while let Some(id) = parent {
                count += 1;
                if count > state.nodes.len() {
                    break;
                }
                parent = state.nodes.get(id).and_then(|node| node.parent_id.as_ref());
            }
            count
        }
        let template = state().nodes.values().next().unwrap().clone();
        let mut random = 17u64;
        for _ in 0..100 {
            let mut graph = DocumentState::default();
            for i in 0..64 {
                random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                let mut node = template.clone();
                node.id = NodeId(i.to_string());
                let parent = (random >> 32) % 70;
                node.parent_id = (parent != 69).then(|| NodeId(parent.to_string()));
                graph.nodes.insert(node.id.clone(), node);
            }
            let actual = depths(&graph);
            for node in graph.nodes.values() {
                assert_eq!(actual[&node.id], legacy(&graph, node));
            }
        }
        let mut deep = DocumentState::default();
        for i in 0..20_000 {
            let mut node = template.clone();
            node.id = NodeId(format!("{i:026}"));
            node.parent_id = (i > 0).then(|| NodeId(format!("{:026}", i - 1)));
            deep.nodes.insert(node.id.clone(), node);
        }
        let actual = depths(&deep);
        assert_eq!(actual[&NodeId(format!("{:026}", 19_999))], 19_999);
    }
    fn state() -> DocumentState {
        let mut s = DocumentState::default();
        s.nodes.insert(
            NodeId("root".into()),
            MaterializedNode {
                id: NodeId("root".into()),
                parent_id: None,
                node_type: "form".into(),
                pos: "a0".into(),
                current_fields: json!({"a":1,"b":1}),
                var_name: None,
                deleted: false,
            },
        );
        s
    }
    #[test]
    fn protected_snapshot_diffs_apply_content_before_lock_and_explicit_unlock_before_edits() {
        use crate::governance::{authorize, Role};
        let base = state();
        let mut target = base.clone();
        target.nodes.insert(
            NodeId("sheet".into()),
            MaterializedNode {
                id: NodeId("sheet".into()),
                parent_id: Some(NodeId("root".into())),
                node_type: "section".into(),
                pos: "0".into(),
                current_fields: json!({"kind":"sheet","sheet_protected":true,"label":"Old"}),
                var_name: None,
                deleted: false,
            },
        );
        target.nodes.insert(
            NodeId("row".into()),
            MaterializedNode {
                id: NodeId("row".into()),
                parent_id: Some(NodeId("sheet".into())),
                node_type: "item".into(),
                pos: "0".into(),
                current_fields: json!({"cell_0":"saved"}),
                var_name: None,
                deleted: false,
            },
        );
        let apply = |from: &DocumentState, to: &DocumentState| {
            let mut state = from.clone();
            for op in diff(from, to) {
                authorize(Role::Author, &op, &state).unwrap();
                crate::materializer::apply_payload(&mut state, &op).unwrap();
            }
            state
        };
        let created = apply(&base, &target);
        assert_eq!(
            created.nodes[&NodeId("sheet".into())].current_fields["sheet_protected"],
            true
        );
        let mut unprotected = target.clone();
        unprotected
            .nodes
            .get_mut(&NodeId("sheet".into()))
            .unwrap()
            .current_fields = json!({"kind":"sheet","label":"New"});
        unprotected
            .nodes
            .get_mut(&NodeId("row".into()))
            .unwrap()
            .current_fields["cell_0"] = json!("edited");
        let unlocked = apply(&target, &unprotected);
        assert!(
            unlocked.nodes[&NodeId("sheet".into())].current_fields["sheet_protected"].is_null()
        );
        let restored = apply(&unlocked, &target);
        assert_eq!(
            restored.nodes[&NodeId("row".into())].current_fields["cell_0"],
            "saved"
        );
        assert_eq!(
            restored.nodes[&NodeId("sheet".into())].current_fields["sheet_protected"],
            true
        );
    }

    #[test]
    fn separate_cells_merge_and_overlaps_require_a_choice() {
        let b = state();
        let mut t = b.clone();
        let mut d = b.clone();
        t.nodes
            .get_mut(&NodeId("root".into()))
            .unwrap()
            .current_fields["a"] = json!(2);
        d.nodes
            .get_mut(&NodeId("root".into()))
            .unwrap()
            .current_fields["b"] = json!(3);
        let p = merge(&b, &t, &d, &BTreeMap::new());
        assert!(p.conflicts.is_empty());
        assert_eq!(p.ops.len(), 1);
        d.nodes
            .get_mut(&NodeId("root".into()))
            .unwrap()
            .current_fields["a"] = json!(4);
        let p = merge(&b, &t, &d, &BTreeMap::new());
        assert_eq!(p.conflicts.len(), 1);
        let p = merge(
            &b,
            &t,
            &d,
            &BTreeMap::from([("root:a".into(), "draft".into())]),
        );
        assert!(p.conflicts.is_empty());
        assert_eq!(p.state.nodes[&NodeId("root".into())].current_fields["a"], 4);
    }
    #[test]
    fn deletion_and_editing_conflict() {
        let b = state();
        let mut t = b.clone();
        let mut d = b.clone();
        t.nodes.get_mut(&NodeId("root".into())).unwrap().deleted = true;
        d.nodes
            .get_mut(&NodeId("root".into()))
            .unwrap()
            .current_fields["a"] = json!(2);
        assert_eq!(merge(&b, &t, &d, &BTreeMap::new()).conflicts.len(), 1);
    }
    #[test]
    fn unrelated_content_needs_a_choice_for_every_existing_block() {
        let b = state();
        let mut para = b.nodes[&NodeId("root".into())].clone();
        para.id = NodeId("p1".into());
        para.parent_id = Some(NodeId("root".into()));
        para.current_fields = json!({"label":"Team paragraph"});
        let mut base = b.clone();
        base.nodes.insert(para.id.clone(), para.clone());
        let team = base.clone();
        let mut draft = base.clone();
        draft
            .nodes
            .get_mut(&NodeId("p1".into()))
            .unwrap()
            .current_fields = json!({"label":"Their unrelated paragraph"});
        let mut added = para.clone();
        added.id = NodeId("p2".into());
        added.current_fields = json!({"label":"Their new paragraph"});
        draft.nodes.insert(added.id.clone(), added);
        // The ordinary merge would take the edit silently; the strict merge asks.
        assert!(merge(&base, &team, &draft, &BTreeMap::new())
            .conflicts
            .is_empty());
        let plan = merge_strict(&base, &team, &draft, &BTreeMap::new());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].key, "p1:$block");
        // Until chosen, the team's paragraph stays and the new one is still offered.
        assert_eq!(plan.ops.len(), 1);
        let keep = merge_strict(
            &base,
            &team,
            &draft,
            &BTreeMap::from([("p1:$block".into(), "team".into())]),
        );
        assert!(keep.conflicts.is_empty());
        assert_eq!(keep.ops.len(), 1);
        let take = merge_strict(
            &base,
            &team,
            &draft,
            &BTreeMap::from([("p1:$block".into(), "draft".into())]),
        );
        assert!(take.conflicts.is_empty());
        assert_eq!(
            take.state.nodes[&NodeId("p1".into())].current_fields["label"],
            "Their unrelated paragraph"
        );
        assert_eq!(take.ops.len(), 2);
    }
    #[test]
    fn restoration_keeps_the_id() {
        let b = state();
        let mut deleted = b.clone();
        deleted
            .nodes
            .get_mut(&NodeId("root".into()))
            .unwrap()
            .deleted = true;
        assert!(
            matches!(&diff(&deleted,&b)[0],EventPayload::NodeRestored{node_id} if node_id.0=="root")
        );
    }

    #[test]
    fn canonical_borrows_when_empty_and_owns_when_choices_removed() {
        let mut s = state();
        assert!(matches!(canonical(&s), Cow::Borrowed(_)));
        s.removed_choices.insert(NodeId("root".into()));
        let c = canonical(&s);
        assert!(matches!(c, Cow::Owned(_)));
        assert!(c.nodes[&NodeId("root".into())].deleted);
    }

    fn add_section(state: &mut DocumentState, id: &str, parent: &str) {
        let mut node = state.nodes[&NodeId("root".into())].clone();
        node.id = NodeId(id.into());
        node.parent_id = Some(NodeId(parent.into()));
        node.node_type = "section".into();
        state.nodes.insert(node.id.clone(), node);
    }

    fn assert_valid_merge_replay(team: &DocumentState, plan: &MergePlan) {
        let mut applied = team.clone();
        for op in &plan.ops {
            crate::ops::validate_op(&applied, op).unwrap_or_else(|err| {
                panic!("invalid merge operation {op:?}: {err}");
            });
            crate::materializer::apply_payload(&mut applied, op).unwrap();
        }
        let live = |state: &DocumentState| {
            state
                .nodes
                .iter()
                .filter(|(id, _)| is_node_live(id, state))
                .map(|(id, node)| (id.clone(), node.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(live(&applied), live(&plan.state));
        assert_eq!(applied.removed_choices, plan.state.removed_choices);
        assert!(find_parent_cycles(&plan.state).is_empty());
        assert!(find_direct_orphan(&plan.state).is_none());
    }

    #[test]
    fn deleted_container_and_new_subtree_require_an_explicit_location_choice() {
        let mut base = state();
        add_section(&mut base, "container", "root");
        let mut deleted = base.clone();
        deleted
            .nodes
            .get_mut(&NodeId("container".into()))
            .unwrap()
            .deleted = true;
        let mut added = base.clone();
        add_section(&mut added, "child", "container");
        add_section(&mut added, "grandchild", "child");
        for (team, draft, keep, drop) in [
            (&deleted, &added, "draft", "team"),
            (&added, &deleted, "team", "draft"),
        ] {
            let preview = merge(&base, team, draft, &BTreeMap::new());
            assert_eq!(preview.conflicts.len(), 1);
            assert_eq!(preview.conflicts[0].key, "child:$location");
            assert_valid_merge_replay(team, &preview);
            for (choice, survives) in [
                (keep, true),
                (drop, false),
                ("restore container", true),
                ("drop block", false),
            ] {
                let plan = merge(
                    &base,
                    team,
                    draft,
                    &BTreeMap::from([("child:$location".into(), choice.into())]),
                );
                assert!(plan.conflicts.is_empty(), "{choice}: {:?}", plan.conflicts);
                assert_eq!(is_node_live(&NodeId("child".into()), &plan.state), survives);
                assert_eq!(
                    is_node_live(&NodeId("grandchild".into()), &plan.state),
                    survives
                );
                assert_valid_merge_replay(team, &plan);
            }
        }
    }

    #[test]
    fn orphan_resolution_restores_all_deleted_ancestors_before_creating_child() {
        let mut base = state();
        add_section(&mut base, "outer", "root");
        add_section(&mut base, "container", "outer");
        let mut team = base.clone();
        for id in ["outer", "container"] {
            team.nodes.get_mut(&NodeId(id.into())).unwrap().deleted = true;
        }
        let mut draft = base.clone();
        add_section(&mut draft, "child", "container");
        let plan = merge(
            &base,
            &team,
            &draft,
            &BTreeMap::from([("child:$location".into(), "draft".into())]),
        );
        assert!(plan.conflicts.is_empty());
        assert_eq!(plan.ops.len(), 3);
        assert_valid_merge_replay(&team, &plan);
    }

    #[test]
    fn moving_into_a_deleted_container_can_keep_the_original_location() {
        let mut base = state();
        add_section(&mut base, "container", "root");
        add_section(&mut base, "child", "root");
        let mut deleted = base.clone();
        deleted
            .nodes
            .get_mut(&NodeId("container".into()))
            .unwrap()
            .deleted = true;
        let mut moved = base.clone();
        moved
            .nodes
            .get_mut(&NodeId("child".into()))
            .unwrap()
            .parent_id = Some(NodeId("container".into()));
        for (team, draft, keep) in [(&deleted, &moved, "team"), (&moved, &deleted, "draft")] {
            let plan = merge(
                &base,
                team,
                draft,
                &BTreeMap::from([("child:$location".into(), keep.into())]),
            );
            assert!(plan.conflicts.is_empty());
            assert_eq!(
                plan.state.nodes[&NodeId("child".into())].parent_id,
                Some(NodeId("root".into()))
            );
            assert_valid_merge_replay(team, &plan);
            let dropped = merge(
                &base,
                team,
                draft,
                &BTreeMap::from([("child:$location".into(), "drop block".into())]),
            );
            assert!(!is_node_live(&NodeId("child".into()), &dropped.state));
            assert_valid_merge_replay(team, &dropped);
        }
    }

    #[test]
    fn unrelated_parent_resolution_does_not_hide_an_orphan_conflict() {
        let mut base = state();
        add_section(&mut base, "container", "root");
        let mut team = base.clone();
        team.nodes
            .get_mut(&NodeId("container".into()))
            .unwrap()
            .deleted = true;
        let mut draft = base.clone();
        add_section(&mut draft, "child", "container");
        let plan = merge(
            &base,
            &team,
            &draft,
            &BTreeMap::from([("container:$location".into(), "team".into())]),
        );
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].key, "child:$location");
        assert_valid_merge_replay(&team, &plan);
    }

    #[test]
    fn orphan_relocation_rechecks_cycles_from_other_merged_moves() {
        let mut base = state();
        add_section(&mut base, "a", "root");
        add_section(&mut base, "child", "a");
        add_section(&mut base, "container", "root");
        let mut team = base.clone();
        team.nodes
            .get_mut(&NodeId("container".into()))
            .unwrap()
            .deleted = true;
        let mut draft = base.clone();
        draft
            .nodes
            .get_mut(&NodeId("child".into()))
            .unwrap()
            .parent_id = Some(NodeId("container".into()));
        draft.nodes.get_mut(&NodeId("a".into())).unwrap().parent_id = Some(NodeId("child".into()));
        let choices = BTreeMap::from([("child:$location".into(), "team".into())]);
        let plan = merge(&base, &team, &draft, &choices);
        assert!(!plan.conflicts.is_empty());
        assert_valid_merge_replay(&team, &plan);
        for (choice, resolves) in [("team", true), ("draft", false)] {
            let mut choices = choices.clone();
            choices.insert("a:$location".into(), choice.into());
            let plan = merge(&base, &team, &draft, &choices);
            assert_eq!(plan.conflicts.is_empty(), resolves);
            assert_valid_merge_replay(&team, &plan);
        }
    }

    #[test]
    fn restoring_a_removed_choice_also_restores_its_deleted_parent() {
        let mut base = state();
        add_section(&mut base, "item", "root");
        base.nodes
            .get_mut(&NodeId("item".into()))
            .unwrap()
            .node_type = "item".into();
        add_section(&mut base, "choice", "item");
        base.nodes
            .get_mut(&NodeId("choice".into()))
            .unwrap()
            .node_type = "choice".into();
        let mut team = base.clone();
        team.removed_choices.insert(NodeId("choice".into()));
        team.nodes.get_mut(&NodeId("item".into())).unwrap().deleted = true;
        let mut draft = base.clone();
        draft
            .nodes
            .get_mut(&NodeId("choice".into()))
            .unwrap()
            .current_fields["a"] = json!(2);
        let plan = merge(
            &base,
            &team,
            &draft,
            &BTreeMap::from([
                ("choice:$node".into(), "draft".into()),
                ("choice:$location".into(), "draft".into()),
            ]),
        );
        assert!(plan.conflicts.is_empty());
        assert!(plan.state.removed_choices.is_empty());
        assert_valid_merge_replay(&team, &plan);
    }

    #[test]
    fn missing_ancestry_cannot_be_silently_resolved_by_restoration() {
        let base = state();
        let mut draft = base.clone();
        add_section(&mut draft, "child", "missing");
        let plan = merge(
            &base,
            &base,
            &draft,
            &BTreeMap::from([("child:$location".into(), "restore container".into())]),
        );
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].key, "child:$location");
        assert_valid_merge_replay(&base, &plan);
    }

    #[test]
    fn strict_merge_rechecks_orphans_after_keeping_a_team_block() {
        let mut base = state();
        add_section(&mut base, "container", "root");
        add_section(&mut base, "child", "container");
        let team = base.clone();
        let mut draft = base.clone();
        draft
            .nodes
            .get_mut(&NodeId("container".into()))
            .unwrap()
            .deleted = true;
        draft
            .nodes
            .get_mut(&NodeId("child".into()))
            .unwrap()
            .parent_id = Some(NodeId("root".into()));
        let choices = BTreeMap::from([
            ("container:$block".into(), "draft".into()),
            ("child:$block".into(), "team".into()),
        ]);
        let plan = merge_strict(&base, &team, &draft, &choices);
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].key, "child:$location");
        assert_valid_merge_replay(&team, &plan);
    }

    #[test]
    fn cross_moves_conflict_instead_of_cycle() {
        use crate::ops::validate_op;

        let mut b = state();
        let mut a_node = b.nodes[&NodeId("root".into())].clone();
        a_node.id = NodeId("a".into());
        a_node.node_type = "section".into();
        a_node.parent_id = Some(NodeId("root".into()));
        let mut b_node = a_node.clone();
        b_node.id = NodeId("b".into());
        b.nodes.insert(a_node.id.clone(), a_node);
        b.nodes.insert(b_node.id.clone(), b_node);

        let mut t = b.clone();
        t.nodes.get_mut(&NodeId("a".into())).unwrap().parent_id = Some(NodeId("b".into()));

        let mut d = b.clone();
        d.nodes.get_mut(&NodeId("b".into())).unwrap().parent_id = Some(NodeId("a".into()));

        // Unresolved preview surfaces the location conflict on b and keeps state acyclic
        let plan = merge(&b, &t, &d, &BTreeMap::new());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].key, "b:$location");
        assert!(find_parent_cycles(&plan.state).is_empty());

        // Choosing team keeps team's location for b and remains acyclic
        let keep_team = merge(
            &b,
            &t,
            &d,
            &BTreeMap::from([("b:$location".into(), "team".into())]),
        );
        assert!(keep_team.conflicts.is_empty());
        assert!(find_parent_cycles(&keep_team.state).is_empty());

        // Choosing draft moves b under a and safely reverts opposing team move on a
        let take_draft = merge(
            &b,
            &t,
            &d,
            &BTreeMap::from([("b:$location".into(), "draft".into())]),
        );
        assert!(take_draft.conflicts.is_empty());
        assert!(find_parent_cycles(&take_draft.state).is_empty());
        assert_eq!(
            take_draft.state.nodes[&NodeId("b".into())].parent_id,
            Some(NodeId("a".into()))
        );

        // Applying take_draft ops to team validates and produces a valid state
        let mut applied = t.clone();
        for op in &take_draft.ops {
            validate_op(&applied, op).unwrap();
            crate::materializer::apply_payload(&mut applied, op).unwrap();
        }
        assert!(find_parent_cycles(&applied).is_empty());
    }

    #[test]
    fn three_node_cycle_conflict_blames_divergent_move() {
        use crate::ops::validate_op;

        let mut b = state();
        let mut a_node = b.nodes[&NodeId("root".into())].clone();
        a_node.id = NodeId("a".into());
        a_node.node_type = "section".into();
        a_node.parent_id = Some(NodeId("root".into()));
        let mut b_node = a_node.clone();
        b_node.id = NodeId("b".into());
        let mut c_node = a_node.clone();
        c_node.id = NodeId("c".into());
        b.nodes.insert(a_node.id.clone(), a_node);
        b.nodes.insert(b_node.id.clone(), b_node);
        b.nodes.insert(c_node.id.clone(), c_node);

        // Team moves a under b and b under c
        let mut t = b.clone();
        t.nodes.get_mut(&NodeId("a".into())).unwrap().parent_id = Some(NodeId("b".into()));
        t.nodes.get_mut(&NodeId("b".into())).unwrap().parent_id = Some(NodeId("c".into()));

        // Draft also moves a under b, and moves c under a
        let mut d = b.clone();
        d.nodes.get_mut(&NodeId("a".into())).unwrap().parent_id = Some(NodeId("b".into()));
        d.nodes.get_mut(&NodeId("c".into())).unwrap().parent_id = Some(NodeId("a".into()));

        // Both moved a under b identically; only c diverged from team's tree.
        // The conflict must blame c:$location, not a.
        let plan = merge(&b, &t, &d, &BTreeMap::new());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].key, "c:$location");
        assert!(find_parent_cycles(&plan.state).is_empty());

        // Unresolved preview maintains a valid state that passes validate_op
        let mut preview_applied = t.clone();
        for op in &plan.ops {
            validate_op(&preview_applied, op).unwrap();
            crate::materializer::apply_payload(&mut preview_applied, op).unwrap();
        }

        // Choosing team keeps c at root, producing a valid acyclic tree
        let keep_team = merge(
            &b,
            &t,
            &d,
            &BTreeMap::from([("c:$location".into(), "team".into())]),
        );
        assert!(keep_team.conflicts.is_empty());
        assert!(find_parent_cycles(&keep_team.state).is_empty());
        let mut team_applied = t.clone();
        for op in &keep_team.ops {
            validate_op(&team_applied, op).unwrap();
            crate::materializer::apply_payload(&mut team_applied, op).unwrap();
        }

        // Choosing draft moves c under a and reverts opposing team move on b to base (root)
        let take_draft = merge(
            &b,
            &t,
            &d,
            &BTreeMap::from([("c:$location".into(), "draft".into())]),
        );
        assert!(take_draft.conflicts.is_empty());
        assert!(find_parent_cycles(&take_draft.state).is_empty());
        assert_eq!(
            take_draft.state.nodes[&NodeId("c".into())].parent_id,
            Some(NodeId("a".into()))
        );
        assert_eq!(
            take_draft.state.nodes[&NodeId("b".into())].parent_id,
            Some(NodeId("root".into()))
        );
        let mut draft_applied = t.clone();
        for op in &take_draft.ops {
            validate_op(&draft_applied, op).unwrap();
            crate::materializer::apply_payload(&mut draft_applied, op).unwrap();
        }
        assert!(find_parent_cycles(&draft_applied).is_empty());
    }
}
