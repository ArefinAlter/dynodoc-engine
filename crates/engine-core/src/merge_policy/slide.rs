//! `dynodoc.slide.shape.v1` (design 4.7): fields of slide shapes and slides.
//!
//! | Field | Rule |
//! |---|---|
//! | `x`, `y`, `w`, `h` changed differently on both sides | `geometry_conflict: manual` (the default) is a conflict; `prefer-role` prefers the higher role and preserves the other value |
//! | `text`, `notes`, `label` | the text strategy ([`super::text`]) |
//! | `style` | property by property |
//! | `src` (image) | always a conflict |
//! | anything else | a conflict when both sides changed it differently |
//!
//! Different fields of one shape and different shapes merge as they always have.
//! Not decided here: the coupling of a slide's `layout` with the geometry of its
//! placeholder shapes, which spans nodes (left to a human through the per-field
//! conflicts it causes, and listed as not built).

use super::{
    strategy::{Context, Inputs, Laws, ParamSpec, ParamType, Reason, Resolved, Strategy},
    text,
};

pub const ID: &str = "dynodoc.slide.shape.v1";

pub struct SlideShape;

const PARAMS: &[ParamSpec] = &[ParamSpec {
    name: "geometry_conflict",
    ty: ParamType::OneOf(&["manual", "prefer-role"]),
}];

impl Strategy for SlideShape {
    fn id(&self) -> &'static str {
        ID
    }
    fn params(&self) -> &'static [ParamSpec] {
        PARAMS
    }
    fn max_input_bytes(&self) -> Option<usize> {
        // Images are at most 1 MiB (`MAX_IMAGE_BYTES`) and travel as data URLs.
        Some(3 << 20)
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
            .any(|v| serde_json::to_vec(v).map_or(usize::MAX, |b| b.len()) > 3 << 20)
        {
            return Resolved::conflict(Reason::TOO_LARGE, "bound");
        }
        match ctx.field {
            "x" | "y" | "w" | "h" => Resolved::prefer_role_or(
                ctx,
                "geometry_conflict",
                i,
                Reason::BOTH_CHANGED,
                "geometry",
            ),
            "text" | "notes" | "label" => text::merge_value(i, ctx),
            "style" => {
                let base = (!i.base.is_null()).then_some(i.base);
                match crate::richtext::merge_property(base, Some(i.team), Some(i.draft)) {
                    Ok(Some(v)) => Resolved::merged(v, "style-keys"),
                    _ => Resolved::conflict(Reason::OVERLAP, "style-keys"),
                }
            }
            "src" => Resolved::conflict(Reason::BOTH_CHANGED, "image"),
            _ => Resolved::conflict(Reason::BOTH_CHANGED, "whole-value"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge_policy::{policy::Role, strategy::Side, Family, Outcome};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    fn run(field: &str, b: Value, t: Value, d: Value, prefer: bool) -> Resolved {
        let mut params = BTreeMap::new();
        if prefer {
            params.insert("geometry_conflict".to_string(), json!("prefer-role"));
        }
        let rank = [Role::Owner, Role::Manager, Role::Editor];
        let ctx = Context {
            node: None,
            node_type: "item",
            field,
            aspect: None,
            family: Family::Presentation,
            params: &params,
            roles: Some((Role::Editor, Role::Manager)),
            rank: &rank,
            marks: None,
        };
        SlideShape.resolve(
            &Inputs {
                base: &b,
                team: &t,
                draft: &d,
            },
            &ctx,
        )
    }

    #[test]
    fn geometry_is_manual_unless_roles_decide() {
        assert_eq!(
            run("x", json!(10), json!(12), json!(14), false).outcome,
            Outcome::Conflict(Reason::BOTH_CHANGED)
        );
        let r = run("x", json!(10), json!(12), json!(14), true);
        assert_eq!(r.outcome, Outcome::Prefer(Side::Draft));
        assert_eq!(r.used.lost, vec![json!(12)]);
    }

    #[test]
    fn shape_text_and_style_merge_and_images_conflict() {
        assert_eq!(
            run(
                "text",
                json!("Results"),
                json!("Results 2026"),
                json!("Key Results"),
                false
            )
            .outcome,
            Outcome::Merged(json!("Key Results 2026"))
        );
        assert_eq!(
            run(
                "style",
                json!({"fill":"red","font":"A"}),
                json!({"fill":"blue","font":"A"}),
                json!({"fill":"red","font":"B"}),
                false
            )
            .outcome,
            Outcome::Merged(json!({"fill":"blue","font":"B"}))
        );
        assert_eq!(
            run("src", json!("a"), json!("b"), json!("c"), false).outcome,
            Outcome::Conflict(Reason::BOTH_CHANGED)
        );
    }
}
