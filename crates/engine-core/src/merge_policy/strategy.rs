//! The strategy interface of section 3 and 4.1 of the node-conflict design: a pure
//! function from `(base, team, draft)` to a merged value, a preferred side or a
//! conflict, plus the evidence it used. No clock, randomness, IO or global state.

use super::{policy::Role, Aspect, Family, Gate};
use engine_shared::NodeId;
use serde_json::Value;
use std::collections::BTreeMap;

/// The side of a three-way merge a value came from. `Team` is the version already
/// in place, `Draft` the one being merged into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Team,
    Draft,
}

impl Side {
    pub fn other(self) -> Self {
        match self {
            Self::Team => Self::Draft,
            Self::Draft => Self::Team,
        }
    }
}

/// The three values of one field (or collection) being merged.
#[derive(Clone, Copy, Debug)]
pub struct Inputs<'a> {
    pub base: &'a Value,
    pub team: &'a Value,
    pub draft: &'a Value,
}

impl<'a> Inputs<'a> {
    /// The same inputs with the two sides exchanged (law L1).
    pub fn swapped(&self) -> Inputs<'a> {
        Inputs {
            base: self.base,
            team: self.draft,
            draft: self.team,
        }
    }
    pub fn side(&self, side: Side) -> &'a Value {
        match side {
            Side::Team => self.team,
            Side::Draft => self.draft,
        }
    }
}

/// Where a decision is taken. The strategy must not depend on anything else.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// The node, or `None` for a document-level collection.
    pub node: Option<&'a NodeId>,
    pub node_type: &'a str,
    /// The field (`"$node"` and `"$location"` for whole-node decisions), or the
    /// collection name (`"$comments"`, `"$suggestions"`).
    pub field: &'a str,
    /// Set for a document-level collection, `None` for a node field.
    pub aspect: Option<Aspect>,
    pub family: Family,
    /// The rule's parameters, already checked against [`Strategy::params`].
    pub params: &'a BTreeMap<String, Value>,
    /// The roles of the authors of the team and draft sides, when the caller knows
    /// them (the shared service does; a portable repository does not). Only
    /// `prefer-role` parameters read them.
    pub roles: Option<(Role, Role)>,
    /// The policy's `defaults.roles_rank`, highest authority first.
    pub rank: &'a [Role],
    /// The rule that decides formatting marks inside this field (`match.aspect:
    /// marks`), when the policy has one. Text strategies consult it per atom.
    pub marks: Option<MarksRule<'a>>,
}

/// A marks rule as a text strategy sees it.
#[derive(Clone, Copy, Debug)]
pub struct MarksRule<'a> {
    pub params: &'a BTreeMap<String, Value>,
    pub gate: Gate,
}

impl Context<'_> {
    /// The text value of a `OneOf` parameter, or `default` when the rule does not
    /// set it. Parameters were validated at load, so any other type cannot occur.
    pub fn param<'p>(&'p self, name: &str, default: &'p str) -> &'p str {
        self.params
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or(default)
    }
    /// The side whose author ranks strictly higher in `rank`, when both roles are
    /// known. Content, never side order, decides: swapping the sides swaps the
    /// roles, so the preferred value is the same (law L1).
    pub fn higher_role(&self) -> Option<Side> {
        let (team, draft) = self.roles?;
        let at = |role| self.rank.iter().position(|r| *r == role);
        match (at(team), at(draft)) {
            (Some(t), Some(d)) if t < d => Some(Side::Team),
            (Some(t), Some(d)) if d < t => Some(Side::Draft),
            _ => None,
        }
    }
}

/// A short stable code that says why a strategy declined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct Reason(pub &'static str);

impl Reason {
    /// Both sides changed the value and nothing in the strategy can combine them.
    pub const BOTH_CHANGED: Self = Self("both-changed");
    /// The edits overlap in the text or the properties they touch.
    pub const OVERLAP: Self = Self("overlapping-edit");
    /// The input exceeds the strategy's stated bound (law L8).
    pub const TOO_LARGE: Self = Self("too-large");
    /// Two sides changed the same element differently.
    pub const ELEMENT_DIFFERS: Self = Self("element-differs");
    /// The input is not in the shape the strategy understands.
    pub const UNSUPPORTED_SHAPE: Self = Self("unsupported-shape");
    /// More edit hunks on one side than the strategy's bound.
    pub const TOO_MANY_HUNKS: Self = Self("too-many-hunks");
    /// A list or table changed shape and its children carry no identifiers.
    pub const SHAPE_CHANGED: Self = Self("shape-changed");
    /// One side made a value a formula (or the reverse) and the other edited it.
    pub const KIND_CHANGED: Self = Self("kind-changed");
    /// A structural shift explains a side in more than one way.
    pub const AMBIGUOUS_SHIFT: Self = Self("ambiguous-shift");
    /// Two fields that must change together were changed on different sides.
    pub const COUPLED: Self = Self("coupled-fields");
}

/// What a strategy decided.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// One value that combines both sides.
    Merged(Value),
    /// One side's value is kept and the other is the loser; [`Used::lost`] must
    /// carry the loser (law L7).
    Prefer(Side),
    Conflict(Reason),
}

/// What the strategy used, kept as evidence.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Used {
    /// A short code for the branch of the strategy that decided.
    pub basis: &'static str,
    /// Information present in an input and absent from the output (law L7).
    pub lost: Vec<Value>,
    /// Plain facts that explain the outcome, such as which elements differed.
    pub notes: Vec<String>,
    /// The case taken asks for review even when the rule's gate is `auto` (for
    /// example two different insertions at one gap, design 4.2).
    pub review: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Resolved {
    pub outcome: Outcome,
    pub used: Used,
}

impl Resolved {
    pub fn merged(value: Value, basis: &'static str) -> Self {
        Self {
            outcome: Outcome::Merged(value),
            used: Used {
                basis,
                ..Used::default()
            },
        }
    }
    pub fn conflict(reason: Reason, basis: &'static str) -> Self {
        Self {
            outcome: Outcome::Conflict(reason),
            used: Used {
                basis,
                ..Used::default()
            },
        }
    }
    pub fn with_notes(mut self, notes: Vec<String>) -> Self {
        self.used.notes = notes;
        self
    }
    /// One side preferred; the other side's value is carried as lost (law L7).
    pub fn prefer(side: Side, inputs: &Inputs<'_>, basis: &'static str) -> Self {
        Self {
            outcome: Outcome::Prefer(side),
            used: Used {
                basis,
                lost: vec![inputs.side(side.other()).clone()],
                ..Used::default()
            },
        }
    }
    /// `Prefer` by role when the parameter `name` asks for `prefer-role` and the
    /// roles decide; otherwise a conflict for `reason`.
    pub fn prefer_role_or(
        ctx: &Context<'_>,
        name: &str,
        inputs: &Inputs<'_>,
        reason: Reason,
        basis: &'static str,
    ) -> Self {
        match (ctx.param(name, "manual"), ctx.higher_role()) {
            ("prefer-role", Some(side)) => Self::prefer(side, inputs, basis),
            _ => Self::conflict(reason, basis),
        }
    }
}

/// The value an outcome selects: the merged value, or the preferred side's input.
pub fn selected<'a>(outcome: &'a Outcome, inputs: &Inputs<'a>) -> Option<&'a Value> {
    match outcome {
        Outcome::Merged(value) => Some(value),
        Outcome::Prefer(side) => Some(inputs.side(*side)),
        Outcome::Conflict(_) => None,
    }
}

/// The type a policy parameter must have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamType {
    Bool,
    Int { min: i64, max: i64 },
    OneOf(&'static [&'static str]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParamSpec {
    pub name: &'static str,
    pub ty: ParamType,
}

/// The laws of section 4.1 a strategy promises. The laws harness checks exactly
/// the promised ones, so a strategy that cannot keep one must say so here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Laws(u8);

impl Laws {
    pub const SYMMETRY: Self = Self(1);
    pub const IDEMPOTENCE: Self = Self(1 << 1);
    pub const IDENTITY: Self = Self(1 << 2);
    pub const TOTALITY: Self = Self(1 << 3);
    pub const DETERMINISM: Self = Self(1 << 4);
    pub const INVARIANTS: Self = Self(1 << 5);
    pub const NO_SILENT_LOSS: Self = Self(1 << 6);
    pub const BOUNDED: Self = Self(1 << 7);
    pub const ALL: Self = Self(u8::MAX);
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

pub trait Strategy: Send + Sync {
    /// The stable versioned identifier, such as `dynodoc.default.whole-value.v1`.
    fn id(&self) -> &'static str;
    /// The parameters a policy rule may set for this strategy.
    fn params(&self) -> &'static [ParamSpec] {
        &[]
    }
    /// The document-level collections this strategy decides. Empty means it decides
    /// node fields instead.
    fn aspects(&self) -> &'static [Aspect] {
        &[]
    }
    /// The laws of section 4.1 that the harness holds this strategy to.
    fn promises(&self) -> Laws {
        Laws::ALL
    }
    /// The largest canonical-JSON size of any input it decides (law L8); larger
    /// inputs return [`Reason::TOO_LARGE`]. `None` states no bound of its own.
    fn max_input_bytes(&self) -> Option<usize> {
        None
    }
    fn resolve(&self, inputs: &Inputs<'_>, ctx: &Context<'_>) -> Resolved;
}
