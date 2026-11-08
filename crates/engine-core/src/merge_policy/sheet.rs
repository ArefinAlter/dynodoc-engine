//! Spreadsheet strategies (design 4.5, 4.6) and the formula tokenizer they share.
//!
//! * [`tokens`]: a tokenizer owned by Dynodoc, independent of the formula engine
//!   being replaced. Two formulas are equal when their token streams are; function
//!   names, names, booleans, errors and references compare case-insensitively,
//!   string literals exactly, whitespace outside strings not at all. A formula that
//!   does not tokenize is `unparsed` and only ever equal to itself.
//! * `dynodoc.sheet.cell.v1` ([`SheetCell`]): one `cell_<n>` or `format_<n>` field.
//! * `dynodoc.sheet.shift.v1` ([`SheetShift`], N4): a column inserted or deleted on
//!   one side rewrites `cell_<n>`/`format_<n>` keys in every row and references in
//!   every formula, so a state merge sees thousands of changed fields. A shift
//!   *certificate* says that side equals the shifted base plus a residual of at
//!   most 5 % of cells; it is accepted only when unique. The other side (and the
//!   base) are then rewritten through the same shift and merged cell by cell.
//!
//! Not built: row shifts (rows are nodes with identifiers already; only formula
//! references to rows move), more than one column per side, cross-sheet references
//! (rewritten only for the shifted sheet's own unqualified or self-qualified
//! references), and stable column identifiers (NC-Q5). Excel's exact rules at range
//! boundaries were not verified against vendor documentation: a range whose first
//! column is deleted keeps its position and loses one column, a range is expanded
//! when a column is inserted after its first column.

use super::{
    strategy::{Context, Inputs, Laws, ParamSpec, ParamType, Reason, Resolved, Strategy},
    Aspect,
};
use crate::materializer::DocumentState;
use engine_shared::NodeId;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const CELL_ID: &str = "dynodoc.sheet.cell.v1";
pub const SHIFT_ID: &str = "dynodoc.sheet.shift.v1";
pub const MAX_COLUMNS: u32 = 100;
pub const MAX_ROWS: u32 = 3_000;
const MAX_FORMULA: usize = 8_192;

/// A cell or column reference: column and row are zero-based, `$` marks absolute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ref {
    pub sheet: Option<String>,
    pub col: Option<(bool, u32)>,
    pub row: Option<(bool, u32)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    Str(String),
    Num(String),
    Bool(bool),
    Error(String),
    Op(String),
    Func(String),
    Name(String),
    Ref(Ref),
}

/// A token and where its text is in the formula (bytes).
#[derive(Clone, Debug)]
pub struct Spanned {
    pub token: Token,
    pub start: usize,
    pub end: usize,
}

fn col_index(letters: &str) -> Option<u32> {
    if letters.is_empty() || letters.len() > 3 {
        return None;
    }
    let mut n: u32 = 0;
    for c in letters.bytes() {
        n = n * 26 + u32::from(c.to_ascii_uppercase() - b'A') + 1;
    }
    (n <= 16_384).then(|| n - 1)
}

pub fn col_letters(mut col: u32) -> String {
    let mut out = Vec::new();
    loop {
        out.push(b'A' + (col % 26) as u8);
        if col < 26 {
            break;
        }
        col = col / 26 - 1;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// `$A$1`, `A1`, `$A` (column only) after any sheet prefix.
/// One coordinate of a reference: absolute (`$`) or not, and its zero-based index.
type Coord = Option<(bool, u32)>;

fn parse_ref(text: &str, column_only: bool) -> Option<(Coord, Coord)> {
    let b = text.as_bytes();
    let mut i = 0;
    let abs_col = b.first() == Some(&b'$');
    i += usize::from(abs_col);
    let start = i;
    while i < b.len() && b[i].is_ascii_alphabetic() {
        i += 1;
    }
    let col = col_index(&text[start..i])?;
    if i == b.len() {
        return column_only.then_some((Some((abs_col, col)), None));
    }
    let abs_row = b[i] == b'$';
    i += usize::from(abs_row);
    let digits = &text[i..];
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) || digits.starts_with('0') {
        return None;
    }
    let row: u32 = digits.parse().ok()?;
    (1..=1_048_576)
        .contains(&row)
        .then_some((Some((abs_col, col)), Some((abs_row, row - 1))))
}

/// Tokenize a formula (with or without the leading `=`). `None` is `unparsed`.
pub fn tokens(formula: &str) -> Option<Vec<Spanned>> {
    let src = formula.strip_prefix('=').unwrap_or(formula);
    let offset = formula.len() - src.len();
    if src.len() > MAX_FORMULA {
        return None;
    }
    let b = src.as_bytes();
    let mut out: Vec<Spanned> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let start = i;
        let push = |out: &mut Vec<Spanned>, token, end| {
            out.push(Spanned {
                token,
                start: start + offset,
                end: end + offset,
            });
        };
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c == b'"' {
            let mut s = String::new();
            i += 1;
            loop {
                let ch = *b.get(i)?;
                if ch == b'"' {
                    if b.get(i + 1) == Some(&b'"') {
                        s.push('"');
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                let next = src[i..].chars().next()?;
                s.push(next);
                i += next.len_utf8();
            }
            push(&mut out, Token::Str(s), i);
            continue;
        }
        if c.is_ascii_digit() || (c == b'.' && b.get(i + 1).is_some_and(u8::is_ascii_digit)) {
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
                let mut j = i + 1;
                if j < b.len() && (b[j] == b'+' || b[j] == b'-') {
                    j += 1;
                }
                if j < b.len() && b[j].is_ascii_digit() {
                    i = j;
                    while i < b.len() && b[i].is_ascii_digit() {
                        i += 1;
                    }
                }
            }
            push(&mut out, Token::Num(src[start..i].to_ascii_lowercase()), i);
            continue;
        }
        if c == b'#' {
            i += 1;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b"/!?".contains(&b[i])) {
                i += 1;
            }
            push(
                &mut out,
                Token::Error(src[start..i].to_ascii_uppercase()),
                i,
            );
            continue;
        }
        // A sheet prefix: 'Quoted name'! or Name!
        let mut sheet = None;
        if c == b'\'' {
            let mut s = String::new();
            i += 1;
            loop {
                let ch = *b.get(i)?;
                if ch == b'\'' {
                    if b.get(i + 1) == Some(&b'\'') {
                        s.push('\'');
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                let next = src[i..].chars().next()?;
                s.push(next);
                i += next.len_utf8();
            }
            if b.get(i) != Some(&b'!') {
                return None;
            }
            i += 1;
            sheet = Some(s);
        }
        let ident = |i: usize| {
            let mut j = i;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b"_.$".contains(&b[j])) {
                j += 1;
            }
            j
        };
        if sheet.is_some() || c.is_ascii_alphabetic() || c == b'_' || c == b'$' {
            let mut j = ident(i);
            if sheet.is_none() && b.get(j) == Some(&b'!') {
                sheet = Some(src[i..j].to_string());
                i = j + 1;
                j = ident(i);
            }
            let word = &src[i..j];
            if sheet.is_none() && b.get(j) == Some(&b'(') && !word.is_empty() {
                push(&mut out, Token::Func(word.to_ascii_uppercase()), j);
                i = j;
                continue;
            }
            let after_colon =
                matches!(out.last(), Some(Spanned { token: Token::Op(op), .. }) if op == ":");
            let column_only = after_colon || b.get(j) == Some(&b':');
            if let Some((col, row)) = parse_ref(word, column_only) {
                push(
                    &mut out,
                    Token::Ref(Ref {
                        sheet: sheet.map(|s| s.to_uppercase()),
                        col,
                        row,
                    }),
                    j,
                );
                i = j;
                continue;
            }
            if sheet.is_some() || word.is_empty() {
                return None;
            }
            let upper = word.to_ascii_uppercase();
            let token = if b.get(j) == Some(&b'(') {
                Token::Func(upper)
            } else if upper == "TRUE" || upper == "FALSE" {
                Token::Bool(upper == "TRUE")
            } else {
                Token::Name(upper)
            };
            push(&mut out, token, j);
            i = j;
            continue;
        }
        let two = src.get(i..i + 2);
        let op = match two {
            Some("<=" | ">=" | "<>") => {
                i += 2;
                two.map(str::to_string)
            }
            _ if b"+-*/^&=<>%:(),;{}@".contains(&c) => {
                i += 1;
                Some((c as char).to_string())
            }
            _ => None,
        }?;
        push(&mut out, Token::Op(op), i);
    }
    Some(out)
}

/// Equal token streams, or `None` when either side does not tokenize.
pub fn same_formula(a: &str, b: &str) -> Option<bool> {
    let (x, y) = (tokens(a)?, tokens(b)?);
    Some(x.len() == y.len() && x.iter().zip(&y).all(|(p, q)| p.token == q.token))
}

fn is_formula(v: &Value) -> bool {
    v.as_str().is_some_and(|s| s.starts_with('='))
}

pub struct SheetCell;

const CELL_PARAMS: &[ParamSpec] = &[
    ParamSpec {
        name: "formula_equality",
        ty: ParamType::OneOf(&["tokens", "exact"]),
    },
    ParamSpec {
        name: "value_conflict",
        ty: ParamType::OneOf(&["manual", "prefer-role"]),
    },
];

impl Strategy for SheetCell {
    fn id(&self) -> &'static str {
        CELL_ID
    }
    fn params(&self) -> &'static [ParamSpec] {
        CELL_PARAMS
    }
    fn max_input_bytes(&self) -> Option<usize> {
        Some(1 << 16)
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
            .any(|v| serde_json::to_vec(v).map_or(usize::MAX, |b| b.len()) > 1 << 16)
        {
            return Resolved::conflict(Reason::TOO_LARGE, "bound");
        }
        if ctx.field.starts_with("format_") {
            let base = (!i.base.is_null()).then_some(i.base);
            return match crate::richtext::merge_property(base, Some(i.team), Some(i.draft)) {
                Ok(Some(v)) => Resolved::merged(v, "format-keys"),
                _ => Resolved::prefer_role_or(ctx, "value_conflict", i, Reason::OVERLAP, "format"),
            };
        }
        match (is_formula(i.team), is_formula(i.draft)) {
            (true, true) => {
                let (t, d) = (
                    i.team.as_str().unwrap_or(""),
                    i.draft.as_str().unwrap_or(""),
                );
                if ctx.param("formula_equality", "tokens") == "tokens" {
                    if let Some(true) = same_formula(t, d) {
                        // One spelling of one formula; the order is content order.
                        let kept = if t <= d { i.team } else { i.draft };
                        return Resolved::merged(kept.clone(), "formula-equal").with_notes(vec![
                            format!("the two formulas have equal tokens; kept the spelling {kept}"),
                        ]);
                    }
                    if tokens(t).is_none() || tokens(d).is_none() {
                        return Resolved::conflict(Reason::BOTH_CHANGED, "unparsed")
                            .with_notes(vec!["a formula does not tokenize (unparsed)".into()]);
                    }
                }
                Resolved::prefer_role_or(ctx, "value_conflict", i, Reason::BOTH_CHANGED, "formula")
            }
            (false, false) if !is_formula(i.base) => {
                Resolved::prefer_role_or(ctx, "value_conflict", i, Reason::BOTH_CHANGED, "value")
            }
            _ => Resolved::conflict(Reason::KIND_CHANGED, "formula-value"),
        }
    }
}

/// A column inserted before (or deleted at) zero-based column `at`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Shift {
    pub insert: bool,
    pub at: u32,
}

impl Shift {
    /// Where base column `col` is after the shift, `None` when it was deleted.
    fn map(self, col: u32) -> Option<u32> {
        match (self.insert, col.cmp(&self.at)) {
            (_, std::cmp::Ordering::Less) => Some(col),
            (true, _) => Some(col + 1),
            (false, std::cmp::Ordering::Equal) => None,
            (false, std::cmp::Ordering::Greater) => Some(col - 1),
        }
    }
}

/// Rewrite the references of `formula` that address `sheet` (unqualified, or
/// qualified with its label) through `shift`. Text outside references is kept.
pub fn rewrite(formula: &str, shift: Shift, label: Option<&str>) -> String {
    if !formula.starts_with('=') {
        return formula.to_string();
    }
    let Some(toks) = tokens(formula) else {
        return formula.to_string();
    };
    let ours = |r: &Ref| match (&r.sheet, label) {
        (None, _) => true,
        (Some(s), Some(l)) => s.eq_ignore_ascii_case(l),
        _ => false,
    };
    // The sheet prefix is kept exactly as written.
    let text = |r: &Ref, col: u32, written: &str| {
        let mut s = String::new();
        if r.sheet.is_some() {
            s.push_str(written.rfind('!').map_or("", |p| &written[..=p]));
        }
        if let Some((abs, _)) = r.col {
            if abs {
                s.push('$');
            }
            s.push_str(&col_letters(col));
        }
        if let Some((abs, row)) = r.row {
            if abs {
                s.push('$');
            }
            s.push_str(&(row + 1).to_string());
        }
        s
    };
    // (start, end, replacement) for every reference or range that moves.
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut k = 0;
    while k < toks.len() {
        let Token::Ref(first) = &toks[k].token else {
            k += 1;
            continue;
        };
        let range = matches!(toks.get(k + 1), Some(Spanned { token: Token::Op(op), .. }) if op == ":")
            && matches!(
                toks.get(k + 2),
                Some(Spanned {
                    token: Token::Ref(_),
                    ..
                })
            );
        if !ours(first) || first.col.is_none() {
            k += if range { 3 } else { 1 };
            continue;
        }
        if range {
            let Token::Ref(last) = &toks[k + 2].token else {
                break;
            };
            let (Some((_, c1)), Some((_, c2))) = (first.col, last.col) else {
                k += 3;
                continue;
            };
            let (lo, hi) = (c1.min(c2), c1.max(c2));
            let mapped = if shift.insert {
                Some((shift.map(lo).unwrap_or(lo), shift.map(hi).unwrap_or(hi)))
            } else if lo == hi && lo == shift.at {
                None
            } else {
                let lo2 = if lo > shift.at { lo - 1 } else { lo };
                let hi2 = if hi >= shift.at { hi - 1 } else { hi };
                Some((lo2, hi2))
            };
            let (s, e) = (toks[k].start, toks[k + 2].end);
            let replacement = match mapped {
                Some((a, b)) => format!(
                    "{}:{}",
                    text(first, a, &formula[s..toks[k].end]),
                    text(last, b, &formula[toks[k + 2].start..e])
                ),
                None => "#REF!".to_string(),
            };
            if replacement != formula[s..e] {
                edits.push((s, e, replacement));
            }
            k += 3;
            continue;
        }
        let Some((_, col)) = first.col else {
            k += 1;
            continue;
        };
        let (s, e) = (toks[k].start, toks[k].end);
        let replacement = match shift.map(col) {
            Some(c) => text(first, c, &formula[s..e]),
            None => "#REF!".to_string(),
        };
        if replacement != formula[s..e] && shift.map(col) != Some(col) {
            edits.push((s, e, replacement));
        }
        k += 1;
    }
    let mut out = formula.to_string();
    for (s, e, r) in edits.into_iter().rev() {
        out.replace_range(s..e, &r);
    }
    out
}

/// One sheet as the shift strategy sees it: its column count and each row's cells.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Grid {
    pub columns: u32,
    pub label: Option<String>,
    /// Row node id to `cell_<n>`/`format_<n>` field values by column.
    pub rows: BTreeMap<String, BTreeMap<u32, (Value, Value)>>,
}

impl Grid {
    pub fn from_json(v: &Value) -> Option<Self> {
        let columns = u32::try_from(v["columns"].as_u64()?).ok()?;
        let mut rows = BTreeMap::new();
        for (id, fields) in v["rows"].as_object()? {
            let mut cells = BTreeMap::new();
            for (k, val) in fields.as_object()? {
                if let Some(n) = k.strip_prefix("cell_").and_then(|n| n.parse().ok()) {
                    cells.entry(n).or_insert((Value::Null, Value::Null)).0 = val.clone();
                } else if let Some(n) = k.strip_prefix("format_").and_then(|n| n.parse().ok()) {
                    cells.entry(n).or_insert((Value::Null, Value::Null)).1 = val.clone();
                }
            }
            rows.insert(id.clone(), cells);
        }
        Some(Self {
            columns,
            label: v["label"].as_str().map(str::to_string),
            rows,
        })
    }
    pub fn to_json(&self) -> Value {
        let mut rows = Map::new();
        for (id, cells) in &self.rows {
            let mut fields = Map::new();
            for (n, (cell, format)) in cells {
                if !cell.is_null() {
                    fields.insert(format!("cell_{n}"), cell.clone());
                }
                if !format.is_null() {
                    fields.insert(format!("format_{n}"), format.clone());
                }
            }
            rows.insert(id.clone(), Value::Object(fields));
        }
        json!({"columns": self.columns, "label": self.label, "rows": rows})
    }
    fn cell(&self, row: &str, col: u32) -> &Value {
        static NULL: Value = Value::Null;
        self.rows
            .get(row)
            .and_then(|r| r.get(&col))
            .map_or(&NULL, |c| &c.0)
    }
    /// The grid after `shift`, formulas rewritten.
    pub fn shifted(&self, shift: Shift) -> Self {
        let mut rows = BTreeMap::new();
        for (id, cells) in &self.rows {
            let mut out = BTreeMap::new();
            for (col, (cell, format)) in cells {
                let Some(c) = shift.map(*col) else { continue };
                let cell = match cell.as_str() {
                    Some(f) if f.starts_with('=') => {
                        Value::String(rewrite(f, shift, self.label.as_deref()))
                    }
                    _ => cell.clone(),
                };
                out.insert(c, (cell, format.clone()));
            }
            rows.insert(id.clone(), out);
        }
        Self {
            columns: if shift.insert {
                self.columns + 1
            } else {
                self.columns.saturating_sub(1)
            },
            label: self.label.clone(),
            rows,
        }
    }
}

fn cells_equal(a: &Value, b: &Value) -> bool {
    let empty = |v: &Value| v.is_null() || v.as_str() == Some("");
    if a == b || (empty(a) && empty(b)) {
        return true;
    }
    match (a.as_str(), b.as_str()) {
        (Some(x), Some(y)) if x.starts_with('=') && y.starts_with('=') => {
            same_formula(x, y).unwrap_or(false)
        }
        _ => false,
    }
}

/// What explains `side` as a shift of `base`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Certificate {
    /// The column counts are equal: no shift.
    None,
    Unique(Shift),
    /// No shift explains the side within the residual bound, or two shifts with
    /// different results explain it equally well.
    Ambiguous,
}

/// The residual of `side` against `base` shifted by `shift`, stopping above `cap`.
fn residual(base: &Grid, side: &Grid, shift: Shift, cap: usize) -> Option<(usize, Grid)> {
    let shifted = base.shifted(shift);
    let mut count = 0;
    for id in side.rows.keys().filter(|id| base.rows.contains_key(*id)) {
        for col in 0..side.columns {
            if !cells_equal(shifted.cell(id, col), side.cell(id, col)) {
                count += 1;
                if count > cap {
                    return None;
                }
            }
        }
    }
    Some((count, shifted))
}

/// Find the unique shift certificate (design 4.6 steps 1 and 2).
pub fn certify(base: &Grid, side: &Grid) -> Certificate {
    let insert = match side.columns.cmp(&base.columns) {
        std::cmp::Ordering::Equal => return Certificate::None,
        std::cmp::Ordering::Greater if side.columns == base.columns + 1 => true,
        std::cmp::Ordering::Less if side.columns + 1 == base.columns => false,
        _ => return Certificate::Ambiguous,
    };
    let common = side
        .rows
        .keys()
        .filter(|id| base.rows.contains_key(*id))
        .count();
    let cells = common * side.columns as usize;
    let cap = cells.div_ceil(20);
    let candidates = if insert {
        base.columns + 1
    } else {
        base.columns
    };
    let mut best: Vec<(Shift, Grid)> = Vec::new();
    let mut best_count = usize::MAX;
    for at in 0..candidates {
        let shift = Shift { insert, at };
        let Some((count, shifted)) = residual(base, side, shift, cap.min(best_count)) else {
            continue;
        };
        if count < best_count {
            best_count = count;
            best.clear();
        }
        best.push((shift, shifted));
    }
    match best.as_slice() {
        [] => Certificate::Ambiguous,
        [(shift, first), rest @ ..] => {
            let same = |g: &Grid| {
                g.rows.iter().all(|(id, cells)| {
                    (0..g.columns.max(first.columns)).all(|c| {
                        cells_equal(
                            &cells.get(&c).map_or(Value::Null, |v| v.0.clone()),
                            first.cell(id, c),
                        )
                    })
                })
            };
            if rest.iter().all(|(_, g)| same(g)) {
                Certificate::Unique(*shift)
            } else {
                Certificate::Ambiguous
            }
        }
    }
}

/// The live sheet sections of a state and their rows, as grids.
pub fn grids(state: &DocumentState) -> BTreeMap<NodeId, Grid> {
    let mut out: BTreeMap<NodeId, Grid> = BTreeMap::new();
    for node in state.nodes.values() {
        if !node.deleted && node.current_fields["kind"] == "sheet" {
            let columns = node.current_fields["columns"]
                .as_u64()
                .and_then(|c| u32::try_from(c).ok())
                .unwrap_or(12);
            out.insert(
                node.id.clone(),
                Grid {
                    columns,
                    label: node.current_fields["label"].as_str().map(str::to_string),
                    rows: BTreeMap::new(),
                },
            );
        }
    }
    for node in state.nodes.values() {
        let Some(parent) = node.parent_id.as_ref().filter(|_| !node.deleted) else {
            continue;
        };
        let Some(grid) = out.get_mut(parent) else {
            continue;
        };
        let mut cells = BTreeMap::new();
        if let Some(fields) = node.current_fields.as_object() {
            for (k, v) in fields {
                if let Some(n) = k.strip_prefix("cell_").and_then(|n| n.parse::<u32>().ok()) {
                    cells.entry(n).or_insert((Value::Null, Value::Null)).0 = v.clone();
                } else if let Some(n) = k
                    .strip_prefix("format_")
                    .and_then(|n| n.parse::<u32>().ok())
                {
                    cells.entry(n).or_insert((Value::Null, Value::Null)).1 = v.clone();
                }
            }
        }
        grid.rows.insert(node.id.0.clone(), cells);
    }
    out
}

/// Rewrite one sheet of `state` through `shift`: row keys, formulas and `columns`.
pub fn apply_shift(state: &mut DocumentState, sheet: &NodeId, shift: Shift) {
    let label = state
        .nodes
        .get(sheet)
        .and_then(|n| n.current_fields["label"].as_str().map(str::to_string));
    for node in state.nodes.values_mut() {
        if node.id == *sheet {
            if let Some(c) = node.current_fields["columns"].as_u64() {
                node.current_fields["columns"] = json!(if shift.insert {
                    c + 1
                } else {
                    c.saturating_sub(1)
                });
            }
            continue;
        }
        if node.parent_id.as_ref() != Some(sheet) {
            continue;
        }
        let Some(fields) = node.current_fields.as_object() else {
            continue;
        };
        let mut out = Map::new();
        for (k, v) in fields {
            let moved = |prefix: &str| -> Option<Option<String>> {
                let n: u32 = k.strip_prefix(prefix)?.parse().ok()?;
                Some(shift.map(n).map(|c| format!("{prefix}{c}")))
            };
            match moved("cell_").or_else(|| moved("format_")) {
                Some(Some(key)) => {
                    let v = match v.as_str() {
                        Some(f) if key.starts_with("cell_") && f.starts_with('=') => {
                            Value::String(rewrite(f, shift, label.as_deref()))
                        }
                        _ => v.clone(),
                    };
                    out.insert(key, v);
                }
                Some(None) => {}
                None => {
                    out.insert(k.clone(), v.clone());
                }
            }
        }
        node.current_fields = Value::Object(out);
    }
}

pub struct SheetShift;

impl Strategy for SheetShift {
    fn id(&self) -> &'static str {
        SHIFT_ID
    }
    fn aspects(&self) -> &'static [Aspect] {
        &[Aspect::Structure]
    }
    fn max_input_bytes(&self) -> Option<usize> {
        Some(16 << 20)
    }
    /// Decides a sheet given as `{columns, label, rows: {row: {cell_n, format_n}}}`:
    /// certify each side, rewrite the base and the side without a shift through the
    /// other side's certificate, and merge cell by cell (a cell changed differently
    /// on both sides is a conflict). This is the same certificate the convergence
    /// pre-pass uses; it exists as a strategy so a policy can name and gate it.
    fn resolve(&self, i: &Inputs<'_>, _: &Context<'_>) -> Resolved {
        if i.draft == i.base || i.draft == i.team {
            return Resolved::merged(i.team.clone(), "unchanged-or-team-only");
        }
        if i.team == i.base {
            return Resolved::merged(i.draft.clone(), "draft-only");
        }
        if [i.base, i.team, i.draft]
            .iter()
            .any(|v| serde_json::to_vec(v).map_or(usize::MAX, |b| b.len()) > 16 << 20)
        {
            return Resolved::conflict(Reason::TOO_LARGE, "bound");
        }
        let (Some(b), Some(t), Some(d)) = (
            Grid::from_json(i.base),
            Grid::from_json(i.team),
            Grid::from_json(i.draft),
        ) else {
            return Resolved::conflict(Reason::UNSUPPORTED_SHAPE, "grid");
        };
        let (base, team, draft) = match (certify(&b, &t), certify(&b, &d)) {
            (Certificate::None, Certificate::None) => (b, t, d),
            (Certificate::Unique(s), Certificate::None) => (b.shifted(s), t, d.shifted(s)),
            (Certificate::None, Certificate::Unique(s)) => (b.shifted(s), t.shifted(s), d),
            (Certificate::Unique(x), Certificate::Unique(y)) if x == y => (b.shifted(x), t, d),
            _ => return Resolved::conflict(Reason::AMBIGUOUS_SHIFT, "certificate"),
        };
        let mut out = team.clone();
        let mut differ = Vec::new();
        let ids: std::collections::BTreeSet<&String> = base
            .rows
            .keys()
            .chain(team.rows.keys())
            .chain(draft.rows.keys())
            .collect();
        for id in ids {
            for col in 0..team.columns.max(draft.columns) {
                let get = |g: &Grid| g.rows.get(id).and_then(|r| r.get(&col)).cloned();
                let (bc, tc, dc) = (get(&base), get(&team), get(&draft));
                let v = if dc == bc || dc == tc {
                    tc
                } else if tc == bc {
                    dc
                } else {
                    differ.push(format!("{id}:cell_{col}"));
                    tc
                };
                let row = out.rows.entry(id.clone()).or_default();
                match v {
                    Some(v) => {
                        row.insert(col, v);
                    }
                    None => {
                        row.remove(&col);
                    }
                }
            }
        }
        if differ.is_empty() {
            Resolved::merged(out.to_json(), "shift-certificate")
        } else {
            Resolved::conflict(Reason::ELEMENT_DIFFERS, "shift-certificate").with_notes(differ)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_ignore_case_and_space_but_not_strings() {
        assert_eq!(same_formula("=sum(a1:b2)", "=SUM( A1 : B2 )"), Some(true));
        assert_eq!(same_formula("=\"a\"", "=\"A\""), Some(false));
        assert_eq!(same_formula("=A1+1", "=A1+2"), Some(false));
        assert!(tokens("=\"open").is_none());
        assert_eq!(
            same_formula("='My Sheet'!$A$1", "='MY SHEET'!$a$1"),
            Some(true)
        );
    }

    #[test]
    fn column_letters_round_trip() {
        for c in [0, 25, 26, 27, 701, 702, 16_383] {
            assert_eq!(col_index(&col_letters(c)), Some(c));
        }
    }

    #[test]
    fn rewrite_follows_insert_and_delete_rules() {
        let ins = Shift {
            insert: true,
            at: 1,
        };
        assert_eq!(rewrite("=A1+B1+$C$2", ins, None), "=A1+C1+$D$2");
        assert_eq!(rewrite("=SUM(A1:C1)", ins, None), "=SUM(A1:D1)");
        assert_eq!(rewrite("=Other!B1", ins, Some("Sheet1")), "=Other!B1");
        assert_eq!(rewrite("=Sheet1!B1", ins, Some("Sheet1")), "=Sheet1!C1");
        assert_eq!(rewrite("=LOG10(B1)", ins, None), "=LOG10(C1)");
        let del = Shift {
            insert: false,
            at: 1,
        };
        assert_eq!(rewrite("=B1+C1", del, None), "=#REF!+B1");
        assert_eq!(rewrite("=SUM(A1:C1)", del, None), "=SUM(A1:B1)");
        assert_eq!(rewrite("=SUM(B1:B3)", del, None), "=SUM(#REF!)");
    }

    fn grid(columns: u32, rows: &[(&str, &[&str])]) -> Grid {
        let mut g = Grid {
            columns,
            label: None,
            rows: BTreeMap::new(),
        };
        for (id, cells) in rows {
            g.rows.insert(
                (*id).into(),
                cells
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| !c.is_empty())
                    .map(|(n, c)| (n as u32, (json!(c), Value::Null)))
                    .collect(),
            );
        }
        g
    }

    #[test]
    fn a_column_insert_is_certified_uniquely_and_a_cell_edit_follows_it() {
        let base = grid(3, &[("r1", &["a", "b", "=B1"]), ("r2", &["c", "d", "e"])]);
        let left = grid(
            4,
            &[("r1", &["a", "", "b", "=C1"]), ("r2", &["c", "", "d", "e"])],
        );
        assert_eq!(
            certify(&base, &left),
            Certificate::Unique(Shift {
                insert: true,
                at: 1
            })
        );
        let right = grid(3, &[("r1", &["a", "B!", "=B1"]), ("r2", &["c", "d", "e"])]);
        let params = BTreeMap::new();
        let ctx = Context {
            node: None,
            node_type: "section",
            field: "$structure",
            aspect: Some(Aspect::Structure),
            family: super::super::Family::Spreadsheet,
            params: &params,
            roles: None,
            rank: &[],
            marks: None,
        };
        let (b, l, r) = (base.to_json(), left.to_json(), right.to_json());
        let merged = SheetShift.resolve(
            &Inputs {
                base: &b,
                team: &l,
                draft: &r,
            },
            &ctx,
        );
        let expected = grid(
            4,
            &[
                ("r1", &["a", "", "B!", "=C1"]),
                ("r2", &["c", "", "d", "e"]),
            ],
        );
        assert_eq!(
            merged.outcome,
            super::super::Outcome::Merged(expected.to_json())
        );
    }

    #[test]
    fn two_equally_good_but_different_shifts_are_ambiguous() {
        let base = grid(2, &[("r1", &["x", "y"])]);
        // Deleting either column leaves one cell that matches neither base cell.
        let side = grid(1, &[("r1", &["z"])]);
        assert_eq!(certify(&base, &side), Certificate::Ambiguous);
    }
}
