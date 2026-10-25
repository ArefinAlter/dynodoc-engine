# Optional grouping of concurrent workspace insertions

Status: Opt-in library preference (`merge_with_grouped_insertions` / `merge_strict_with_grouped_insertions`)
proposed in PR #39. Default merge behavior and signed v1 convergence are unchanged.

## Design rules

1. **Ordering**: In base gaps where concurrent insertions alternate between team and draft (e.g. team/draft/team), keeps each side's run together.
2. **Conflict gating**: Groups only when structural and strict existing-block conflicts are resolved. Changes positions, never parent IDs.
3. **Position bounds**: Concatenated positional keys must not exceed 200 bytes and must precede the next sibling separator. If bounds fail, retains existing interleaved positions.
4. **Compatibility**: Does not alter migrations, storage schemas, or wire codecs. Previously recorded events and stored positions are untouched.
