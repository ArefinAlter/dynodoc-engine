//! The existing audit event tree: H(0x00 || content_hash) leaves, H(0x01 ||
//! left || right) parents, and a raw 32-zero sibling at each odd layer. Empty
//! trees have a 32-zero root. This is distinct from an RFC 6962 history tree.
use engine_shared::DocumentId;
use futures::TryStreamExt;
use ring::digest::{Context, SHA256};
use sqlx::PgConnection;

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    for part in parts {
        context.update(part);
    }
    let mut result = [0; 32];
    result.copy_from_slice(context.finish().as_ref());
    result
}
/// A leaf over the stored event content hash, matching the audit proof endpoint.
pub fn leaf(content: &[u8]) -> [u8; 32] {
    hash(&[&[0], content])
}
fn parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash(&[&[1], left, right])
}
/// Streaming frontier; retains O(log(events)) hashes instead of all event rows.
#[derive(Default)]
pub struct Accumulator(Vec<Option<[u8; 32]>>);
impl Accumulator {
    pub fn push(&mut self, content: &[u8]) {
        let (mut next, mut level) = (leaf(content), 0);
        loop {
            if level == self.0.len() {
                self.0.push(Some(next));
                return;
            }
            match self.0[level].take() {
                None => {
                    self.0[level] = Some(next);
                    return;
                }
                Some(left) => {
                    next = parent(&left, &next);
                    level += 1;
                }
            }
        }
    }
    pub fn root(&self) -> [u8; 32] {
        let mut result = None;
        let mut height = 0;
        for (level, peak) in self.0.iter().enumerate() {
            if let Some(peak) = peak {
                if let Some(mut right) = result {
                    while height < level {
                        right = parent(&right, &[0; 32]);
                        height += 1;
                    }
                    result = Some(parent(peak, &right));
                    height = level + 1;
                } else {
                    result = Some(*peak);
                    height = level;
                }
            }
        }
        result.unwrap_or([0; 32])
    }
}
/// Root over the same exact ordered prefix as `/merkle-proof`: seq <= through_seq.
pub async fn root_in_connection(
    db: &mut PgConnection,
    doc: DocumentId,
    through_seq: i64,
) -> Result<[u8; 32], sqlx::Error> {
    let mut tree = Accumulator::default();
    let mut rows = sqlx::query_scalar::<_, Vec<u8>>(
        "select content_hash from event where document_id=$1 and seq<=$2 order by seq",
    )
    .bind(doc.0)
    .bind(through_seq)
    .fetch(db);
    while let Some(content) = rows.try_next().await? {
        tree.push(&content);
    }
    Ok(tree.root())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_frontier_matches_every_odd_and_even_padded_layer() {
        let mut tree = Accumulator::default();
        let mut leaves = Vec::new();
        assert_eq!(tree.root(), [0; 32]);
        for i in 0u64..1025 {
            tree.push(&i.to_be_bytes());
            leaves.push(leaf(&i.to_be_bytes()));
            let mut layer = leaves.clone();
            while layer.len() > 1 {
                if layer.len() % 2 == 1 {
                    layer.push([0; 32]);
                }
                layer = layer
                    .chunks_exact(2)
                    .map(|p| parent(&p[0], &p[1]))
                    .collect();
            }
            assert_eq!(tree.root(), layer[0], "prefix {}", i + 1);
        }
    }
}
