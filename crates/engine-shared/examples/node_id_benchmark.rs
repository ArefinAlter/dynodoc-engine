//! PR-73 In-Memory NodeId Benchmark:
//! Measures parse/conversion cost, allocation/retained memory, BTree ordering,
//! hash performance, and serde roundtrip between public `NodeId(pub String)`
//! and the internal `CompactNodeId` prototype.

use std::collections::{BTreeMap, HashMap};
use std::hint::black_box;
use std::time::Instant;

use engine_shared::ids::{encode_ulid_u128, CompactNodeId};
use engine_shared::NodeId;

#[derive(Debug, Clone, serde::Serialize)]
struct BenchmarkResult {
    workload: String,
    count: usize,
    node_id_parse_ns: f64,
    compact_parse_ns: f64,
    parse_speedup: f64,

    node_id_to_string_ns: f64,
    compact_to_string_ns: f64,

    node_id_hashmap_insert_ns: f64,
    compact_hashmap_insert_ns: f64,

    node_id_hashmap_lookup_ns: f64,
    compact_hashmap_lookup_ns: f64,

    node_id_btreemap_insert_ns: f64,
    compact_btreemap_insert_ns: f64,

    node_id_btreemap_lookup_ns: f64,
    compact_btreemap_lookup_ns: f64,

    node_id_json_ser_ns: f64,
    compact_json_ser_ns: f64,

    node_id_json_de_ns: f64,
    compact_json_de_ns: f64,

    node_id_retained_bytes: usize,
    compact_retained_bytes: usize,
    memory_savings_ratio: f64,
}

fn generate_canonical_ulids(n: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(n);
    let mut buf = [0u8; 26];
    for i in 0..n {
        let val = (i as u128) + 0x01850000000000000000000000000000;
        encode_ulid_u128(val, &mut buf);
        out.push(std::str::from_utf8(&buf).unwrap().to_string());
    }
    out
}

fn generate_historical_ids(n: usize) -> Vec<String> {
    let legacy_templates = [
        "01NODE00000000",
        "root",
        "question-1",
        "01arz3ndektsv4rrffq69g5fav",
        "stable",
        "clause_99",
        "doc_title_item",
        "choice_variant_a",
    ];
    let mut out = Vec::with_capacity(n);
    let mut buf = [0u8; 26];
    for i in 0..n {
        if i % 2 == 0 {
            let val = (i as u128) + 0x01850000000000000000000000000000;
            encode_ulid_u128(val, &mut buf);
            out.push(std::str::from_utf8(&buf).unwrap().to_string());
        } else {
            let idx = (i / 2) % legacy_templates.len();
            out.push(format!("{}_{}", legacy_templates[idx], i));
        }
    }
    out
}

fn generate_repetitive_ids(distinct: usize, repetitions: usize) -> Vec<String> {
    let base = generate_canonical_ulids(distinct);
    let mut out = Vec::with_capacity(distinct * repetitions);
    for _ in 0..repetitions {
        out.extend(base.iter().cloned());
    }
    out
}

fn run_workload(name: &str, raw_ids: &[String]) -> BenchmarkResult {
    let count = raw_ids.len();

    // 1. Parsing: &str -> NodeId vs CompactNodeId
    let start = Instant::now();
    let mut node_ids: Vec<NodeId> = Vec::with_capacity(count);
    for s in raw_ids {
        node_ids.push(black_box(NodeId(s.clone())));
    }
    let node_id_parse_time = start.elapsed();
    let node_id_parse_ns = (node_id_parse_time.as_nanos() as f64) / (count as f64);

    let start = Instant::now();
    let mut compact_ids: Vec<CompactNodeId> = Vec::with_capacity(count);
    for s in raw_ids {
        compact_ids.push(black_box(CompactNodeId::parse(s.as_str())));
    }
    let compact_parse_time = start.elapsed();
    let compact_parse_ns = (compact_parse_time.as_nanos() as f64) / (count as f64);

    // 2. Conversion to String:
    let start = Instant::now();
    for id in &node_ids {
        black_box(id.0.clone());
    }
    let node_id_to_str_time = start.elapsed();
    let node_id_to_string_ns = (node_id_to_str_time.as_nanos() as f64) / (count as f64);

    let start = Instant::now();
    for cid in &compact_ids {
        black_box(cid.to_string());
    }
    let compact_to_str_time = start.elapsed();
    let compact_to_string_ns = (compact_to_str_time.as_nanos() as f64) / (count as f64);

    // 3. HashMap Insert & Lookup
    let start = Instant::now();
    let mut map_node: HashMap<&NodeId, usize> = HashMap::with_capacity(count);
    for (i, id) in node_ids.iter().enumerate() {
        map_node.insert(id, i);
    }
    let node_hm_insert_ns = (start.elapsed().as_nanos() as f64) / (count as f64);

    let start = Instant::now();
    let mut map_compact: HashMap<&CompactNodeId, usize> = HashMap::with_capacity(count);
    for (i, cid) in compact_ids.iter().enumerate() {
        map_compact.insert(cid, i);
    }
    let compact_hm_insert_ns = (start.elapsed().as_nanos() as f64) / (count as f64);

    let start = Instant::now();
    for id in &node_ids {
        black_box(map_node.get(id));
    }
    let node_hm_lookup_ns = (start.elapsed().as_nanos() as f64) / (count as f64);

    let start = Instant::now();
    for cid in &compact_ids {
        black_box(map_compact.get(cid));
    }
    let compact_hm_lookup_ns = (start.elapsed().as_nanos() as f64) / (count as f64);

    // 4. BTreeMap Insert & Lookup
    let start = Instant::now();
    let mut btree_node: BTreeMap<&NodeId, usize> = BTreeMap::new();
    for (i, id) in node_ids.iter().enumerate() {
        btree_node.insert(id, i);
    }
    let node_bm_insert_ns = (start.elapsed().as_nanos() as f64) / (count as f64);

    let start = Instant::now();
    let mut btree_compact: BTreeMap<&CompactNodeId, usize> = BTreeMap::new();
    for (i, cid) in compact_ids.iter().enumerate() {
        btree_compact.insert(cid, i);
    }
    let compact_bm_insert_ns = (start.elapsed().as_nanos() as f64) / (count as f64);

    let start = Instant::now();
    for id in &node_ids {
        black_box(btree_node.get(id));
    }
    let node_bm_lookup_ns = (start.elapsed().as_nanos() as f64) / (count as f64);

    let start = Instant::now();
    for cid in &compact_ids {
        black_box(btree_compact.get(cid));
    }
    let compact_bm_lookup_ns = (start.elapsed().as_nanos() as f64) / (count as f64);

    // 5. Serde JSON Serialize & Deserialize
    let json_node = serde_json::to_string(&node_ids).unwrap();
    let json_compact = serde_json::to_string(&compact_ids).unwrap();
    assert_eq!(
        json_node, json_compact,
        "JSON serialization MUST be byte-for-byte identical"
    );

    let start = Instant::now();
    let _ = black_box(serde_json::to_string(&node_ids).unwrap());
    let node_json_ser_ns = (start.elapsed().as_nanos() as f64) / (count as f64);

    let start = Instant::now();
    let _ = black_box(serde_json::to_string(&compact_ids).unwrap());
    let compact_json_ser_ns = (start.elapsed().as_nanos() as f64) / (count as f64);

    let start = Instant::now();
    let de_nodes: Vec<NodeId> = serde_json::from_str(&json_node).unwrap();
    let node_json_de_ns = (start.elapsed().as_nanos() as f64) / (count as f64);
    assert_eq!(de_nodes.len(), count);

    let start = Instant::now();
    let de_compacts: Vec<CompactNodeId> = serde_json::from_str(&json_compact).unwrap();
    let compact_json_de_ns = (start.elapsed().as_nanos() as f64) / (count as f64);
    assert_eq!(de_compacts.len(), count);

    // 6. Retained Memory Calculation
    // NodeId stack size: 24 bytes + heap buffer: 26 bytes (allocator typically reserves 32 bytes)
    let node_id_retained_bytes = count * (std::mem::size_of::<NodeId>() + 32);

    let mut compact_retained_bytes = 0;
    for cid in &compact_ids {
        compact_retained_bytes += std::mem::size_of::<CompactNodeId>();
        if let CompactNodeId::Legacy(s) = cid {
            compact_retained_bytes += s.capacity().max(s.len());
        }
    }

    let memory_savings_ratio = (node_id_retained_bytes as f64) / (compact_retained_bytes as f64);

    BenchmarkResult {
        workload: name.to_string(),
        count,
        node_id_parse_ns,
        compact_parse_ns,
        parse_speedup: node_id_parse_ns / compact_parse_ns,
        node_id_to_string_ns,
        compact_to_string_ns,
        node_id_hashmap_insert_ns: node_hm_insert_ns,
        compact_hashmap_insert_ns: compact_hm_insert_ns,
        node_id_hashmap_lookup_ns: node_hm_lookup_ns,
        compact_hashmap_lookup_ns: compact_hm_lookup_ns,
        node_id_btreemap_insert_ns: node_bm_insert_ns,
        compact_btreemap_insert_ns: compact_bm_insert_ns,
        node_id_btreemap_lookup_ns: node_bm_lookup_ns,
        compact_btreemap_lookup_ns: compact_bm_lookup_ns,
        node_id_json_ser_ns: node_json_ser_ns,
        compact_json_ser_ns,
        node_id_json_de_ns: node_json_de_ns,
        compact_json_de_ns,
        node_id_retained_bytes,
        compact_retained_bytes,
        memory_savings_ratio,
    }
}

fn print_result(r: &BenchmarkResult) {
    println!("============================================================");
    println!("Workload: {} ({} elements)", r.workload, r.count);
    println!("------------------------------------------------------------");
    println!(
        "Memory Retained:      NodeId: {:>8} KiB | Compact: {:>8} KiB ({:.2}x smaller)",
        r.node_id_retained_bytes / 1024,
        r.compact_retained_bytes / 1024,
        r.memory_savings_ratio
    );
    println!(
        "Parse from &str:      NodeId: {:>7.2} ns/op | Compact: {:>7.2} ns/op ({:.2}x speedup)",
        r.node_id_parse_ns, r.compact_parse_ns, r.parse_speedup
    );
    println!(
        "Render to String:     NodeId: {:>7.2} ns/op | Compact: {:>7.2} ns/op",
        r.node_id_to_string_ns, r.compact_to_string_ns
    );
    println!(
        "HashMap Insert:       NodeId: {:>7.2} ns/op | Compact: {:>7.2} ns/op",
        r.node_id_hashmap_insert_ns, r.compact_hashmap_insert_ns
    );
    println!(
        "HashMap Lookup:       NodeId: {:>7.2} ns/op | Compact: {:>7.2} ns/op",
        r.node_id_hashmap_lookup_ns, r.compact_hashmap_lookup_ns
    );
    println!(
        "BTreeMap Insert:      NodeId: {:>7.2} ns/op | Compact: {:>7.2} ns/op",
        r.node_id_btreemap_insert_ns, r.compact_btreemap_insert_ns
    );
    println!(
        "BTreeMap Lookup:      NodeId: {:>7.2} ns/op | Compact: {:>7.2} ns/op",
        r.node_id_btreemap_lookup_ns, r.compact_btreemap_lookup_ns
    );
    println!(
        "JSON Serialize:       NodeId: {:>7.2} ns/op | Compact: {:>7.2} ns/op",
        r.node_id_json_ser_ns, r.compact_json_ser_ns
    );
    println!(
        "JSON Deserialize:     NodeId: {:>7.2} ns/op | Compact: {:>7.2} ns/op",
        r.node_id_json_de_ns, r.compact_json_de_ns
    );
    println!("============================================================");
    println!();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_path = args
        .windows(2)
        .find(|w| w[0] == "--out")
        .map(|w| w[1].clone());

    println!("Starting PR-73 In-Memory NodeId Benchmark...\n");

    let mut results = Vec::new();

    // Workload 1: 100k Canonical ULIDs
    let canonical_100k = generate_canonical_ulids(100_000);
    let r1 = run_workload("100k Canonical ULIDs", &canonical_100k);
    print_result(&r1);
    results.push(r1);

    // Workload 2: 10k Canonical ULIDs
    let canonical_10k = generate_canonical_ulids(10_000);
    let r2 = run_workload("10k Canonical ULIDs", &canonical_10k);
    print_result(&r2);
    results.push(r2);

    // Workload 3: 10k Mixed Historical & Legacy IDs
    let historical_10k = generate_historical_ids(10_000);
    let r3 = run_workload("10k Historical & Legacy IDs (50/50 mix)", &historical_10k);
    print_result(&r3);
    results.push(r3);

    // Workload 4: Repetitive Workload (1,000 distinct IDs repeated 100 times)
    let repetitive_100k = generate_repetitive_ids(1_000, 100);
    let r4 = run_workload("100k Repetitive IDs (1k x 100)", &repetitive_100k);
    print_result(&r4);
    results.push(r4);

    if let Some(path) = out_path {
        let json_data = serde_json::to_string_pretty(&results).unwrap();
        std::fs::write(&path, json_data).expect("write output file");
        println!("Wrote benchmark results to {}", path);
    }
}
