//! Parity vectors v1 (decision 036) through the native build of the WebAssembly exports.
//! The SDK runs the same file through the `.wasm` build in Node, so both targets reproduce
//! one frozen set of outputs. `DYNODOC_FILL_PARITY=1` fills outputs that are still
//! missing (only when the vector set is first written); it never overwrites one.
use dynodoc_engine_wasm::engine;
use serde_json::{json, Value};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../engine-core/tests/fixtures/wasm-parity-v1.json"
);

fn text(v: &Value) -> String {
    serde_json::to_string(v).unwrap()
}

/// Outputs of every vector, computed now.
fn outputs(doc: &Value) -> Value {
    let canonical = |cases: &Value| -> Vec<Value> {
        cases
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                let input = c["input"].as_str().unwrap();
                json!({
                    "output": engine::canonical_json(input).unwrap(),
                    "sha256": engine::canonical_hash(input).unwrap(),
                })
            })
            .collect()
    };
    let chain = &doc["chain"];
    let events = text(&chain["events"]);
    let verified: Value = serde_json::from_str(
        &engine::verify_chain(
            &events,
            chain["after_seq"].as_i64().unwrap(),
            chain["after_chain_hash"].as_str().unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let state = engine::fold(&events).unwrap();
    let merges: Vec<Value> = doc["merges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let plan: Value = serde_json::from_str(
                &engine::merge(
                    &text(&m["base"]),
                    &text(&m["team"]),
                    &text(&m["draft"]),
                    &text(&m["resolutions"]),
                )
                .unwrap(),
            )
            .unwrap();
            // Replaying the plan onto the team state gives the merged state.
            let replayed = engine::apply_ops(&text(&m["team"]), &text(&plan["ops"])).unwrap();
            assert_eq!(
                engine::state_hash(&replayed).unwrap(),
                engine::state_hash(&text(&plan["state"])).unwrap(),
                "{}",
                m["name"]
            );
            json!({
                "state_hash": engine::state_hash(&text(&plan["state"])).unwrap(),
                "conflicts": plan["conflicts"].as_array().unwrap().iter().map(|c| c["key"].clone()).collect::<Vec<_>>(),
                "ops_sha256": engine::canonical_hash(&text(&plan["ops"])).unwrap(),
            })
        })
        .collect();
    let text_merges: Vec<Value> = doc["text_merges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let merged =
                engine::merge_text(&text(&m["base"]), &text(&m["team"]), &text(&m["draft"]))
                    .unwrap();
            json!({"merged": serde_json::from_str::<Value>(&merged).unwrap()})
        })
        .collect();
    json!({
        "canonical_js_form": canonical(&doc["canonical_js_form"]),
        "canonical_lexemes": canonical(&doc["canonical_lexemes"]),
        "chain": {
            "through_seq": verified["through_seq"],
            "chain_hash": verified["chain_hash"],
            "state_hash": engine::state_hash(&state).unwrap(),
        },
        "merges": merges,
        "text_merges": text_merges,
    })
}

/// Fill missing output keys of `doc` from `out` and report outputs that differ. Only the
/// vector lists and `chain` are walked; every other output is compared whole.
fn compare(doc: &mut Value, out: &Value, path: &str, fill: bool, diffs: &mut Vec<String>) {
    for (k, v) in out.as_object().unwrap() {
        let here = format!("{path}.{k}");
        if k == "chain" {
            compare(&mut doc[k], v, &here, fill, diffs);
        } else if let (Some(items), true) = (v.as_array(), k != "conflicts") {
            for (i, v) in items.iter().enumerate() {
                compare(&mut doc[k][i], v, &format!("{here}[{i}]"), fill, diffs);
            }
        } else if doc.get(k).is_none() && fill {
            doc[k] = v.clone();
        } else if doc.get(k) != Some(v) {
            diffs.push(format!("{here}: expected {:?}, got {v}", doc.get(k)));
        }
    }
}

#[test]
fn native_build_reproduces_the_parity_vectors() {
    let raw = std::fs::read_to_string(PATH).unwrap();
    let mut doc: Value = serde_json::from_str(&raw).unwrap();
    let fill = std::env::var("DYNODOC_FILL_PARITY").as_deref() == Ok("1");
    let out = outputs(&doc);
    let mut diffs = Vec::new();
    compare(&mut doc, &out, "", fill, &mut diffs);
    if fill {
        let mut written = serde_json::to_string_pretty(&doc).unwrap();
        written.push('\n');
        if written != raw {
            std::fs::write(PATH, written).unwrap();
        }
    }
    assert!(diffs.is_empty(), "{}", diffs.join("\n"));
}

#[test]
fn a_tampered_event_breaks_the_chain_at_its_seq() {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let mut events = doc["chain"]["events"].clone();
    events[4]["payload"]["fields"] = json!({"title": "Tampered"});
    let err = engine::verify_chain(&text(&events), 0, &"0".repeat(64)).unwrap_err();
    assert!(err.to_string().contains("seq 5"), "{err}");
    // A wrong trusted start is refused, not silently re-anchored.
    assert!(engine::verify_chain(&text(&doc["chain"]["events"]), 0, &"1".repeat(64)).is_err());
    // Verifying from a later trusted position needs only the rows after it.
    let tail = Value::Array(doc["chain"]["events"].as_array().unwrap()[3..].to_vec());
    let anchor: Vec<u8> =
        serde_json::from_value(doc["chain"]["events"][2]["chain_hash"].clone()).unwrap();
    let anchor: String = anchor.iter().map(|b| format!("{b:02x}")).collect();
    assert!(engine::verify_chain(&text(&tail), 3, &anchor).is_ok());
    assert!(engine::verify_chain(&text(&tail), 2, &anchor).is_err());
}
