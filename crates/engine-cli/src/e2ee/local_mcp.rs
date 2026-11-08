//! A local MCP backend for one sealed file of an encrypted project (clients document 8.2):
//! the file was delegated to this agent's key by a person, with typed consent, through
//! `engine-cli e2ee delegate`; this process opens the delegation, decrypts the file into memory
//! and answers read tools from it. Nothing is written to disk, nothing goes to the service but
//! ciphertext fetches, and there is no write tool: proposals on encrypted files are a later
//! phase. The hosted gateway refuses sealed files (`422 encrypted_project`, `local_agent`).
use engine_core::materializer::DocumentState;
use engine_mcp::{Backend, CallContext, Tool, ToolCall, ToolOutput};
use serde_json::{json, Value};

/// Largest answer in characters, so one call cannot flood the assistant's context.
const MAX_ANSWER: usize = 64 * 1024;

pub struct SealedBackend {
    pub document: uuid::Uuid,
    pub name: String,
    pub state: DocumentState,
}

fn text_of(fields: &Value) -> String {
    match fields.get("label").or_else(|| fields.get("content")) {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

fn out(text: String) -> ToolOutput {
    let mut text = text;
    if text.len() > MAX_ANSWER {
        let mut cut = MAX_ANSWER;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str("\n[truncated]");
    }
    ToolOutput {
        text,
        is_error: false,
        meta: None,
    }
}
fn refuse(text: &str) -> ToolOutput {
    ToolOutput {
        text: text.into(),
        is_error: true,
        meta: None,
    }
}

impl SealedBackend {
    fn answer(&self, call: &ToolCall) -> ToolOutput {
        let live = || self.state.nodes.values().filter(|n| !n.deleted);
        match call.tool {
            Tool::Files => out(format!("{}\t{}\t(encrypted project, decrypted on this device)", self.document, self.name)),
            Tool::Outline => out(live().map(|n| format!("{}\t{}\t{}", n.id.0, n.node_type, n.parent_id.as_ref().map_or("-", |p| p.0.as_str()))).collect::<Vec<_>>().join("\n")),
            Tool::Read => {
                let refs: Vec<&str> = call.args.get("refs").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
                out(live().filter(|n| refs.is_empty() || refs.contains(&n.id.0.as_str())).map(|n| format!("{}\t{}", n.id.0, text_of(&n.current_fields))).collect::<Vec<_>>().join("\n"))
            }
            Tool::Find => {
                let Some(q) = call.args.get("q").and_then(Value::as_str).map(str::to_lowercase) else {
                    return refuse("find needs q");
                };
                out(live().filter(|n| text_of(&n.current_fields).to_lowercase().contains(&q)).map(|n| format!("{}\t{}", n.id.0, text_of(&n.current_fields))).collect::<Vec<_>>().join("\n"))
            }
            Tool::Status => out(json!({"file": self.document, "mode": "local delegation, read only", "label": "Encrypted project (pre-release, not independently reviewed)"}).to_string()),
            _ => refuse("This local server holds a read-only delegation of one encrypted file. It cannot write, diff or remember."),
        }
    }
}

impl Backend for SealedBackend {
    async fn call(&self, _ctx: CallContext, call: ToolCall) -> ToolOutput {
        tracing::info!(tool = ?call.tool, "local encrypted-file tool call");
        self.answer(&call)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::materializer::MaterializedNode;
    use engine_shared::NodeId;

    #[test]
    fn reads_and_finds_in_the_decrypted_file_and_refuses_writes() {
        let mut state = DocumentState::default();
        for (id, text, deleted) in [("A", "Revenue grew 5%.", false), ("B", "Gone", true)] {
            state.nodes.insert(
                NodeId(id.into()),
                MaterializedNode {
                    id: NodeId(id.into()),
                    parent_id: None,
                    node_type: "paragraph".into(),
                    pos: "a".into(),
                    current_fields: json!({"label": text}),
                    var_name: None,
                    deleted,
                },
            );
        }
        let b = SealedBackend {
            document: uuid::Uuid::nil(),
            name: "Budget.docx".into(),
            state,
        };
        let call = |tool, args: Value| ToolCall {
            tool,
            args: args.as_object().cloned().unwrap_or_default(),
        };
        assert_eq!(
            b.answer(&call(Tool::Find, json!({"q": "revenue"}))).text,
            "A\tRevenue grew 5%."
        );
        assert_eq!(
            b.answer(&call(Tool::Read, json!({}))).text,
            "A\tRevenue grew 5%.",
            "deleted blocks are not read"
        );
        assert!(b.answer(&call(Tool::Propose, json!({}))).is_error);
        assert!(b.answer(&call(Tool::Submit, json!({}))).is_error);
    }
}
