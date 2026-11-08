-- Organisation-level allow and deny of AI clients by kind (decision 038, docs/AI-AGENT-CONNECTORS.md
-- 5.1 layer 2). The client kinds are a closed set (agent_identity.client_kind), so one deny list
-- states, per kind, allowed or denied; an empty list (the default) allows every kind, as before.
-- A member of an organisation that denies the kind of a key cannot use the key: the agent routes,
-- the remote MCP endpoint and the OAuth consent and token endpoints refuse it.
alter table organisation add column agent_clients_denied text[] not null default '{}'
    check (cardinality(agent_clients_denied) <= 8
           and agent_clients_denied <@ array['claude','chatgpt','gemini','copilot','cursor','codex','device','generic']::text[]);
