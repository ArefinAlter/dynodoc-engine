# Security policy

This is an early source release. Security fixes target the current main branch;
there are no supported older release lines or guaranteed response times.

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/ArefinAlter/dynodoc-engine/security/advisories/new),
or email arefinalter@gmail.com if that channel is unavailable. Include affected
revision, impact, a minimal synthetic reproduction and suggested mitigation.
Do not publish working credentials, private documents or a weaponized exploit in
an issue. Coordinate public disclosure after a fix or an agreed mitigation.

Particularly relevant areas are authorization across drafts/public views, event
integrity and replay, parser/resource limits, authentication, administrative erasure
and SQL concurrency. Run tests only against an isolated database. Never expose a
development database or test authentication to the public internet.
