# Engine project status

Updated 10 October 2026. See [the product contract](PRODUCT-SPEC.md),
[ordered plan](ENGINE-EVOLUTION-PLAN.md) and [current handoff](ENGINE-EVOLUTION-HANDOFF.md).
The engine serves document repositories around existing editors. Questionnaire
validation remains a supported adapter; it is not the product scope.

Part 1 implements nearest-checkpoint historical reads with streamed suffixes and
replay accounting, streamed chain verification, and sequence-only snapshot cadence
queries. Old-base batches and draft creation use the shared reader. Unique-name and
crossed-move regressions demonstrate why different IDs alone do not imply independence.
Events, applied migrations, HTTP responses and the MIT boundary are preserved.

Shared content-addressed checkpoints, local commit DAG/branches, complete offline
replica convergence, signed/witnessed provenance and large-file/service capacity
are planned, not implemented. Native hosts/adapters and web review UI live in the
application. See CAPABILITIES for existing API boundaries.

Engine implementation `647249e` is pushed to main, synchronized from application `667ecb6`. Local task lint, all 204 tests, task docs
and unchanged generated OpenAPI passed. Independent CI also passed for implementation `647249e`; the handoff links its evidence. No VPS deployment is part of this increment.
