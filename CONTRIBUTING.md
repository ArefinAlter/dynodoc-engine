# Contributing

Open an issue describing the problem and expected behavior, or submit a focused
pull request. For a large design change, discuss the compatibility contract first.
Use synthetic fixtures; never submit private documents, credentials or database
dumps. Follow the [code of conduct](CODE_OF_CONDUCT.md).

1. Follow the README setup and create a branch.
2. Keep changes focused. Preserve append-only events, stable IDs and old readers.
3. Add regression evidence for changed behavior. Database tests must use isolated
   SQLx databases. Add a numbered migration instead of editing an applied file.
4. Run `task lint`, `task test` and `task docs`. Regenerate OpenAPI for API changes.
5. Describe the problem, behavior, compatibility impact and validation in the PR.

Contributions are made under MIT. You must have the right to submit your changes;
retain third-party notices and identify borrowed code. No copyright assignment or
separate contributor license agreement is required. Maintainers review and merge
changes; there is no promised response time or security service-level agreement.
