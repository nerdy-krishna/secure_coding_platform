---
sidebar_position: 1
title: Contributing
---

# Contributing

Contributions, bug reports, and feature requests are welcome. The
short version:

1. Fork the repo on GitHub.
2. Create a feature branch off `main`.
3. Make your change, run the lint + test suite locally.
4. Commit with a clear message; open a PR against `main`.
5. CI runs backend lint + tests, frontend lint + build, poetry.lock
   drift, and a Docker build. All five must be green.

## Local setup

```bash
git clone https://github.com/<your-fork>/ai-secure-coding-compliance-platform.git
cd ai-secure-coding-compliance-platform
./setup.sh
```

The script checks prerequisites, generates secrets, writes `.env`,
builds + starts the compose stack, runs Alembic migrations, and
installs UI dependencies.

## Commit conventions

- Prefix the subject with a type: `feat(x): ...`, `fix: ...`,
  `refactor: ...`, `docs: ...`, `chore: ...`.
- Subject line ≤72 chars. Use the body for the **why**, not the
  **what** — the diff shows the what.
- The repo uses a conservative branching model; feature work lands
  on `main` via squash merges unless the PR explicitly asks for a
  merge commit.

## Secrets

Never commit `.env` or any file that matches `*.env*` other than
`.env.example`. Encrypted API keys already in the database are fine
to keep across branches — they can only be decrypted with the
installation's `ENCRYPTION_KEY`.

If you rotate `ENCRYPTION_KEY`, expect to re-enter every LLM API
key + SMTP password via the Admin UI. See
[Architecture → LLM Integration](../architecture/llm-integration.md#key-rotation).

## Upgrades

Default to the **latest stable** version of a dependency when
bumping. Avoid hedging toward an intermediate "safer" version
unless there's a concrete incompatibility blocking it — we'd
rather take one upgrade hit and move on than defer twice.

## Communication

- Bugs + small features → GitHub Issues.
- Large design changes → open a discussion first. It's faster to
  align on an approach in a thread than to rebase a 600-line PR
  against a different direction.
- Security issues → please email the maintainer instead of opening
  a public issue.

## Code of conduct

Be respectful. No personal attacks. If you disagree with a review
comment, say why — "I disagree" is fine, "this is stupid" is not.
