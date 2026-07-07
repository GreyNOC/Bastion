# Contributing to GreyNOC Bastion

Thanks for helping defenders. Bastion is a **defensive-only, local-first** tool;
that scope shapes what we can accept.

## Scope — what will and won't be merged

Bastion helps authorized defenders understand and protect their own systems. We
**cannot** accept anything offensive, even "for testing":

- exploitation, exploit/payload generation
- credential replay, validation, brute forcing, password spraying
- unauthorized or public-target scanning
- malware behavior, evasion, persistence, or attack automation

See [`docs/SAFETY_MODEL.md`](docs/SAFETY_MODEL.md) and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Contributions must preserve the
core guarantees: local-first, network-off-by-default, and no full secrets in any
output.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Before you open a PR

Run the same checks CI runs:

```bash
ruff check src tests        # lint
mypy src                    # types (advisory)
bandit -r src -c pyproject.toml   # security lint
pytest                      # tests
pip-audit                   # dependency audit (needs network)
```

Guidelines:

- **Keep runtime dependencies minimal.** New runtime deps need a strong reason;
  dev-only tools go in the `dev` extra.
- **Add tests** for behavior changes, especially anything touching the safety
  layer, masking, network guard, or the dashboard auth/CSRF path.
- **Update docs** when behavior changes (README, the relevant `docs/` page, and
  `docs/explanations/` if an engine's flow changes).
- **Don't weaken safe defaults.** Loopback binding, live-fetch off, masking, and
  draft-until-validated detections are defaults, not suggestions.

## Commit and PR style

- Small, focused commits with clear messages.
- Fill in the pull request template checklist.
- One logical change per PR where practical.

## Reporting security issues

Do not open a public issue for an unpatched vulnerability — see
[`SECURITY.md`](SECURITY.md).
