# Summary

<!-- What does this change and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature (defensive)
- [ ] Hardening / security
- [ ] Docs only
- [ ] Refactor / tooling

## Safety checklist (required)

- [ ] No offensive capability (no exploitation, payloads, credential replay,
      brute forcing, public scanning, malware behavior, evasion, persistence).
- [ ] Local-first and network-off-by-default preserved.
- [ ] No full secrets can appear in any output, log, or report (masking intact).
- [ ] Safe defaults not weakened (loopback bind, live-fetch off, drafts stay
      drafts until validated).

## Quality checklist

- [ ] `ruff check src tests` passes
- [ ] `bandit -r src -c pyproject.toml` passes
- [ ] `pytest` passes
- [ ] Tests added/updated for the change
- [ ] Docs updated (README / `docs/` / `docs/explanations/`) if behavior changed

## Notes / limitations

<!-- Anything reviewers should know: TODOs, follow-ups, known limitations. -->
