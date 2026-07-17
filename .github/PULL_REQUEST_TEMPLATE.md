<!--
==============================================================================
File:         .github/PULL_REQUEST_TEMPLATE.md
Project:      Apotropaios - Firewall Manager (Python Variant)
Synopsis:     Pull request template
Description:  Structured change description with verification evidence,
              cascade tracking, and the project quality gates as a
              pre-submission checklist.
# Version:      1.6.0
==============================================================================
-->

## Summary

<!-- What does this change do, and why? Link the issue it resolves. -->

Resolves #

## Change category

<!-- Check exactly the categories that apply -->

- [ ] Bug fix (patch)
- [ ] New functionality (minor)
- [ ] Breaking change (major)
- [ ] Documentation only
- [ ] CI / build / repository infrastructure
- [ ] Test suite

## Verification evidence

<!-- Paste actual output, not assertions -->

- [ ] `pytest tests/ -q` — all tests pass (paste tail)
- [ ] `mypy apotropaios/ --strict` — zero errors
- [ ] `pyflakes apotropaios/` — clean (intentional re-export/registration imports excepted)
- [ ] New behavior covered by new or updated tests

```text
<verification output>
```

## Quality gates

- [ ] Complete implementation — no stubs, placeholders, or partial code
- [ ] All `open()` calls specify `encoding="utf-8"` (binary mode and /dev/tty excepted)
- [ ] `pip3`/`python3` used in any scripts or docs (never `pip`/`python`)
- [ ] Comprehensive file headers on new files (Synopsis, Description, Notes, Version)
- [ ] User-supplied values re-validated at command-composition sites (defense-in-depth)
- [ ] Emergency-control and service-operation return codes checked (fail closed)
- [ ] No version identifiers added to documentation outside the changelogs

## Documentation & cascade

- [ ] CHANGELOG entry added under the correct version
- [ ] docs/ and docs/wiki updated for behavior changes (fact-of, no version callouts)
- [ ] `tasks/sync_function.md` cascade log updated for cross-module impacts
- [ ] Line counts / catalogs regenerated if source files changed
