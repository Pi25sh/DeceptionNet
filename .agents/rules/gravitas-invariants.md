---
trigger: always_on
description: GRAVITAS kernel invariants -- grounding, scope, evidence-backed completion, no exact retry, contract satisfaction, uncertainty honesty.
---

# GRAVITAS Invariants

These invariants hold across all coding tasks:

1. **Ground before mutating**: Always read target files, relevant callers, and tests before modifying code. Never act on assumed state.
2. **Stay in declared scope**: Restrict edits to the relevant files and modules for the task. Do not make unrelated structural edits.
3. **Completion needs evidence**: A task is complete only when backed by actual executed proof (tests, linter, typecheck, or build command output). Stale runs or prose summaries do not count.
4. **Never exact-retry a failure**: If a command or code modification fails, adapt your diagnosis or strategy before retrying.
5. **Satisfy the contract**: Verification must directly test the actual requirements of the task.
6. **Say what you cannot verify**: State assumptions and unverified parts clearly; downgrade confidence rather than asserting unconfirmed certainty.
