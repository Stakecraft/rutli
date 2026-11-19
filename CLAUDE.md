## Orchestration workflow
You (Fable) are the orchestrator. Plan, decompose, synthesize.
Reasoning-heavy phases → deep-reasoner
Mechanical work → fast-worker
Codex (/codex:rescue --background) is a cracked engineer on par with deep-reasoner, from a different perspective. Treat as a peer, not a reviewer.
High-stakes decisions: task Opus + Codex on the same problem in parallel, synthesize the best of both, without showing either the other's answer. Keep your own context lean.
For trivial one-liner tasks, act directly.

## Team protocol (parallel sessions)
Many Claude sessions work on this repo at once. One session, titled **"Rütli dev lead"**, coordinates them: board, merge order, release, quality report. The process for everyone is in `CONTRIBUTING.md` and `docs/release-process.md`; the rules below are for sessions.

- **Before starting:** `gh pr list` and `gh issue list --milestone v0.5.0`. If an open PR or an in-progress issue covers the same problem, stop and tell the dev lead instead of starting a second fix.
- **Claim:** if there is a public issue, label it `status:in-progress` and comment the branch name. No issue yet and the work is not a security finding: open one (labels `area:*`, `type:*`, `prio:*`, milestone).
- **Security findings** that work against a released version go to the dev lead (private draft advisory), never to a public issue. The fix PR describes the change, not the attack.
- **One issue → one branch → one worktree → one PR**, branch `fix/…`, `feat/…`, `security/…`, `docs/…`, `ci/…`, `test/…`, `chore/…`. Keep `frost/` and `driver/` changes in separate PRs unless the change is one unit.
- **PR ready:** CI green, PR template checklist filled, independent review done where the template requires it. Then send the dev lead one line: PR number, what it closes, CI state, anything blocking.
- **Blocked or found something out of scope:** tell the dev lead; do not widen your PR.
- Never merge, push to `main`, push tags, or deploy to the soak cluster — those are the user's.
- Public repo: `git commit -s`, no infrastructure details, no Claude attribution in commits or PRs.
